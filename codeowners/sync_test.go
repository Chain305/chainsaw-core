package codeowners

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
)

type fakeGH struct {
	files map[string]map[string][]byte // repo → path → bytes
	calls []string
}

func (f *fakeGH) GetFile(_ context.Context, repo, path string) ([]byte, error) {
	f.calls = append(f.calls, repo+":"+path)
	if r, ok := f.files[repo]; ok {
		if b, ok := r[path]; ok {
			return b, nil
		}
	}
	return nil, ErrNotFound
}

type memStore struct {
	mu sync.Mutex
	m  map[string][]Mapping
}

func newMemStore() *memStore { return &memStore{m: make(map[string][]Mapping)} }

func (s *memStore) UpsertCodeowners(_ context.Context, repoID string, mappings []Mapping) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]Mapping, len(mappings))
	copy(cp, mappings)
	s.m[repoID] = cp
	return nil
}

func (s *memStore) GetCodeowners(_ context.Context, repoID string) ([]Mapping, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Mapping, len(s.m[repoID]))
	copy(out, s.m[repoID])
	return out, nil
}

func TestSyncFetchesFromFirstAvailableLocation(t *testing.T) {
	gh := &fakeGH{
		files: map[string]map[string][]byte{
			"acme/api": {
				"docs/CODEOWNERS": []byte("/docs/ @docs-team\n"),
			},
		},
	}
	store := newMemStore()
	if err := Sync(context.Background(), gh, "acme/api", store); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	want := []string{"acme/api:.github/CODEOWNERS", "acme/api:CODEOWNERS", "acme/api:docs/CODEOWNERS"}
	if !reflect.DeepEqual(gh.calls, want) {
		t.Errorf("call sequence = %v, want %v", gh.calls, want)
	}
	got, err := store.GetCodeowners(context.Background(), "acme/api")
	if err != nil {
		t.Fatalf("GetCodeowners: %v", err)
	}
	if len(got) != 1 || got[0].Pattern != "/docs/" {
		t.Errorf("persisted mappings = %+v", got)
	}
}

func TestSyncIsIdempotent(t *testing.T) {
	gh := &fakeGH{
		files: map[string]map[string][]byte{
			"acme/api": {".github/CODEOWNERS": []byte("* @everyone\n")},
		},
	}
	store := newMemStore()
	for i := 0; i < 3; i++ {
		if err := Sync(context.Background(), gh, "acme/api", store); err != nil {
			t.Fatalf("Sync iteration %d: %v", i, err)
		}
	}
	got, _ := store.GetCodeowners(context.Background(), "acme/api")
	if len(got) != 1 {
		t.Fatalf("expected 1 mapping after re-sync, got %d", len(got))
	}
}

func TestSyncReturnsErrorWhenNoCandidateExists(t *testing.T) {
	gh := &fakeGH{files: map[string]map[string][]byte{}}
	store := newMemStore()
	err := Sync(context.Background(), gh, "acme/api", store)
	if err == nil {
		t.Fatal("expected error for missing CODEOWNERS")
	}
}

func TestSyncSurfacesNonNotFoundError(t *testing.T) {
	wantErr := errors.New("rate limited")
	gh := errGH{err: wantErr}
	store := newMemStore()
	err := Sync(context.Background(), gh, "acme/api", store)
	if err == nil || !errors.Is(err, wantErr) {
		t.Errorf("Sync error = %v, want wrapping %v", err, wantErr)
	}
}

type errGH struct{ err error }

func (e errGH) GetFile(_ context.Context, _ string, _ string) ([]byte, error) {
	return nil, e.err
}

func TestLookupOwnersFallsBackToNilWhenUnsynced(t *testing.T) {
	store := newMemStore()
	got, err := LookupOwners(context.Background(), store, "acme/api", "src/foo.go")
	if err != nil {
		t.Fatalf("LookupOwners: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil owners for unsynced repo, got %v", got)
	}
}

func TestLookupOwnersAfterSync(t *testing.T) {
	gh := &fakeGH{
		files: map[string]map[string][]byte{
			"acme/api": {".github/CODEOWNERS": []byte("* @everyone\n*.go @gophers\n/docs/ @docs\n")},
		},
	}
	store := newMemStore()
	if err := Sync(context.Background(), gh, "acme/api", store); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	cases := map[string][]string{
		"src/foo.go":    {"@gophers"},
		"docs/index.md": {"@docs"},
		"README.md":     {"@everyone"},
	}
	for path, want := range cases {
		got, err := LookupOwners(context.Background(), store, "acme/api", path)
		if err != nil {
			t.Fatalf("LookupOwners(%q): %v", path, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("LookupOwners(%q) = %v, want %v", path, got, want)
		}
	}
}

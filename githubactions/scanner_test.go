package githubactions

import (
	"context"
	"errors"
	"testing"
)

// fakeTyposquat returns a fixed suggestion when the looked-up name
// matches one of the configured triggers (case-insensitive). Any other
// name returns no suggestion.
type fakeTyposquat struct {
	hits map[string]string
	err  error
}

func (f *fakeTyposquat) Lookup(_ context.Context, ownerSlashName string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	if f.hits == nil {
		return "", nil
	}
	return f.hits[ownerSlashName], nil
}

// fakeMalware reports a fixed (owner, name) as malicious, regardless of
// ref, with the configured reason.
type fakeMalware struct {
	owner  string
	name   string
	reason string
	err    error
}

func (f *fakeMalware) IsMalicious(_ context.Context, owner, name, _ string) (bool, string, error) {
	if f.err != nil {
		return false, "", f.err
	}
	if owner == f.owner && name == f.name {
		return true, f.reason, nil
	}
	return false, "", nil
}

func remoteRef(owner, name, version, sha, file string, line int) ActionRef {
	return ActionRef{
		Owner:      owner,
		Name:       name,
		Version:    version,
		SHA:        sha,
		Kind:       KindRemote,
		SourceFile: file,
		SourceLine: line,
	}
}

func TestScan_EmptyRefs(t *testing.T) {
	got, err := Scan(context.Background(), nil, ScanDeps{})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(got))
	}
}

func TestScan_UnpinnedRef(t *testing.T) {
	refs := []ActionRef{
		remoteRef("actions", "checkout", "v4", "", "wf.yml", 10),
	}
	got, err := Scan(context.Background(), refs, ScanDeps{
		KnownPublishers: []string{"actions"},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(got), got)
	}
	if got[0].Signal != SignalActionUnpinnedRef {
		t.Errorf("signal = %q, want %q", got[0].Signal, SignalActionUnpinnedRef)
	}
	if got[0].Severity != "medium" {
		t.Errorf("severity = %q, want medium", got[0].Severity)
	}
}

func TestScan_SHAPinned_NoUnpinnedFinding(t *testing.T) {
	sha := "0123456789abcdef0123456789abcdef01234567"
	refs := []ActionRef{
		remoteRef("actions", "checkout", sha, sha, "wf.yml", 5),
	}
	got, err := Scan(context.Background(), refs, ScanDeps{
		KnownPublishers: []string{"actions"},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	for _, f := range got {
		if f.Signal == SignalActionUnpinnedRef {
			t.Fatalf("unexpected unpinned finding for SHA-pinned ref: %+v", f)
		}
	}
}

func TestScan_LocalRef_Skipped(t *testing.T) {
	refs := []ActionRef{
		{
			Kind:       KindLocal,
			Name:       "./.github/actions/local",
			SourceFile: "wf.yml",
			SourceLine: 3,
		},
	}
	got, err := Scan(context.Background(), refs, ScanDeps{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("local refs must be skipped, got %d findings: %+v", len(got), got)
	}
}

func TestScan_TyposquatHit(t *testing.T) {
	refs := []ActionRef{
		remoteRef("attacker", "chekout", "v4", "", "wf.yml", 1),
	}
	got, err := Scan(context.Background(), refs, ScanDeps{
		Typosquat: &fakeTyposquat{
			hits: map[string]string{"attacker/chekout": "actions/checkout"},
		},
		KnownPublishers: []string{"attacker"}, // suppress unknown_publisher noise
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	var typo *Finding
	for i := range got {
		if got[i].Signal == SignalActionTyposquat {
			typo = &got[i]
		}
	}
	if typo == nil {
		t.Fatalf("expected typosquat finding, got %+v", got)
	}
	if typo.Detail != "actions/checkout" {
		t.Errorf("detail = %q, want actions/checkout", typo.Detail)
	}
	if typo.Severity != "high" {
		t.Errorf("severity = %q, want high", typo.Severity)
	}
}

func TestScan_TyposquatStripsSubPath(t *testing.T) {
	// Parser preserves composite-action subpaths in Name.
	ref := ActionRef{
		Owner:      "actions",
		Name:       "cache/save", // sub-path
		Version:    "v3",
		Kind:       KindRemote,
		SourceFile: "wf.yml",
		SourceLine: 1,
	}
	// The fake answers only for the stripped form.
	fake := &fakeTyposquat{hits: map[string]string{"actions/cache": "actions/cache"}}
	// Since the lookup returns a non-empty suggestion equal to the
	// queried name, this would fire — but our purpose here is to
	// confirm the stripped lookup string is what we feed to the
	// detector. We assert the call happened by checking we got the
	// suggestion back.
	got, err := Scan(context.Background(), []ActionRef{ref}, ScanDeps{
		Typosquat:       fake,
		KnownPublishers: []string{"actions"},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	var typo *Finding
	for i := range got {
		if got[i].Signal == SignalActionTyposquat {
			typo = &got[i]
		}
	}
	if typo == nil {
		t.Fatalf("expected typosquat finding for sub-path lookup, got %+v", got)
	}
}

func TestScan_MaliciousHit(t *testing.T) {
	refs := []ActionRef{
		remoteRef("tj-actions", "changed-files", "v1", "", "wf.yml", 7),
	}
	got, err := Scan(context.Background(), refs, ScanDeps{
		Malware:         &fakeMalware{owner: "tj-actions", name: "changed-files", reason: "compromised"},
		KnownPublishers: []string{"tj-actions"},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	var mal *Finding
	for i := range got {
		if got[i].Signal == SignalActionMalicious {
			mal = &got[i]
		}
	}
	if mal == nil {
		t.Fatalf("expected malicious finding, got %+v", got)
	}
	if mal.Detail != "compromised" {
		t.Errorf("detail = %q, want compromised", mal.Detail)
	}
	if mal.Severity != "high" {
		t.Errorf("severity = %q, want high", mal.Severity)
	}
}

func TestScan_UnknownPublisher(t *testing.T) {
	sha := "0123456789abcdef0123456789abcdef01234567"
	refs := []ActionRef{
		remoteRef("randoorg", "thing", sha, sha, "wf.yml", 2),
	}
	got, err := Scan(context.Background(), refs, ScanDeps{
		KnownPublishers: []string{"actions", "github"},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(got) != 1 || got[0].Signal != SignalActionUnknownPublisher {
		t.Fatalf("expected single unknown_publisher finding, got %+v", got)
	}
	if got[0].Severity != "low" {
		t.Errorf("severity = %q, want low", got[0].Severity)
	}
}

func TestScan_KnownPublisher_NoFinding(t *testing.T) {
	sha := "0123456789abcdef0123456789abcdef01234567"
	refs := []ActionRef{
		remoteRef("Actions", "checkout", sha, sha, "wf.yml", 2), // mixed case
	}
	got, err := Scan(context.Background(), refs, ScanDeps{
		KnownPublishers: []string{"actions"},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	for _, f := range got {
		if f.Signal == SignalActionUnknownPublisher {
			t.Fatalf("did not expect unknown_publisher for known owner: %+v", f)
		}
	}
}

func TestScan_MixedSignals_OrderedBySeverity(t *testing.T) {
	refs := []ActionRef{
		// Unpinned + typosquat + unknown_publisher all on one ref.
		remoteRef("attacker", "chekout", "v1", "", "wf.yml", 4),
	}
	got, err := Scan(context.Background(), refs, ScanDeps{
		Typosquat: &fakeTyposquat{
			hits: map[string]string{"attacker/chekout": "actions/checkout"},
		},
		KnownPublishers: []string{"actions"}, // attacker is NOT known
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 findings, got %d: %+v", len(got), got)
	}
	wantOrder := []string{
		SignalActionTyposquat,
		SignalActionUnpinnedRef,
		SignalActionUnknownPublisher,
	}
	for i, want := range wantOrder {
		if got[i].Signal != want {
			t.Errorf("position %d signal = %q, want %q", i, got[i].Signal, want)
		}
	}
}

func TestScan_SortingAcrossFiles(t *testing.T) {
	sha := "0123456789abcdef0123456789abcdef01234567"
	refs := []ActionRef{
		remoteRef("randz", "z", sha, sha, "b.yml", 2),
		remoteRef("randa", "a", sha, sha, "a.yml", 9),
		remoteRef("randb", "b", sha, sha, "a.yml", 1),
	}
	got, err := Scan(context.Background(), refs, ScanDeps{
		KnownPublishers: []string{}, // everyone unknown -> 1 finding per ref
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(got))
	}
	want := []struct {
		file string
		line int
	}{
		{"a.yml", 1},
		{"a.yml", 9},
		{"b.yml", 2},
	}
	for i, w := range want {
		if got[i].Ref.SourceFile != w.file || got[i].Ref.SourceLine != w.line {
			t.Errorf("position %d: got %s:%d, want %s:%d",
				i, got[i].Ref.SourceFile, got[i].Ref.SourceLine, w.file, w.line)
		}
	}
}

func TestScan_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Scan starts

	refs := []ActionRef{
		remoteRef("actions", "checkout", "v4", "", "wf.yml", 1),
	}
	got, err := Scan(ctx, refs, ScanDeps{KnownPublishers: []string{"actions"}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 partial findings (cancelled before any work), got %+v", got)
	}
}

func TestScan_NilRefs_DefaultPublishers(t *testing.T) {
	// Nil KnownPublishers should fall back to DefaultKnownPublishers.
	sha := "0123456789abcdef0123456789abcdef01234567"
	refs := []ActionRef{
		remoteRef("actions", "checkout", sha, sha, "wf.yml", 1),
	}
	got, err := Scan(context.Background(), refs, ScanDeps{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	for _, f := range got {
		if f.Signal == SignalActionUnknownPublisher {
			t.Fatalf("expected actions/ to be in default allowlist, got %+v", f)
		}
	}
}

func TestScan_UnpinnedSkipsWhenVersionEmpty(t *testing.T) {
	// Version empty AND SHA empty — neither condition fires unpinned.
	refs := []ActionRef{
		remoteRef("actions", "checkout", "", "", "wf.yml", 1),
	}
	got, err := Scan(context.Background(), refs, ScanDeps{
		KnownPublishers: []string{"actions"},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	for _, f := range got {
		if f.Signal == SignalActionUnpinnedRef {
			t.Fatalf("did not expect unpinned finding when Version is empty: %+v", f)
		}
	}
}

func TestDefaultKnownPublishers_Lowercase(t *testing.T) {
	got := DefaultKnownPublishers()
	if len(got) == 0 {
		t.Fatal("expected non-empty default known-publishers list")
	}
	for _, p := range got {
		for _, r := range p {
			if r >= 'A' && r <= 'Z' {
				t.Errorf("publisher %q contains uppercase rune", p)
				break
			}
		}
	}
}

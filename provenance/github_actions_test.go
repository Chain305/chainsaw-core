package provenance

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeFetcher struct {
	bundle []byte
	digest string
	err    error
	gotCtx context.Context
}

func (f *fakeFetcher) Fetch(ctx context.Context, owner, name, ref string) ([]byte, string, error) {
	f.gotCtx = ctx
	return f.bundle, f.digest, f.err
}

type fakeValidator struct {
	id  SigstoreIdentity
	err error

	gotBundle []byte
	gotDigest string
}

func (f *fakeValidator) VerifyBundle(ctx context.Context, bundle []byte, digest string) (SigstoreIdentity, error) {
	f.gotBundle = bundle
	f.gotDigest = digest
	return f.id, f.err
}

func TestGitHubActionsVerifier_Verify(t *testing.T) {
	verifiedID := SigstoreIdentity{
		SourceRepo: "https://github.com/actions/checkout",
		BuilderID:  "https://github.com/actions/checkout/.github/workflows/release.yml@refs/tags/v4.0.0",
		Issuer:     "https://token.actions.githubusercontent.com",
	}
	digestHex := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

	tests := []struct {
		name        string
		fetcher     *fakeFetcher
		validator   *fakeValidator
		wantStatus  Status
		wantErr     bool // whether Verify itself returns a non-nil error
		wantErrSubs string
		wantSource  string
	}{
		{
			name:       "happy path: bundle verified",
			fetcher:    &fakeFetcher{bundle: []byte(`{"bundle":"x"}`), digest: digestHex},
			validator:  &fakeValidator{id: verifiedID},
			wantStatus: StatusVerified,
			wantSource: "https://github.com/actions/checkout",
		},
		{
			name:       "no attestation -> unavailable",
			fetcher:    &fakeFetcher{err: ErrNoAttestation},
			validator:  &fakeValidator{},
			wantStatus: StatusUnavailable,
		},
		{
			name:        "digest mismatch -> failed",
			fetcher:     &fakeFetcher{bundle: []byte(`{"bundle":"x"}`), digest: digestHex},
			validator:   &fakeValidator{err: errors.New("digest mismatch: artifact sha256 does not match bundle subject")},
			wantStatus:  StatusFailed,
			wantErrSubs: "digest mismatch",
		},
		{
			name:        "expired cert -> failed",
			fetcher:     &fakeFetcher{bundle: []byte(`{"bundle":"x"}`), digest: digestHex},
			validator:   &fakeValidator{err: errors.New("fulcio certificate expired")},
			wantStatus:  StatusFailed,
			wantErrSubs: "expired",
		},
		{
			name:        "fetcher returns generic error -> failed",
			fetcher:     &fakeFetcher{err: errors.New("github api: 500 internal server error")},
			validator:   &fakeValidator{},
			wantStatus:  StatusFailed,
			wantErrSubs: "fetch attestation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &GitHubActionsVerifier{
				Fetcher:        tt.fetcher,
				SigstoreVerify: tt.validator,
			}
			res, err := v.Verify(context.Background(), "actions", "checkout", "v4.0.0")
			if tt.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Status != tt.wantStatus {
				t.Fatalf("status: want %q, got %q (result: %+v)", tt.wantStatus, res.Status, res)
			}
			if tt.wantErrSubs != "" && !strings.Contains(res.Error, tt.wantErrSubs) {
				t.Fatalf("Error: want substring %q, got %q", tt.wantErrSubs, res.Error)
			}
			if tt.wantSource != "" && res.SourceRepo != tt.wantSource {
				t.Fatalf("SourceRepo: want %q, got %q", tt.wantSource, res.SourceRepo)
			}
			if tt.wantStatus == StatusVerified {
				if res.Ecosystem != "github_actions" {
					t.Fatalf("ecosystem: want github_actions, got %q", res.Ecosystem)
				}
				if res.SubjectDigest == "" {
					t.Fatalf("expected SubjectDigest to be populated on verified result")
				}
				if res.BuilderID == "" {
					t.Fatalf("expected BuilderID to be populated on verified result")
				}
			}
		})
	}
}

func TestGitHubActionsVerifier_ContextCancellationFromFetcher(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	v := &GitHubActionsVerifier{
		Fetcher:        &fakeFetcher{err: context.Canceled},
		SigstoreVerify: &fakeValidator{},
	}
	res, err := v.Verify(ctx, "owner", "name", "ref")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled propagation, got %v", err)
	}
	if res.Status != StatusFailed {
		t.Fatalf("expected StatusFailed on cancellation, got %q", res.Status)
	}
}

func TestGitHubActionsVerifier_ContextCancellationFromValidator(t *testing.T) {
	v := &GitHubActionsVerifier{
		Fetcher: &fakeFetcher{
			bundle: []byte(`{"bundle":"x"}`),
			digest: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		},
		SigstoreVerify: &fakeValidator{err: context.DeadlineExceeded},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	res, err := v.Verify(ctx, "owner", "name", "ref")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded propagation, got %v", err)
	}
	if res.Status != StatusFailed {
		t.Fatalf("expected StatusFailed on deadline, got %q", res.Status)
	}
}

type fakeResolver struct {
	digest string
	err    error
	gotRef string
}

func (r *fakeResolver) Resolve(ctx context.Context, owner, name, ref string) (string, error) {
	r.gotRef = ref
	return r.digest, r.err
}

func TestGitHubActionsVerifier_ResolverWiring(t *testing.T) {
	resolvedDigest := "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe"
	verifiedID := SigstoreIdentity{
		SourceRepo: "https://github.com/actions/checkout",
		BuilderID:  "builder",
		Issuer:     "https://token.actions.githubusercontent.com",
	}

	resolver := &fakeResolver{digest: resolvedDigest}
	fetcher := &fakeFetcher{bundle: []byte(`{"bundle":"x"}`), digest: resolvedDigest}
	validator := &fakeValidator{id: verifiedID}

	v := &GitHubActionsVerifier{
		Resolver:       resolver,
		Fetcher:        fetcher,
		SigstoreVerify: validator,
	}
	res, err := v.Verify(context.Background(), "actions", "checkout", "v4")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.Status != StatusVerified {
		t.Fatalf("status: want verified, got %q (err=%q)", res.Status, res.Error)
	}
	if resolver.gotRef != "v4" {
		t.Fatalf("resolver got ref %q, want v4", resolver.gotRef)
	}
	if validator.gotDigest != resolvedDigest {
		t.Fatalf("validator got digest %q, want %q", validator.gotDigest, resolvedDigest)
	}
}

func TestGitHubActionsVerifier_ResolverUnresolvable(t *testing.T) {
	v := &GitHubActionsVerifier{
		Resolver:       &fakeResolver{err: ErrUnresolvableRef},
		Fetcher:        &fakeFetcher{},
		SigstoreVerify: &fakeValidator{},
	}
	res, err := v.Verify(context.Background(), "actions", "checkout", "v4")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.Status != StatusUnavailable {
		t.Fatalf("status: want unavailable, got %q", res.Status)
	}
}

func TestGitHubActionsVerifier_NilDeps(t *testing.T) {
	v := &GitHubActionsVerifier{}
	res, err := v.Verify(context.Background(), "o", "n", "r")
	if err == nil {
		t.Fatalf("expected error when fetcher/validator are nil")
	}
	if res.Status != StatusFailed {
		t.Fatalf("expected StatusFailed, got %q", res.Status)
	}
}

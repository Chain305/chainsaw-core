package provenance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/provenance/sigstoreverify"
)

// repoFile is a live repo file with the bytes a HuggingFace resolve URL
// would serve for it.
type repoFile struct {
	name  string
	bytes []byte
}

// subjectFor returns the signed subject (name + sha256 of the given bytes),
// as it would appear in the model-signing manifest.
func subjectFor(name string, body []byte) sigstoreverify.Subject {
	sum := sha256.Sum256(body)
	return sigstoreverify.Subject{Name: name, SHA256: sum[:]}
}

// newRepoServer serves each file's bytes at
// /<repo>/resolve/<rev>/<name>; unknown paths 404.
func newRepoServer(files []repoFile) *httptest.Server {
	byName := map[string][]byte{}
	for _, f := range files {
		byName[f.name] = f.bytes
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// path shape: /org/model/resolve/main/<name>
		i := strings.Index(r.URL.Path, "/resolve/")
		if i < 0 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		rest := r.URL.Path[i+len("/resolve/"):]
		// strip "<rev>/"
		if j := strings.Index(rest, "/"); j >= 0 {
			rest = rest[j+1:]
		}
		body, ok := byName[rest]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
}

func TestVerifyManifestFilesAllMatch(t *testing.T) {
	files := []repoFile{
		{"config.json", []byte(`{"hidden":1}`)},
		{"model.safetensors", []byte("weights")},
	}
	srv := newRepoServer(files)
	defer srv.Close()

	c := newHuggingFaceChecker(srv.Client(), nil)
	c.baseURL = srv.URL

	subjects := []sigstoreverify.Subject{
		subjectFor("config.json", files[0].bytes),
		subjectFor("model.safetensors", files[1].bytes),
	}
	mismatch, partial := c.verifyManifestFiles(context.Background(), srv.URL, "org/model", "main", subjects)
	if mismatch != "" {
		t.Errorf("all-match: want no mismatch, got %q", mismatch)
	}
	if partial != "" {
		t.Errorf("all-match: want no partial, got %q", partial)
	}
}

func TestVerifyManifestFilesTamperDetected(t *testing.T) {
	files := []repoFile{
		{"config.json", []byte(`{"hidden":1}`)},
		{"model.safetensors", []byte("TAMPERED-weights")},
	}
	srv := newRepoServer(files)
	defer srv.Close()

	c := newHuggingFaceChecker(srv.Client(), nil)
	c.baseURL = srv.URL

	// Manifest signed the ORIGINAL bytes; repo now serves tampered bytes.
	subjects := []sigstoreverify.Subject{
		subjectFor("config.json", files[0].bytes),
		subjectFor("model.safetensors", []byte("original-weights")),
	}
	mismatch, partial := c.verifyManifestFiles(context.Background(), srv.URL, "org/model", "main", subjects)
	if partial != "" {
		t.Errorf("tamper: want no partial, got %q", partial)
	}
	if !strings.Contains(mismatch, "model.safetensors") || !strings.Contains(mismatch, "mismatch") {
		t.Errorf("tamper: want a sha256-mismatch on model.safetensors, got %q", mismatch)
	}
}

func TestVerifyManifestFilesMissingFileIsMismatch(t *testing.T) {
	files := []repoFile{{"config.json", []byte(`{"hidden":1}`)}}
	srv := newRepoServer(files)
	defer srv.Close()

	c := newHuggingFaceChecker(srv.Client(), nil)
	c.baseURL = srv.URL

	subjects := []sigstoreverify.Subject{
		subjectFor("config.json", files[0].bytes),
		subjectFor("weights.bin", []byte("gone")), // 404 in repo
	}
	mismatch, _ := c.verifyManifestFiles(context.Background(), srv.URL, "org/model", "main", subjects)
	if !strings.Contains(mismatch, "weights.bin") || !strings.Contains(mismatch, "missing") {
		t.Errorf("missing file: want a 'missing from repo' verdict, got %q", mismatch)
	}
}

func TestVerifyManifestFilesPartialOnFileCap(t *testing.T) {
	// Build more subjects than the file cap; all match so the only reason to
	// stop is the cap → partial warning, no mismatch.
	var files []repoFile
	var subjects []sigstoreverify.Subject
	for i := 0; i < hfMaxManifestFiles+5; i++ {
		name := fmt.Sprintf("f%d.bin", i)
		body := []byte(fmt.Sprintf("body-%d", i))
		files = append(files, repoFile{name, body})
		subjects = append(subjects, subjectFor(name, body))
	}
	srv := newRepoServer(files)
	defer srv.Close()

	c := newHuggingFaceChecker(srv.Client(), nil)
	c.baseURL = srv.URL

	mismatch, partial := c.verifyManifestFiles(context.Background(), srv.URL, "org/model", "main", subjects)
	if mismatch != "" {
		t.Errorf("cap: want no mismatch, got %q", mismatch)
	}
	if !strings.Contains(partial, "partial") || !strings.Contains(partial, "files") {
		t.Errorf("cap: want a file-count partial warning, got %q", partial)
	}
}

// stubVerify returns a canned identity/error, standing in for the real
// Sigstore crypto verify so Check() can be driven end-to-end offline.
func stubVerify(id *sigstoreverify.Identity, err error) func(context.Context, []byte, []byte) (*sigstoreverify.Identity, error) {
	return func(context.Context, []byte, []byte) (*sigstoreverify.Identity, error) {
		return id, err
	}
}

// newModelSigServer serves the model-signing bundle at /<repo>/resolve/<rev>/model.sig
// and every repo file at its resolve path; unknown paths 404.
func newModelSigServer(bundle []byte, files []repoFile) *httptest.Server {
	byName := map[string][]byte{}
	for _, f := range files {
		byName[f.name] = f.bytes
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := strings.Index(r.URL.Path, "/resolve/")
		if i < 0 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		rest := r.URL.Path[i+len("/resolve/"):]
		if j := strings.Index(rest, "/"); j >= 0 {
			rest = rest[j+1:]
		}
		if rest == "model.sig" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(bundle)
			return
		}
		body, ok := byName[rest]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
}

// TestHuggingFaceCheckVerifiedThroughCheck is Item 3's first headline
// acceptance test: a valid model-signing bundle whose subjects match the live
// repo files returns StatusVerified with the signer identity — exercised
// end-to-end through Check() behind the (stubbed) crypto verify.
func TestHuggingFaceCheckVerifiedThroughCheck(t *testing.T) {
	files := []repoFile{
		{"config.json", []byte(`{"hidden":1}`)},
		{"model.safetensors", []byte("weights")},
	}
	bundle := sigstoreverify.NewModelSigningBundleForTesting(t, []sigstoreverify.TestSubject{
		{Name: "config.json", Bytes: files[0].bytes, WithSHA256: true},
		{Name: "model.safetensors", Bytes: files[1].bytes, WithSHA256: true},
	})
	srv := newModelSigServer(bundle, files)
	defer srv.Close()

	c := newHuggingFaceChecker(srv.Client(), nil)
	c.baseURL = srv.URL
	c.verify = stubVerify(&sigstoreverify.Identity{
		SourceRepo: "https://huggingface.co/org/model",
		BuilderID:  "https://github.com/org/model/.github/workflows/sign.yml@refs/heads/main",
	}, nil)

	got := c.Check(context.Background(), "org/model", "main")
	if got.Status != StatusVerified {
		t.Fatalf("valid bundle + matching files: want StatusVerified, got %+v", got)
	}
	if got.SourceRepo != "https://huggingface.co/org/model" {
		t.Errorf("SourceRepo = %q, want the signer's source repo", got.SourceRepo)
	}
	if !strings.Contains(got.BuilderID, "sign.yml") {
		t.Errorf("BuilderID = %q, want the signer's builder id", got.BuilderID)
	}
}

// TestHuggingFaceCheckTamperThroughCheck is Item 3's second headline
// acceptance test: a valid signature over a manifest whose repo now serves ONE
// tampered file returns StatusFailed — driven through the full Check() flow,
// not just the verifyManifestFiles helper.
func TestHuggingFaceCheckTamperThroughCheck(t *testing.T) {
	// Repo serves TAMPERED weights; the bundle signed the ORIGINAL bytes.
	repoFiles := []repoFile{
		{"config.json", []byte(`{"hidden":1}`)},
		{"model.safetensors", []byte("TAMPERED-weights")},
	}
	bundle := sigstoreverify.NewModelSigningBundleForTesting(t, []sigstoreverify.TestSubject{
		{Name: "config.json", Bytes: repoFiles[0].bytes, WithSHA256: true},
		{Name: "model.safetensors", Bytes: []byte("original-weights"), WithSHA256: true},
	})
	srv := newModelSigServer(bundle, repoFiles)
	defer srv.Close()

	c := newHuggingFaceChecker(srv.Client(), nil)
	c.baseURL = srv.URL
	// Signature verifies fine (stub returns success); the tamper must be
	// caught by the file-level walk downstream of the verify gate.
	c.verify = stubVerify(&sigstoreverify.Identity{SourceRepo: "https://huggingface.co/org/model"}, nil)

	got := c.Check(context.Background(), "org/model", "main")
	if got.Status != StatusFailed {
		t.Fatalf("valid signature + tampered file: want StatusFailed, got %+v", got)
	}
	if !strings.Contains(got.Error, "model.safetensors") || !strings.Contains(got.Error, "mismatch") {
		t.Errorf("want a sha256-mismatch on model.safetensors, got %q", got.Error)
	}
}

// TestHuggingFaceCheckOversizeFileIsPartialNotTamper is Item 3 / finding 5:
// a legitimate signed file larger than the per-file cap must NOT be branded
// tampered. Check() stays StatusVerified with a partial file-level warning.
func TestHuggingFaceCheckOversizeFileIsPartialNotTamper(t *testing.T) {
	big := bytes.Repeat([]byte("A"), 4096) // larger than the tiny test cap below
	files := []repoFile{{"model.safetensors", big}}
	bundle := sigstoreverify.NewModelSigningBundleForTesting(t, []sigstoreverify.TestSubject{
		{Name: "model.safetensors", Bytes: big, WithSHA256: true},
	})
	srv := newModelSigServer(bundle, files)
	defer srv.Close()

	c := newHuggingFaceChecker(srv.Client(), nil)
	c.baseURL = srv.URL
	c.maxFileBytes = 1024 // force truncation of the 4096-byte file
	c.verify = stubVerify(&sigstoreverify.Identity{SourceRepo: "https://huggingface.co/org/model"}, nil)

	got := c.Check(context.Background(), "org/model", "main")
	if got.Status != StatusVerified {
		t.Fatalf("oversize legit file: want StatusVerified (not a false tamper), got %+v", got)
	}
	joined := strings.Join(got.Warnings, " ")
	if !strings.Contains(joined, "partial") || !strings.Contains(joined, "cap") {
		t.Errorf("want a partial file-level warning about the cap, got %v", got.Warnings)
	}
}

// TestVerifyManifestFilesOversizeIsPartialNotMismatch is the helper-level
// counterpart to finding 5: an oversize file downgrades to partial, never a
// manufactured sha256 mismatch.
func TestVerifyManifestFilesOversizeIsPartialNotMismatch(t *testing.T) {
	big := bytes.Repeat([]byte("W"), 4096)
	files := []repoFile{{"weights.bin", big}}
	srv := newRepoServer(files)
	defer srv.Close()

	c := newHuggingFaceChecker(srv.Client(), nil)
	c.baseURL = srv.URL
	c.maxFileBytes = 1024

	subjects := []sigstoreverify.Subject{subjectFor("weights.bin", big)}
	mismatch, partial := c.verifyManifestFiles(context.Background(), srv.URL, "org/model", "main", subjects)
	if mismatch != "" {
		t.Fatalf("oversize file must not be reported as a mismatch, got %q", mismatch)
	}
	if !strings.Contains(partial, "partial") || !strings.Contains(partial, "cap") {
		t.Errorf("want a partial-cap warning, got %q", partial)
	}
}

// TestHuggingFaceNoSha256SubjectsFails covers Check()'s guard: a bundle whose
// manifest carries subjects with no sha256 digest cannot anchor verification.
func TestHuggingFaceNoSha256SubjectsFails(t *testing.T) {
	bundleJSON := sigstoreverify.NewModelSigningBundleForTesting(t, []sigstoreverify.TestSubject{
		{Name: "no-digest.bin", WithSHA256: false},
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/model.sig") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(bundleJSON)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := newHuggingFaceChecker(srv.Client(), nil)
	c.baseURL = srv.URL

	got := c.Check(context.Background(), "org/model", "main")
	if got.Status != StatusFailed {
		t.Fatalf("no-sha256 subjects: want StatusFailed, got %+v", got)
	}
	if !strings.Contains(got.Error, "no sha256 subjects") {
		t.Errorf("no-sha256 subjects: want 'no sha256 subjects' error, got %q", got.Error)
	}
}

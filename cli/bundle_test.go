package cli

// bundle_test.go — `chainsaw bundle verify` + `doctor --offline` posture
// wiring. Covers the integrity-only (digest-bound) vs authenticated
// (full Sigstore) distinction exposed by the loader's Authenticated().
//
// The authenticated-success path needs a real bot-signed bundle (not
// synthesizable offline), so it is covered at the pure-helper level
// (TestBundleVerificationStatus) — the verifyBundleAuthenticity crypto
// itself is exercised in core/intelligence/bundle_test.go. The command
// wiring here covers every offline-reachable state: integrity-only,
// strict-rejects-digest-only, and skipped.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/intelligence"
	"github.com/chain305/chainsaw-core/provenance/sigstoreverify"
)

// writeIntelBundle builds a minimal valid intel bundle tarball to a temp
// path. With matchingSidecar=true it writes a .sigstore sidecar whose
// messageDigest equals the bundle's canonical digest (so the always-on
// digest-binding layer passes); otherwise it leaves a `{}` placeholder
// (only useful with SkipSignature / SKIP_VERIFY).
func writeIntelBundle(t *testing.T, matchingSidecar bool) string {
	t.Helper()
	tmp := t.TempDir()
	out := filepath.Join(tmp, "intel.tar.gz")

	files := map[string][]byte{}
	contentMap := map[string]string{}
	hashes := map[string]string{}
	add := func(key, payload string) {
		rel := key + "/data.json"
		files[rel] = []byte(payload)
		contentMap[key] = rel
		h := sha256.Sum256([]byte(payload))
		hashes[rel] = hex.EncodeToString(h[:])
	}
	add("kev", `{"vulnerabilities":[]}`)

	bt := time.Now().UTC().Add(-time.Hour)
	manifest := intelligence.BundleManifest{
		Schema:    intelligence.BundleManifestSchema,
		Version:   "cli-test-1.0",
		BuildTime: bt,
		Contents:  contentMap,
		SHA256:    hashes,
	}
	mb, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	files["manifest.json"] = mb

	f, err := os.Create(out)
	if err != nil {
		t.Fatalf("create bundle: %v", err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for name, data := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), ModTime: bt}); err != nil {
			t.Fatalf("tar header: %v", err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatalf("tar write: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gz: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close file: %v", err)
	}

	// Placeholder sidecar so skip-mode tests have a file present.
	if err := os.WriteFile(out+".sigstore", []byte(`{}`), 0o644); err != nil {
		t.Fatalf("write placeholder sidecar: %v", err)
	}
	if matchingSidecar {
		// Learn the canonical digest via a skip load, then write a sidecar
		// carrying it so the digest-binding layer passes.
		seed, err := intelligence.LoadBundle(context.Background(), out, intelligence.BundleVerifyOptions{SkipSignature: true})
		if err != nil {
			t.Fatalf("seed load: %v", err)
		}
		body := `{"messageSignature":{"messageDigest":{"algorithm":"SHA2_256","digest":"` + seed.Digest() + `"}}}`
		if err := os.WriteFile(out+".sigstore", []byte(body), 0o644); err != nil {
			t.Fatalf("write matching sidecar: %v", err)
		}
	}
	return out
}

func runBundleVerify(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newBundleVerifyCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

func TestBundleVerificationStatus(t *testing.T) {
	cases := []struct {
		name                    string
		verified, authenticated bool
		wantSym, wantText       string
	}{
		{"skipped", false, false, "⚠", "skipped"},
		{"integrity-only", true, false, "✓", "integrity only"},
		{"authenticated", true, true, "✓", "authenticated — full Sigstore"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sym, txt := bundleVerificationStatus(c.verified, c.authenticated)
			if sym != c.wantSym {
				t.Errorf("symbol: got %q want %q", sym, c.wantSym)
			}
			if !strings.Contains(txt, c.wantText) {
				t.Errorf("text %q does not contain %q", txt, c.wantText)
			}
		})
	}
}

func TestBundleVerify_DefaultIsIntegrityOnly(t *testing.T) {
	path := writeIntelBundle(t, true)
	out, err := runBundleVerify(t, path)
	if err != nil {
		t.Fatalf("verify (default) should pass on a digest-bound bundle: %v\n%s", err, out)
	}
	if !strings.Contains(out, "integrity only") {
		t.Errorf("default verify should report integrity-only posture, got:\n%s", out)
	}
	if !strings.Contains(out, "Signature: ✓") {
		t.Errorf("default verify should show a passing signature line, got:\n%s", out)
	}
	if strings.Contains(out, "authenticated") {
		t.Errorf("default (non-strict) verify must NOT claim authenticity, got:\n%s", out)
	}
}

func TestBundleVerify_StrictRejectsDigestOnlySidecar(t *testing.T) {
	// Offline: install the placeholder verifier so layer-2 fails on the
	// unparseable digest-only sidecar instead of blocking on a live TUF fetch.
	restore := sigstoreverify.SetDefaultVerifierForTesting(t, nil)
	defer restore()

	path := writeIntelBundle(t, true)
	out, err := runBundleVerify(t, "--strict", path)
	if err == nil {
		t.Fatalf("`verify --strict` on a digest-only bundle must fail (authenticity not satisfiable yet), got nil\n%s", out)
	}
}

func TestBundleVerify_SkipEnv(t *testing.T) {
	t.Setenv(intelligence.BundleSkipVerifyEnvVar, "1")
	path := writeIntelBundle(t, false)
	out, err := runBundleVerify(t, path)
	if err != nil {
		t.Fatalf("verify with SKIP_VERIFY set should pass: %v\n%s", err, out)
	}
	if !strings.Contains(out, "skipped") {
		t.Errorf("verify with SKIP_VERIFY should report skipped posture, got:\n%s", out)
	}
}

func TestDoctorOffline_DigestBoundPosture(t *testing.T) {
	path := writeIntelBundle(t, true)
	b, err := intelligence.LoadBundle(context.Background(), path, intelligence.BundleVerifyOptions{})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !b.Verified() || b.Authenticated() {
		t.Fatalf("expected digest-bound posture (verified, not authenticated); verified=%v authenticated=%v", b.Verified(), b.Authenticated())
	}

	prev := intelligence.ActiveBundle()
	t.Cleanup(func() { intelligence.SetActiveBundle(prev) })
	intelligence.SetActiveBundle(b)

	dcmd := &cobra.Command{}
	var buf bytes.Buffer
	dcmd.SetOut(&buf)
	if err := runDoctorOffline(dcmd, nil); err != nil {
		t.Fatalf("doctor --offline: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "verify:") || !strings.Contains(out, "integrity only") {
		t.Errorf("doctor --offline should report digest-bound integrity posture, got:\n%s", out)
	}
}

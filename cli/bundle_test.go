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
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
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

// writeIntelBundleWithBuildTime builds a digest-bound bundle whose
// manifest carries the given build_time. Pass the zero time to model the
// "manifest has no usable build_time" case — the shape P8 is about,
// whether it reaches the loader as a missing key or as
// 0001-01-01T00:00:00Z.
func writeIntelBundleWithBuildTime(t *testing.T, bt time.Time) string {
	t.Helper()
	path := writeIntelBundle(t, false)
	rewriteBundleManifestBuildTime(t, path, bt)
	// Re-derive the sidecar over the rewritten tarball so the always-on
	// digest-binding layer still passes and the test is exercising
	// FRESHNESS, not signature failure.
	seed, err := intelligence.LoadBundle(context.Background(), path, intelligence.BundleVerifyOptions{SkipSignature: true})
	if err != nil {
		t.Fatalf("seed load: %v", err)
	}
	body := `{"messageSignature":{"messageDigest":{"algorithm":"SHA2_256","digest":"` + seed.Digest() + `"}}}`
	if err := os.WriteFile(path+".sigstore", []byte(body), 0o644); err != nil {
		t.Fatalf("write sidecar: %v", err)
	}
	return path
}

// rewriteBundleManifestBuildTime rebuilds the tarball at path with
// manifest.json's build_time replaced. Per-file content hashes are
// recomputed for every member so the loader's integrity layer passes.
func rewriteBundleManifestBuildTime(t *testing.T, path string, bt time.Time) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open bundle: %v", err)
	}
	gzr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	members := map[string][]byte{}
	tr := tar.NewReader(gzr)
	for {
		hdr, rerr := tr.Next()
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			t.Fatalf("tar next: %v", rerr)
		}
		data, rerr := io.ReadAll(tr)
		if rerr != nil {
			t.Fatalf("tar read: %v", rerr)
		}
		members[hdr.Name] = data
	}
	_ = gzr.Close()
	_ = f.Close()

	var m intelligence.BundleManifest
	if err := json.Unmarshal(members["manifest.json"], &m); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	m.BuildTime = bt
	m.SHA256 = map[string]string{}
	for name, data := range members {
		if name == "manifest.json" {
			continue
		}
		h := sha256.Sum256(data)
		m.SHA256[name] = hex.EncodeToString(h[:])
	}
	mb, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	members["manifest.json"] = mb

	out, err := os.Create(path)
	if err != nil {
		t.Fatalf("recreate bundle: %v", err)
	}
	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)
	names := make([]string, 0, len(members))
	for name := range members {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		data := members[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data))}); err != nil {
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
	if err := out.Close(); err != nil {
		t.Fatalf("close file: %v", err)
	}
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

// TestBundleVerify_SkipEnv is P7. The env var itself is a documented,
// supported dev escape hatch (docs/CONFIG_REFERENCE.md) and is NOT being
// removed — this test still proves it disables the check and that the
// posture line says so. What changed is the EXIT CODE: the verb whose
// only job is verification used to return 0 when verification did not
// run, so any CI job or runbook that inherited the env var (or a
// compromised environment that set it) passed an unsigned bundle.
func TestBundleVerify_SkipEnv(t *testing.T) {
	t.Setenv(intelligence.BundleSkipVerifyEnvVar, "1")
	path := writeIntelBundle(t, false)

	out, err := runBundleVerify(t, path)
	if err == nil {
		t.Fatalf("verify must NOT exit 0 when signature verification was skipped:\n%s", out)
	}
	var coded *ExitCodeError
	if !errors.As(err, &coded) || coded.Code != ExitOpError {
		t.Fatalf("want ExitCodeError{%d}, got %v (%T)", ExitOpError, err, err)
	}
	if !strings.Contains(err.Error(), "--allow-unverified") {
		t.Errorf("the error must name the opt-in flag, got: %v", err)
	}
	if !strings.Contains(out, "skipped") {
		t.Errorf("verify with SKIP_VERIFY should still report the skipped posture, got:\n%s", out)
	}

	// The escape hatch is still reachable — deliberately, and only with
	// an explicit flag on the invocation.
	out, err = runBundleVerify(t, "--allow-unverified", path)
	if err != nil {
		t.Fatalf("--allow-unverified must accept an unverified bundle: %v\n%s", err, out)
	}
}

// TestBundleVerify_ZeroBuildTimeIsStale is P8 + P14. A manifest with no
// build_time used to read as the FRESHEST possible bundle: Age() returns
// 0 for a zero BuildTime and 0 < 180 days, so dropping one optional field
// defeated the entire freshness gate, permanently and silently. "Unknown
// age" is not "brand new".
//
// P14 rides along: the stale path returns ExitCodeError{1}, not the plain
// error that mapped to ExitOpError(2) — a CI gate can now tell "refresh
// due" (warn-only, as the command's header has always documented) from
// "this bundle is not what it claims to be".
func TestBundleVerify_ZeroBuildTimeIsStale(t *testing.T) {
	path := writeIntelBundleWithBuildTime(t, time.Time{})

	out, err := runBundleVerify(t, path)
	if err == nil {
		t.Fatalf("a manifest with no build_time must not report fresh:\n%s", out)
	}
	var coded *ExitCodeError
	if !errors.As(err, &coded) {
		t.Fatalf("stale must be a coded exit, got %T: %v", err, err)
	}
	if coded.Code != ExitBlocked {
		t.Fatalf("stale is warn-only ExitBlocked(%d) and must be distinguishable from a verification failure ExitOpError(%d); got %d",
			ExitBlocked, ExitOpError, coded.Code)
	}
	if !strings.Contains(out, "stale") {
		t.Errorf("expected the stale freshness line, got:\n%s", out)
	}
}

// TestBundleVerify_OldBuildTimeIsStale is the ordinary staleness case, so
// the P8 fix cannot be mistaken for "zero-time only".
func TestBundleVerify_OldBuildTimeIsStale(t *testing.T) {
	path := writeIntelBundleWithBuildTime(t, time.Now().Add(-2*intelligence.BundleStaleAfter))
	out, err := runBundleVerify(t, path)
	var coded *ExitCodeError
	if !errors.As(err, &coded) || coded.Code != ExitBlocked {
		t.Fatalf("an old bundle must exit ExitBlocked(%d), got %v\n%s", ExitBlocked, err, out)
	}
}

// TestBundleStaleZeroBuildTime pins the same invariant at the library
// level, where every other consumer (doctor --offline, the proxy's
// freshness readout) reads it from.
func TestBundleStaleZeroBuildTime(t *testing.T) {
	path := writeIntelBundleWithBuildTime(t, time.Time{})
	b, err := intelligence.LoadBundle(context.Background(), path, intelligence.BundleVerifyOptions{})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !b.Stale() {
		t.Error("Stale() must be true when the manifest carries no build_time — 0 age is the freshest possible answer, not an honest one")
	}
}

// TestBundleApply_IsUnavailableAndHidden is P13. The subcommand POSTed to
// /api/admin/intel-bundle/apply, a route no server build has ever served,
// and docs/install/AIRGAP.md documented it as a runnable hot-swap step —
// so an operator following the air-gap runbook got a 404 and went to
// debug their proxy. It is not being implemented (the body names a
// server-local path chosen by a remote client), so it now hands back the
// real procedure instead.
func TestBundleApply_IsUnavailableAndHidden(t *testing.T) {
	cmd := newBundleApplyCmd()
	if !cmd.Hidden {
		t.Error("`bundle apply` must not advertise itself in help as a working verb")
	}
	err := cmd.RunE(cmd, []string{"/tmp/whatever.tar.gz"})
	if err == nil {
		t.Fatal("`bundle apply` must fail rather than 404 against a route that does not exist")
	}
	msg := err.Error()
	for _, want := range []string{intelligence.BundleEnvVar, "restart"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the error must tell the operator what to do instead (missing %q): %s", want, msg)
		}
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

package main

// End-to-end test that runs a real `cargo` against a mock crate registry
// and a real `chainsaw cargo-credentials` credential-provider helper.
//
// LOCATION (open-core E5/E6): this test lives next to cmd/chainsaw — the
// package whose binary it builds — rather than in core/cli where the
// cargo-credentials command is implemented. It must `go build` the
// cmd/chainsaw entry point to get a real `chainsaw` executable. As of step 6
// cmd/chainsaw lives IN the free-core module (core/cmd/chainsaw,
// github.com/chain305/chainsaw-core/cmd/chainsaw) so the public free
// repo ships the CLI binary; the `go build -o <bin> .` below therefore
// resolves in-module, including when core is built standalone
// (cd core && GOWORK=off go test ./...). core/cli keeps its unit coverage of
// the cargo-credentials flow; this binary-level e2e belongs with the binary.
//
// Why this exists (Wave Q P2-DRIFT-CARGO-CREDS root cause):
//   - cargo 1.74+ strips URL-embedded credentials when downloading .crate
//     artifacts. The fix is the credential-provider protocol.
//   - cargo only invokes the provider when the registry's config.json
//     advertises "auth-required": true.
//   - The chainsaw proxy used to lie ("auth-required": false) even though
//     the HTTP layer enforced Basic auth — cargo would 401 silently
//     without ever consulting the provider, producing the cryptic error
//     "authenticated registries require a credential-provider to be
//     configured" even when the provider was correctly wired.
//
// This test pins the wiring contract by standing up a tiny crate
// registry httptest server that:
//   - serves config.json with auth-required:true,
//   - 401's any unauthenticated request,
//   - accepts "Authorization: Basic <b64(client_id:client_secret)>",
//   - serves a minimal sparse-index line for one crate and the .crate
//     bytes for it.
//
// The test then builds the chainsaw binary, writes a real .cargo/config.toml
// wiring it as credential-provider, and runs `cargo fetch`. If anything
// in the chain breaks — protocol, helper invocation, header format,
// auth-required signaling — cargo fails and we know.
//
// Gated on `cargo` being on PATH so CI without rust doesn't false-fail.

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCargoCredentialsE2E_RealCargoFetch(t *testing.T) {
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo not on PATH; skipping live integration test")
	}

	const (
		wantClientID     = "wave-q-cargo-e2e"
		wantClientSecret = "s3cret-shh"
	)
	expectedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(wantClientID+":"+wantClientSecret))

	// Minimal valid .crate body: a gzip'd tar with one Cargo.toml inside.
	// Building this on the fly keeps the test hermetic — no fixtures on disk.
	crateBody, crateSHA := buildMinimalCrate(t, "demo-wave-q", "0.0.1")

	indexHits := atomic.Int32{}
	crateHits := atomic.Int32{}
	authedHits := atomic.Int32{}

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// config.json is the ONE endpoint cargo fetches before it has
		// any credentials. It serves anonymously so cargo can read
		// "auth-required": true and learn to invoke the provider for
		// every subsequent request. This matches the proposed real-
		// server behaviour (synthesizeCargoConfig change in this PR):
		// anonymous-readable config.json that declares auth-required
		// upfront.
		if r.URL.Path == "/config.json" {
			cfg := map[string]any{
				"dl":            srv.URL + "/api/v1/crates/{crate}/{version}/download",
				"api":           srv.URL,
				"auth-required": true,
			}
			body, _ := json.Marshal(cfg)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
			return
		}
		// Enforce auth on every other request — matches the proxy.
		gotAuth := r.Header.Get("Authorization")
		if gotAuth == "" {
			w.Header().Set("WWW-Authenticate", "Basic realm=\"Chainsaw repository\"")
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		if gotAuth != expectedAuth {
			t.Errorf("unexpected Authorization header: got %q, want %q", gotAuth, expectedAuth)
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		authedHits.Add(1)

		switch {
		case strings.HasPrefix(r.URL.Path, "/de/mo/demo-wave-q") || strings.HasPrefix(r.URL.Path, "/3/d/demo-wave-q") || strings.HasSuffix(r.URL.Path, "/demo-wave-q"):
			// Sparse index line. cargo asks for /3/d/demo-wave-q or
			// /de/mo/demo-wave-q (length-prefixed path) depending on
			// name length. Match either; we know our name fits the
			// 3-char fallback path /de/mo/demo-wave-q.
			indexHits.Add(1)
			line := map[string]any{
				"name":     "demo-wave-q",
				"vers":     "0.0.1",
				"deps":     []any{},
				"cksum":    crateSHA,
				"features": map[string]any{},
				"yanked":   false,
				"v":        1,
			}
			b, _ := json.Marshal(line)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write(append(b, '\n'))
		case strings.Contains(r.URL.Path, "/crates/demo-wave-q/0.0.1/download"):
			crateHits.Add(1)
			w.Header().Set("Content-Type", "application/gzip")
			_, _ = w.Write(crateBody)
		default:
			// Anything else: 404 quietly. cargo also probes some paths.
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// Build the chainsaw binary for this test. The test binary itself
	// can't be `os.Args[0]` (it's the go test runner), so we go-build
	// the real cmd/chainsaw entry point into a temp file. This test lives
	// IN package cmd/chainsaw (package main), so the go test runner's CWD is
	// this package's directory — "." is the cmd/chainsaw main package. Building
	// "." (not the absolute import path) keeps the build in-module under any
	// module/workspace layout.
	chainsawBin := filepath.Join(t.TempDir(), "chainsaw")
	build := exec.Command("go", "build", "-o", chainsawBin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build chainsaw: %v\n%s", err, out)
	}

	// Set up an isolated cargo project. CARGO_HOME points at a tempdir
	// so we don't disturb the developer's real ~/.cargo state.
	projectDir := t.TempDir()
	cargoHome := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "Cargo.toml"),
		[]byte(`[package]
name = "wave-q-e2e-consumer"
version = "0.0.1"
edition = "2021"

[lib]
path = "src/lib.rs"

[dependencies]
demo-wave-q = "=0.0.1"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(projectDir, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "src", "lib.rs"), []byte("// e2e\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(projectDir, ".cargo"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Wiring strategy: the credential-provider array contains EXACTLY
	// ONE element — the chainsaw executable path. Cargo discards any
	// further array elements (doesn't forward them as argv) and only
	// appends --cargo-plugin. The binary detects --cargo-plugin at
	// process start (root.go Execute) and dispatches to the protocol
	// loop before cobra parses anything.
	//
	// We pin the provider via BOTH global-credential-providers (with a
	// credential-alias so the helper has a readable name in cargo's
	// logs) AND per-registry credential-provider on [registries.chainsaw]
	// — cargo's resolution looks at both and we want it findable from
	// either path.
	cfgTOML := fmt.Sprintf(`[registry]
global-credential-providers = ["chainsaw-cargo", "cargo:token"]

[credential-alias]
chainsaw-cargo = [%q]

[source.crates-io]
replace-with = "chainsaw"

[source.chainsaw]
registry = "sparse+%s/"

[registries.chainsaw]
credential-provider = [%q]
`, chainsawBin, srv.URL, chainsawBin)
	if err := os.WriteFile(filepath.Join(projectDir, ".cargo", "config.toml"), []byte(cfgTOML), 0o644); err != nil {
		t.Fatal(err)
	}

	// Run cargo fetch — the moment of truth.
	cmd := exec.Command("cargo", "fetch", "-v")
	cmd.Dir = projectDir
	cmd.Env = append(os.Environ(),
		"CARGO_HOME="+cargoHome,
		"CHAINSAW_CARGO_CREDENTIALS="+wantClientID+":"+wantClientSecret,
		// Stop CHAINSAW_TOKEN / CHAINSAW_SERVER from leaking in if the dev
		// has them set — the helper must work from env alone.
		"CHAINSAW_TOKEN=",
		"CHAINSAW_SERVER=",
		"CHAINSAW_CONFIG_HOME="+t.TempDir(),
	)
	out, err := cmd.CombinedOutput()
	t.Logf("cargo output:\n%s", out)
	if err != nil {
		t.Fatalf("cargo fetch failed: %v", err)
	}
	if !strings.Contains(string(out), "Updating") && !strings.Contains(string(out), "Downloaded") {
		// Cargo's output varies; the key thing is it didn't error.
		t.Logf("cargo did not print Updating/Downloaded — but exit was clean; output above")
	}

	if indexHits.Load() == 0 {
		t.Errorf("registry never received an authed index request; cargo bypassed the credential-provider")
	}
	if crateHits.Load() == 0 {
		t.Errorf("registry never received an authed .crate request; the URL-cred-strip bug may be back")
	}
	if authedHits.Load() < 2 {
		t.Errorf("expected at least 2 authed hits (index + crate), got %d", authedHits.Load())
	}
}

// buildMinimalCrate emits a syntactically-valid .crate tarball
// (gzip'd tar with crate-name-version/Cargo.toml inside) and returns
// it plus the sha256 hex digest cargo will validate.
//
// A real .crate carries the lib source too, but cargo only verifies
// the checksum at fetch time. For `cargo fetch` (no build) the tar
// contents don't matter beyond shape — we ship a Cargo.toml so any
// future cargo version that does sniff the contents stays happy.
func buildMinimalCrate(t *testing.T, name, version string) (body []byte, sha256hex string) {
	t.Helper()
	// Build a tar inline rather than pulling archive/tar imports into
	// the top of the file. Use a tiny PAX-free ustar header.
	var tarBuf bytes.Buffer
	writeTarEntry(&tarBuf, name+"-"+version+"/Cargo.toml", []byte(`[package]
name = "`+name+`"
version = "`+version+`"
edition = "2021"

[lib]
path = "src/lib.rs"
`))
	// cargo 1.74+ parses the manifest after download to make sure
	// [lib] / [[bin]] points at real source. Include a tiny lib.rs.
	writeTarEntry(&tarBuf, name+"-"+version+"/src/lib.rs", []byte("// minimal\n"))
	// tar end-of-archive: two 512-byte zero blocks.
	tarBuf.Write(make([]byte, 1024))

	// gzip it.
	var gzBuf bytes.Buffer
	gz := gzip.NewWriter(&gzBuf)
	if _, err := gz.Write(tarBuf.Bytes()); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	body = gzBuf.Bytes()
	sum := sha256.Sum256(body)
	return body, hex.EncodeToString(sum[:])
}

// writeTarEntry appends a single ustar regular-file entry to buf.
// Hand-rolled to keep imports tight; the tar format is small enough
// that a 50-line implementation beats pulling archive/tar through
// type assertions.
func writeTarEntry(buf *bytes.Buffer, path string, content []byte) {
	var hdr [512]byte
	copy(hdr[0:], path)
	copy(hdr[100:], []byte("0000644 ")) // mode
	copy(hdr[108:], []byte("0000000 ")) // uid
	copy(hdr[116:], []byte("0000000 ")) // gid
	copy(hdr[124:], []byte(fmt.Sprintf("%011o ", len(content))))
	copy(hdr[136:], []byte("00000000000 ")) // mtime
	// checksum: leave as spaces while computing, then fill.
	for i := 148; i < 156; i++ {
		hdr[i] = ' '
	}
	hdr[156] = '0'                   // typeflag: regular
	copy(hdr[257:], []byte("ustar")) // magic
	copy(hdr[263:], []byte("00"))    // version
	var sum int
	for _, b := range hdr {
		sum += int(b)
	}
	copy(hdr[148:], []byte(fmt.Sprintf("%06o\x00 ", sum)))
	buf.Write(hdr[:])
	buf.Write(content)
	// pad to 512.
	if pad := (512 - (len(content) % 512)) % 512; pad > 0 {
		buf.Write(make([]byte, pad))
	}
}

package cli

// exitcodes_adv_test.go — advanced regression coverage for invariant B
// (BLOCK != ERROR) of the process exit-code contract (see exitcodes.go).
//
// Contract under test:
//
//	ExitOK        = 0  success
//	ExitBlocked   = 1  policy block / --fail-on breach / findings at threshold
//	ExitOpError   = 2  operational: network / server / IO / internal
//	ExitConfigAuth= 3  configuration / authentication (401/403, missing server)
//	ExitUsage     = 4  bad invocation (unknown flag/command, bad arg shape)
//	>=10               command-specific (admission soak=10, intel hard block=11)
//
// The load-bearing rules this file pins:
//   - a BLOCK is never reported as 2 or 3 (never confused with an op/auth error);
//   - an OPERATIONAL error is never reported as 1 (never confused with a block);
//   - auth failures share ExitConfigAuth(3) across scan / intel / root-routed
//     commands, and are never reported as 2;
//   - argument-shape errors are ExitUsage(4), not ExitOpError(2);
//   - a command-specific code (soak=10, intel quarantine/replace=11) never
//     collapses back into the generic 0-4 buckets.
//
// Two layers:
//   - IN-PROCESS unit tests over the pure classifiers (treeExitCode,
//     classifyCLIError -> exitCodeForClass, ExitCodeError precedence, and the
//     renderError nil-Err cosmetic-leak guard) — fast, no toolchain needed.
//   - SUBPROCESS matrix tests over the compiled binary — the only faithful way
//     to exercise the os.Exit(code) paths (guard/scan/intel/soak). These build
//     the CLI once via buildChainsawBinForExit and drive it against httptest
//     fakes, always inside a mktemp cwd so a stray passthrough can never touch
//     the repo. They t.Skip when the go toolchain is absent.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// IN-PROCESS: pure classifiers
// ─────────────────────────────────────────────────────────────────────────────

// TestIntelScan_QuarantineBlock_NotOpErrorCode pins the invariant-B angle the
// existing TestTreeExitCode does not assert directly: the strongest intel BLOCK
// (quarantine / replace) MUST map to a block code (the command-specific
// ExitIntelBlock, in the >=10 range) and MUST NOT collide with ExitOpError(2).
// A weaker warn tree is still a block (ExitBlocked). The ordering
// ExitOK < ExitBlocked < ExitIntelBlock must hold so "clean < warn < hard-block"
// is monotonic and the hard block is never ranked below a warn.
func TestIntelScan_QuarantineBlock_NotOpErrorCode(t *testing.T) {
	tree := func(byVerdict map[string]int) *v1TreeData {
		td := &v1TreeData{}
		td.Summary.ByVerdict = byVerdict
		return td
	}

	cases := []struct {
		name     string
		verdicts map[string]int
		want     int
	}{
		{"quarantine is a block", map[string]int{"quarantine": 1}, ExitIntelBlock},
		{"replace is a block", map[string]int{"replace": 1}, ExitIntelBlock},
		{"quarantine outranks warn", map[string]int{"warn": 9, "quarantine": 1}, ExitIntelBlock},
		{"warn alone is a block", map[string]int{"warn": 1}, ExitBlocked},
		{"upgrade_available is a block", map[string]int{"upgrade_available": 3}, ExitBlocked},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := treeExitCode(tree(tc.verdicts))
			if got != tc.want {
				t.Fatalf("treeExitCode(%v) = %d; want %d", tc.verdicts, got, tc.want)
			}
			// The load-bearing guarantee: a block is NEVER the operational-error
			// code. This is what stops a CI gate from confusing "malicious
			// package" with "server was down".
			if got == ExitOpError {
				t.Fatalf("treeExitCode(%v) = ExitOpError(2); a block must never share the op-error code", tc.verdicts)
			}
			if got == ExitOK {
				t.Fatalf("treeExitCode(%v) = ExitOK(0); a block must be non-zero", tc.verdicts)
			}
		})
	}

	// Monotonic ladder: clean < warn/upgrade < quarantine/replace.
	clean := treeExitCode(tree(map[string]int{"allow": 5}))
	warn := treeExitCode(tree(map[string]int{"warn": 1}))
	hard := treeExitCode(tree(map[string]int{"quarantine": 1}))
	if !(clean < warn && warn < hard) {
		t.Fatalf("exit ladder not monotonic: allow=%d warn=%d quarantine=%d (want allow<warn<quarantine)", clean, warn, hard)
	}
	if clean != ExitOK {
		t.Fatalf("all-allow tree exit = %d; want ExitOK(0)", clean)
	}
}

// TestClassifyCLIError_BlockNeverFromPlainError walks every classifier bucket
// through the full Execute() mapping (classifyCLIError -> exitCodeForClass) and
// asserts a plain error NEVER lands on ExitBlocked(1). ExitBlocked is reserved
// for the EXPECTED enforcement outcome, which always arrives as an
// ExitCodeError{Code:1}, never as a classified plain error.
func TestClassifyCLIError_BlockNeverFromPlainError(t *testing.T) {
	cases := []struct {
		name string
		msg  string
		want int
	}{
		{"401 unauthorized", "server returned 401 unauthorized", ExitConfigAuth},
		{"bare 403", "HTTP 403: forbidden", ExitConfigAuth},
		{"connection refused", "dial tcp 127.0.0.1:1: connect: connection refused", ExitOpError},
		{"deadline/timeout", "context deadline exceeded", ExitOpError},
		{"unknown flag", "unknown flag: --bogus", ExitUsage},
		{"unknown command", `unknown command "frobnicate" for "chainsaw"`, ExitUsage},
		{"arg count", "accepts 1 arg(s), received 2", ExitUsage},
		{"flag needs arg", "flag needs an argument: --server", ExitUsage},
		{"opaque internal", "some internal failure with no keyword", ExitOpError},
		{"404 not found", "resource not found (404)", ExitOpError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			class := classifyCLIError(errors.New(tc.msg))
			got := exitCodeForClass(class)
			if got != tc.want {
				t.Fatalf("error %q classified %q -> exit %d; want %d", tc.msg, class, got, tc.want)
			}
			if got == ExitBlocked {
				t.Fatalf("plain error %q mapped to ExitBlocked(1); 1 is reserved for enforcement outcomes", tc.msg)
			}
		})
	}
}

// TestExitCodeError_CodeWinsOverClassification proves the Execute() precedence:
// an ExitCodeError with a non-zero Code overrides whatever the classifier would
// have produced, while Code==0 falls back to the classified code. This is what
// lets a command emit ExitBlocked(1) or ExitIntelBlock(11) for a message that
// would otherwise classify as "auth"/"network"/"usage".
func TestExitCodeError_CodeWinsOverClassification(t *testing.T) {
	// mirrors the exact resolution in root.go Execute().
	resolve := func(err error) int {
		class := classifyCLIError(err)
		code := exitCodeForClass(class)
		var coded *ExitCodeError
		if errors.As(err, &coded) && coded.Code != 0 {
			code = coded.Code
		}
		return code
	}

	// A block wrapping a message that reads like an auth error must still exit 1.
	blockOverAuth := &ExitCodeError{Code: ExitBlocked, Err: errors.New("401 unauthorized-looking findings")}
	if got := resolve(blockOverAuth); got != ExitBlocked {
		t.Fatalf("ExitCodeError{Blocked} over auth-looking message = %d; want ExitBlocked(1)", got)
	}
	// A command-specific code (soak=10) must win over the "not found" bucket.
	soak := &ExitCodeError{Code: ExitSoakNotCleared, Err: errors.New("soak gate not found yet")}
	if got := resolve(soak); got != ExitSoakNotCleared {
		t.Fatalf("ExitCodeError{Soak} = %d; want ExitSoakNotCleared(10)", got)
	}
	// intel hard block (11).
	intel := &ExitCodeError{Code: ExitIntelBlock}
	if got := resolve(intel); got != ExitIntelBlock {
		t.Fatalf("ExitCodeError{IntelBlock} = %d; want ExitIntelBlock(11)", got)
	}
	// Code==0 falls back to the classified code (usage here).
	zero := &ExitCodeError{Code: 0, Err: errors.New("unknown flag: --x")}
	if got := resolve(zero); got != ExitUsage {
		t.Fatalf("ExitCodeError{Code:0, usage msg} = %d; want ExitUsage(4)", got)
	}
}

// TestExitCodeError_NilErr_NoStderrErrorLine pins the cosmetic-leak fix on the
// block path: renderError, given a message-less ExitCodeError (Code set,
// Err==nil), must stay SILENT — the block reason (findings table / soak
// criteria) was already printed by the command. Printing "Error: exit 1" on top
// would be a confusing artifact. The exit code still carries the outcome; this
// test only checks that renderError does not add a stderr line, without
// weakening the code.
func TestExitCodeError_NilErr_NoStderrErrorLine(t *testing.T) {
	stderr := captureStderr(t, func() {
		renderError(&ExitCodeError{Code: ExitBlocked, Err: nil})
	})
	if strings.Contains(stderr, "Error:") {
		t.Fatalf("renderError printed an Error line for a message-less block: %q", stderr)
	}
	if strings.Contains(stderr, "exit 1") {
		t.Fatalf("renderError leaked the synthetic %q text to stderr: %q", "exit 1", stderr)
	}
	if strings.TrimSpace(stderr) != "" {
		t.Fatalf("renderError should be silent for a nil-Err ExitCodeError; got stderr=%q", stderr)
	}

	// Control: an ExitCodeError that DOES carry a message must still surface it,
	// so silencing is scoped to the nil-Err (enforcement-outcome) case only.
	stderr2 := captureStderr(t, func() {
		renderError(&ExitCodeError{Code: ExitUsage, Err: errors.New("unknown --fail-on \"bogus\"")})
	})
	if !strings.Contains(stderr2, "unknown --fail-on") {
		t.Fatalf("renderError swallowed a real error message: %q", stderr2)
	}
}

// NOTE: captureStderr (redirect os.Stderr around fn, return what was written)
// is a shared package-level helper defined in root_test.go — reused here for the
// renderError test above rather than redefined, to avoid a duplicate symbol.

// ─────────────────────────────────────────────────────────────────────────────
// SUBPROCESS: exit-code matrix over the compiled binary
// ─────────────────────────────────────────────────────────────────────────────

// exitBinOnce builds the CLI exactly once for every subprocess test in this
// file. A private, uniquely-named helper so it never collides with the
// buildChainsawBinary helper that lives in the external cli_test package.
var (
	exitBinOnce sync.Once
	exitBinPath string
	exitBinErr  error
)

// buildChainsawBinForExit compiles cmd/chainsaw once and returns the path.
// Skips (never fails) when the go toolchain is unavailable so constrained CI
// stays runnable. The binary is placed under a stable temp dir (not t.TempDir,
// which is per-test) so the sync.Once result survives across tests.
func buildChainsawBinForExit(t *testing.T) string {
	t.Helper()
	exitBinOnce.Do(func() {
		goTool, err := exec.LookPath("go")
		if err != nil {
			exitBinErr = fmt.Errorf("go toolchain not on PATH")
			return
		}
		dir, err := os.MkdirTemp("", "chainsaw-exitbin-")
		if err != nil {
			exitBinErr = err
			return
		}
		bin := filepath.Join(dir, "chainsaw")
		if runtime.GOOS == "windows" {
			bin += ".exe"
		}
		// Test cwd is core/cli; the binary main lives at ../cmd/chainsaw.
		cmd := exec.Command(goTool, "build", "-o", bin, "../cmd/chainsaw")
		if out, berr := cmd.CombinedOutput(); berr != nil {
			exitBinErr = fmt.Errorf("build failed: %v\n%s", berr, out)
			return
		}
		exitBinPath = bin
	})
	if exitBinErr != nil {
		t.Skipf("skipping subprocess exit-code test: %v", exitBinErr)
	}
	return exitBinPath
}

// runChainsawExit runs the built binary in a throwaway temp cwd with a clean,
// offline env (so telemetry/nudge chatter never pollutes stderr and a stray
// guard passthrough can never touch the repo). Returns exit code, stdout,
// stderr. CHAINSAW_OFFLINE only gates telemetry + guard-artifact fetches — it
// does NOT block the scan/intel/soak API calls to the httptest --server, which
// is exactly what these tests need.
func runChainsawExit(t *testing.T, bin string, extraEnv []string, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = t.TempDir() // isolated cwd; no lockfiles, no repo files
	cmd.Env = append(os.Environ(),
		"CHAINSAW_OFFLINE=1",
		"CHAINSAW_TELEMETRY_DISABLED=1",
		"CHAINSAW_NO_TELEMETRY=1",
		"NO_COLOR=1",
	)
	cmd.Env = append(cmd.Env, extraEnv...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !errorsAsExit(err, &ee) {
			t.Fatalf("running %v: unexpected non-exit error: %v\nstderr=%q", args, err, stderr.String())
		}
		code = ee.ExitCode()
	}
	return code, stdout.String(), stderr.String()
}

// errorsAsExit is a tiny local errors.As shim for *exec.ExitError, kept private
// to this internal-package file so it does not collide with the asExitError
// helper in the external cli_test package.
func errorsAsExit(err error, target **exec.ExitError) bool {
	return errors.As(err, target)
}

// scanServer returns an httptest server whose /api/scan reply is chosen by
// `mode`. Auth modes reply with a well-formed apiError envelope so the message
// deterministically carries "unauthorized"/"forbidden" (classifyCLIError keys
// on the 401/403 substrings regardless).
func scanServer(t *testing.T, mode string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch mode {
		case "clean":
			_, _ = w.Write([]byte(`{"results":[{"name":"lodash","version":"4.17.21","status":"clean"}],"total":1,"vulnerable":0,"unscanned":0}`))
		case "vuln-critical":
			_, _ = w.Write([]byte(`{"results":[{"name":"lodash","version":"1.0.0","status":"vulnerable","severity":"critical","cves":["CVE-2020-0001"]}],"total":1,"vulnerable":1,"unscanned":0}`))
		case "vuln-high":
			_, _ = w.Write([]byte(`{"results":[{"name":"pkg","version":"1.0.0","status":"vulnerable","severity":"high","cves":["CVE-2021-0002"]}],"total":1,"vulnerable":1,"unscanned":0}`))
		case "401":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"code":"CHW-0401","message":"unauthorized"}`))
		case "403":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"code":"CHW-0403","message":"forbidden"}`))
		default:
			t.Fatalf("scanServer: unknown mode %q", mode)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestScan_ExitCodeMatrix_BlockVsError locks the whole invariant-B contract for
// `scan` in one table: clean->0, vulnerable->1, --fail-on high over a high
// finding->1, dead-port op-error->2, 401->3, 403->3, unknown command->4. Each
// exit code is asserted EXACTLY, and a block must never be 2/3 while an op error
// must never be 1.
func TestScan_ExitCodeMatrix_BlockVsError(t *testing.T) {
	bin := buildChainsawBinForExit(t)

	type tc struct {
		name    string
		mode    string // scan server mode; "" => no server / dead port
		args    []string
		want    int
		isBlock bool
		isOp    bool
	}
	cases := []tc{
		{name: "clean->0", mode: "clean", args: []string{"scan", "lodash@4.17.21"}, want: ExitOK},
		{name: "vulnerable default gate->1", mode: "vuln-critical", args: []string{"scan", "lodash@1.0.0"}, want: ExitBlocked, isBlock: true},
		{name: "fail-on high over high->1", mode: "vuln-high", args: []string{"scan", "pkg@1.0.0", "--fail-on", "high"}, want: ExitBlocked, isBlock: true},
		{name: "401->3", mode: "401", args: []string{"scan", "lodash@1.0.0"}, want: ExitConfigAuth},
		{name: "403->3", mode: "403", args: []string{"scan", "lodash@1.0.0"}, want: ExitConfigAuth},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := scanServer(t, c.mode)
			args := append([]string{"--server", srv.URL, "--token", "t"}, c.args...)
			code, _, stderr := runChainsawExit(t, bin, nil, args...)
			if code != c.want {
				t.Fatalf("%s: exit = %d, want %d\nstderr=%q", c.name, code, c.want, stderr)
			}
			if c.isBlock && (code == ExitOpError || code == ExitConfigAuth) {
				t.Fatalf("%s: block reported as op/auth error (%d)", c.name, code)
			}
			if c.isOp && code == ExitBlocked {
				t.Fatalf("%s: operational error reported as ExitBlocked(1)", c.name)
			}
		})
	}

	// Dead-port operational error: exit 2, error only on stderr, stdout empty.
	// (No server; a port that refuses connections.)
	t.Run("dead-port op-error->2", func(t *testing.T) {
		code, stdout, stderr := runChainsawExit(t, bin, nil,
			"--server", "http://127.0.0.1:1", "--token", "t", "scan", "lodash@1.0.0")
		if code != ExitOpError {
			t.Fatalf("dead-port exit = %d, want ExitOpError(2)\nstderr=%q", code, stderr)
		}
		if code == ExitBlocked {
			t.Fatal("operational error reported as ExitBlocked(1)")
		}
		if strings.TrimSpace(stdout) != "" {
			t.Fatalf("op error wrote to stdout (should be stderr-only): %q", stdout)
		}
	})

	// Unknown command is a usage error (4), independent of any server.
	t.Run("unknown command->4", func(t *testing.T) {
		code, _, _ := runChainsawExit(t, bin, nil, "frobnicate-xyz")
		if code != ExitUsage {
			t.Fatalf("unknown command exit = %d, want ExitUsage(4)", code)
		}
	})
}

// TestScan_BlockPath_JSONStaysPure_And_QuietDoesNotChangeExit pins two crossing
// invariants on the scan BLOCK path:
//   - invariant C: under --json, stdout on a block is EXACTLY one JSON object
//     (no findings table, no progress, no "Error:" line);
//   - invariant D: --quiet suppresses chatter only — it must NOT change the
//     block exit code (still 1) nor hide the verdict.
func TestScan_BlockPath_JSONStaysPure_And_QuietDoesNotChangeExit(t *testing.T) {
	bin := buildChainsawBinForExit(t)
	srv := scanServer(t, "vuln-critical")

	// --json on a block: stdout is a single well-formed JSON object.
	t.Run("json block stdout is pure", func(t *testing.T) {
		code, stdout, _ := runChainsawExit(t, bin, nil,
			"--server", srv.URL, "--token", "t", "scan", "lodash@1.0.0", "--json")
		if code != ExitBlocked {
			t.Fatalf("json block exit = %d, want ExitBlocked(1)", code)
		}
		assertSingleJSONObject(t, stdout)
		if strings.Contains(stdout, "Error:") {
			t.Fatalf("stdout carried an error line on the block path: %q", stdout)
		}
	})

	// --quiet on a block: exit code unchanged.
	t.Run("quiet does not change block exit", func(t *testing.T) {
		code, _, _ := runChainsawExit(t, bin, nil,
			"--server", srv.URL, "--token", "t", "--quiet", "scan", "lodash@1.0.0")
		if code != ExitBlocked {
			t.Fatalf("--quiet block exit = %d, want ExitBlocked(1)", code)
		}
	})

	// --quiet AND --json together: still exactly one JSON object, still exit 1.
	t.Run("quiet+json block stays pure and exit 1", func(t *testing.T) {
		code, stdout, _ := runChainsawExit(t, bin, nil,
			"--server", srv.URL, "--token", "t", "--quiet", "scan", "lodash@1.0.0", "--json")
		if code != ExitBlocked {
			t.Fatalf("--quiet --json block exit = %d, want ExitBlocked(1)", code)
		}
		assertSingleJSONObject(t, stdout)
	})
}

// assertSingleJSONObject fails unless s decodes as exactly one JSON value with
// no trailing bytes — the strict "stdout carries ONLY the JSON object" check.
func assertSingleJSONObject(t *testing.T, s string) {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(s))
	var v json.RawMessage
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("stdout is not a single JSON value: %v\nstdout=%q", err, s)
	}
	if dec.More() {
		t.Fatalf("stdout has trailing bytes after the JSON object (impure): %q", s)
	}
}

// TestScan_UsageError_ExitsUsage4 pins that argument-shape errors on scan map to
// ExitUsage(4), never ExitOpError(2): a bogus --fail-on value, a bogus
// --severity value, and a bare `scan` with no package/path/stdin. A live server
// is provided so the failure is unambiguously the argument shape, not a missing
// server (which would be 3).
func TestScan_UsageError_ExitsUsage4(t *testing.T) {
	bin := buildChainsawBinForExit(t)
	srv := scanServer(t, "clean")
	base := []string{"--server", srv.URL, "--token", "t"}

	cases := []struct {
		name string
		args []string
	}{
		{"bogus --fail-on", append(append([]string{}, base...), "scan", "pkg@1.0.0", "--fail-on", "bogus")},
		{"bogus --severity", append(append([]string{}, base...), "scan", "pkg@1.0.0", "--severity", "bogus")},
		{"no package/path/stdin", append(append([]string{}, base...), "scan")},
		{"unknown flag", append(append([]string{}, base...), "scan", "pkg@1.0.0", "--totally-unknown")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, _, stderr := runChainsawExit(t, bin, nil, c.args...)
			if code != ExitUsage {
				t.Fatalf("%s: exit = %d, want ExitUsage(4)\nstderr=%q", c.name, code, stderr)
			}
			if code == ExitOpError {
				t.Fatalf("%s: usage error mislabeled as ExitOpError(2)", c.name)
			}
		})
	}
}

// TestScanAndIntel_AuthError_ExitsConfigAuth3 proves auth failures share ONE
// code (ExitConfigAuth) across the scan path, the intel v1 path (evaluate +
// health), and a root-routed command (policy list) — and are NEVER reported as
// ExitOpError(2). Both 401 and 403 must land on 3.
func TestScanAndIntel_AuthError_ExitsConfigAuth3(t *testing.T) {
	bin := buildChainsawBinForExit(t)

	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		status := status
		body := `{"code":"CHW-0401","message":"unauthorized"}`
		if status == http.StatusForbidden {
			body = `{"code":"CHW-0403","message":"forbidden"}`
		}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(srv.Close)

		// intel scan needs a lockfile in cwd; write one into an isolated dir and
		// point --lockfile at it (avoids depending on the process cwd detection).
		lockDir := t.TempDir()
		lock := filepath.Join(lockDir, "package-lock.json")
		if err := os.WriteFile(lock, []byte(`{"lockfileVersion":3}`), 0o644); err != nil {
			t.Fatalf("write lockfile: %v", err)
		}

		commands := []struct {
			name string
			args []string
		}{
			{"scan", []string{"--server", srv.URL, "--token", "t", "scan", "pkg@1.0.0"}},
			{"intel scan", []string{"--server", srv.URL, "--token", "t", "intel", "scan", "--lockfile", lock}},
			{"intel health", []string{"--server", srv.URL, "--token", "t", "intel", "health"}},
			{"policy list", []string{"--server", srv.URL, "--token", "t", "policy", "list"}},
		}
		for _, c := range commands {
			t.Run(fmt.Sprintf("%d/%s", status, c.name), func(t *testing.T) {
				code, _, stderr := runChainsawExit(t, bin, nil, c.args...)
				if code != ExitConfigAuth {
					t.Fatalf("%s @ HTTP %d: exit = %d, want ExitConfigAuth(3)\nstderr=%q", c.name, status, code, stderr)
				}
				if code == ExitOpError {
					t.Fatalf("%s @ HTTP %d: auth failure reported as ExitOpError(2)", c.name, status)
				}
				if code == ExitBlocked {
					t.Fatalf("%s @ HTTP %d: auth failure reported as ExitBlocked(1)", c.name, status)
				}
			})
		}
	}
}

// TestIntelScan_ExitCodeTaxonomy pins the intel scan ladder end-to-end:
// all-allow->0, warn->1, quarantine->11 (the command-specific hard block, NOT
// ExitOpError(2)), dead-port->2. The 0 < 1 < 11 ordering means a CI gate can
// tell clean from warn from hard-block, and a hard block never collides with an
// operational failure.
func TestIntelScan_ExitCodeTaxonomy(t *testing.T) {
	bin := buildChainsawBinForExit(t)

	intelServer := func(verdicts string) *httptest.Server {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			// v1 envelope: data.summary.ByVerdict drives treeExitCode.
			_, _ = w.Write([]byte(`{"apiVersion":"v1","data":{"nodes":[],"summary":{"TotalNodes":1,"DirectCount":1,"TransitiveCount":0,"ByVerdict":` + verdicts + `,"MinOverall":10}}}`))
		}))
		t.Cleanup(srv.Close)
		return srv
	}

	lock := filepath.Join(t.TempDir(), "package-lock.json")
	if err := os.WriteFile(lock, []byte(`{"lockfileVersion":3}`), 0o644); err != nil {
		t.Fatalf("write lockfile: %v", err)
	}

	cases := []struct {
		name     string
		verdicts string
		want     int
		isBlock  bool
	}{
		{"all allow->0", `{"allow":3}`, ExitOK, false},
		{"warn->1", `{"warn":1}`, ExitBlocked, true},
		{"quarantine->11", `{"quarantine":1}`, ExitIntelBlock, true},
		{"replace->11", `{"replace":1}`, ExitIntelBlock, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := intelServer(c.verdicts)
			code, _, stderr := runChainsawExit(t, bin, nil,
				"--server", srv.URL, "--token", "t", "intel", "scan", "--lockfile", lock)
			if code != c.want {
				t.Fatalf("%s: exit = %d, want %d\nstderr=%q", c.name, code, c.want, stderr)
			}
			if c.isBlock && code == ExitOpError {
				t.Fatalf("%s: intel block reported as ExitOpError(2)", c.name)
			}
		})
	}

	// Dead port -> operational error 2, never a block.
	t.Run("dead-port->2", func(t *testing.T) {
		code, _, _ := runChainsawExit(t, bin, nil,
			"--server", "http://127.0.0.1:1", "--token", "t", "intel", "scan", "--lockfile", lock)
		if code != ExitOpError {
			t.Fatalf("intel dead-port exit = %d, want ExitOpError(2)", code)
		}
		if code == ExitBlocked || code == ExitIntelBlock {
			t.Fatalf("intel op error reported as a block code (%d)", code)
		}
	})

	// Unsupported lockfile shape -> usage error 4, not op error.
	t.Run("bad lockfile arg->4", func(t *testing.T) {
		bad := filepath.Join(t.TempDir(), "not-a-lockfile.txt")
		if err := os.WriteFile(bad, []byte("x"), 0o644); err != nil {
			t.Fatalf("write bad file: %v", err)
		}
		srv := intelServer(`{"allow":1}`)
		code, _, _ := runChainsawExit(t, bin, nil,
			"--server", srv.URL, "--token", "t", "intel", "scan", "--lockfile", bad)
		if code != ExitUsage {
			t.Fatalf("bad --lockfile exit = %d, want ExitUsage(4)", code)
		}
	})
}

// TestAdmissionSoakClear_ExitCodeTaxonomy pins the reference-correct
// command-specific separation for `admission soak clear`:
//
//	cleared:false -> 10 (ExitSoakNotCleared, NOT 3 which it used to collide with)
//	cleared:true  -> 0
//	401           -> 3 (auth, never 2)
//	dead-port     -> 2 (operational, never 10 and never 1)
//
// so the soak path can never regress into the scan/intel os.Exit(2) anti-pattern
// nor re-collide "gate not cleared" with "auth failure".
func TestAdmissionSoakClear_ExitCodeTaxonomy(t *testing.T) {
	bin := buildChainsawBinForExit(t)

	soakServer := func(handler http.HandlerFunc) *httptest.Server {
		srv := httptest.NewServer(handler)
		t.Cleanup(srv.Close)
		return srv
	}

	t.Run("not cleared->10", func(t *testing.T) {
		srv := soakServer(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"cleared":false,"missing":[{"name":"days","met":false,"evidence":"2/7 days"}],"suggestion":"wait"}`))
		})
		code, stdout, stderr := runChainsawExit(t, bin, nil,
			"--server", srv.URL, "--token", "t", "admission", "soak", "clear")
		if code != ExitSoakNotCleared {
			t.Fatalf("not-cleared exit = %d, want ExitSoakNotCleared(10)\nstderr=%q", code, stderr)
		}
		if code == ExitConfigAuth {
			t.Fatal("not-cleared collided with ExitConfigAuth(3) — the bug the renumber fixed")
		}
		// Missing criteria print to stderr; stdout stays empty on the unhappy path.
		if strings.TrimSpace(stdout) != "" {
			t.Fatalf("not-cleared wrote to stdout (should be stderr-only): %q", stdout)
		}
	})

	t.Run("cleared->0", func(t *testing.T) {
		srv := soakServer(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"cleared":true,"kubectl_patch":"kubectl patch validatingwebhookconfiguration ..."}`))
		})
		code, stdout, _ := runChainsawExit(t, bin, nil,
			"--server", srv.URL, "--token", "t", "admission", "soak", "clear")
		if code != ExitOK {
			t.Fatalf("cleared exit = %d, want ExitOK(0)", code)
		}
		if strings.TrimSpace(stdout) == "" {
			t.Fatal("cleared gate printed nothing to stdout (expected kubectl patch)")
		}
	})

	t.Run("401->3", func(t *testing.T) {
		srv := soakServer(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"code":"CHW-0401","message":"unauthorized"}`))
		})
		code, _, _ := runChainsawExit(t, bin, nil,
			"--server", srv.URL, "--token", "t", "admission", "soak", "clear")
		if code != ExitConfigAuth {
			t.Fatalf("soak 401 exit = %d, want ExitConfigAuth(3)", code)
		}
		if code == ExitSoakNotCleared {
			t.Fatal("soak auth failure mislabeled as ExitSoakNotCleared(10)")
		}
	})

	t.Run("dead-port->2", func(t *testing.T) {
		code, _, _ := runChainsawExit(t, bin, nil,
			"--server", "http://127.0.0.1:1", "--token", "t", "admission", "soak", "clear")
		if code != ExitOpError {
			t.Fatalf("soak dead-port exit = %d, want ExitOpError(2)", code)
		}
		if code == ExitSoakNotCleared || code == ExitBlocked {
			t.Fatalf("soak op error mislabeled as a block code (%d)", code)
		}
	})
}

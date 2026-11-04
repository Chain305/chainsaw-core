package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/cli/hook"
	"github.com/chain305/chainsaw-core/homebrew"
)

func specNames(specs []packageSpec) []string {
	var out []string
	for _, s := range specs {
		n := s.Name
		if n == "" {
			n = "origin=" + s.Origin
		}
		if s.HomebrewKind != "" {
			n += "/" + s.HomebrewKind
		}
		out = append(out, n)
	}
	return out
}

func TestParseBrewInstall(t *testing.T) {
	stubBrewOutput(t, func(args ...string) ([]byte, error) {
		if strings.Join(args, " ") != "outdated --json=v2" {
			return nil, errors.New("unexpected " + strings.Join(args, " "))
		}
		return []byte(`{"formulae":[{"name":"jq"}],"casks":[{"name":"firefox"}]}`), nil
	})
	for _, c := range []struct {
		args []string
		ok   bool
		want []string
	}{
		{[]string{"install", "jq", "wget"}, true, []string{"jq", "wget"}},
		{[]string{"instal", "jq"}, true, []string{"jq"}}, // brew's own alias
		{[]string{"install", "--cask", "firefox", "iterm2"}, true, []string{"firefox/cask", "iterm2/cask"}},
		{[]string{"reinstall", "--formula", "homebrew/core/JQ"}, true, []string{"jq/formula"}},
		{[]string{"install", "--cc", "clang", "jq"}, true, []string{"jq"}},
		{[]string{"install", "--appdir=/Applications", "--cask", "x"}, true, []string{"x/cask"}},
		{[]string{"install", "user/tap/tool"}, true, []string{"user/tap/tool"}},
		{[]string{"install", "./local.rb"}, true, []string{"origin=file:./local.rb"}},
		{[]string{"install", "https://example.com/f.rb"}, true, []string{"origin=https://example.com/f.rb"}},
		{[]string{"upgrade"}, true, []string{"jq/formula", "firefox/cask"}},
		{[]string{"upgrade", "jq"}, true, []string{"jq"}},
		{[]string{"list"}, false, nil},
		{[]string{"uninstall", "jq"}, false, nil},
	} {
		got, ok := parseBrewInstall(c.args)
		if ok != c.ok || !reflect.DeepEqual(specNames(got), c.want) {
			t.Errorf("%v: got %v %v, want %v %v", c.args, specNames(got), ok, c.want, c.ok)
		}
		for _, s := range got {
			if s.Ecosystem != "homebrew" {
				t.Errorf("%v: ecosystem %q", c.args, s.Ecosystem)
			}
		}
	}
}

func TestParseBrewUpgradeOutdatedFailureIsNotSilent(t *testing.T) {
	stubBrewOutput(t, func(...string) ([]byte, error) { return nil, errors.New("boom") })
	got, ok := parseBrewInstall([]string{"upgrade"})
	if !ok || len(got) != 1 || !strings.HasPrefix(got[0].Origin, unparsedLockPrefix) {
		t.Fatalf("got %+v %v, want one not-assessed spec", got, ok)
	}
}

func TestParseBrewBundle(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("HOMEBREW_BUNDLE_FILE", "")
	bf := "tap \"acme/tools\"\nbrew \"jq\"\ncask \"firefox\"\nbrew \"acme/tools/x\"\nmas \"Xcode\", id: 1\n"
	if err := os.WriteFile(filepath.Join(dir, "Brewfile"), []byte(bf), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "other.Brewfile"), []byte("cask \"zoom\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	want := []string{"jq/formula", "firefox/cask", "acme/tools/x/formula"}
	for _, args := range [][]string{{"bundle"}, {"bundle", "install"}, {"bundle", "--verbose", "install"}} {
		got, ok := parseBrewInstall(args)
		if !ok || !reflect.DeepEqual(specNames(got), want) {
			t.Errorf("%v: got %v %v", args, specNames(got), ok)
		}
	}
	got, _ := parseBrewInstall([]string{"bundle", "--file", "other.Brewfile"})
	if !reflect.DeepEqual(specNames(got), []string{"zoom/cask"}) {
		t.Errorf("--file: %v", specNames(got))
	}
	got, _ = parseBrewInstall([]string{"bundle", "--file=-"})
	if len(got) != 1 || !strings.HasPrefix(got[0].Origin, unparsedLockPrefix) {
		t.Errorf("--file=-: %+v", got)
	}
	for _, args := range [][]string{{"bundle", "dump"}, {"bundle", "check"}, {"bundle", "cleanup"}} {
		if _, ok := parseBrewInstall(args); ok {
			t.Errorf("%v should pass through", args)
		}
	}
	if got, ok := parseBrewInstall([]string{"bundle", "--file", "missing"}); !ok || len(got) != 0 {
		t.Errorf("missing Brewfile: %v %v", got, ok)
	}
}

// The shared verb-seeker would anchor `brew bundle install` on "install" and
// drop the Brewfile; guardSpecsFor must use brew's own command anchoring.
func TestGuardSpecsForBrewBundleInstall(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("HOMEBREW_BUNDLE_FILE", "")
	if err := os.WriteFile("Brewfile", []byte("brew \"jq\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	specs, ok, _ := guardSpecsFor("brew", []string{"--json", "-v", "bundle", "install"}, parseBrewInstall)
	if !ok || !reflect.DeepEqual(specNames(specs), []string{"jq/formula"}) {
		t.Fatalf("got %v %v", specNames(specs), ok)
	}
}

func fakeBrewAPI(t *testing.T) string {
	t.Helper()
	docs := map[string]string{
		"/formula/jq.json":   `{"name":"jq","tap":"homebrew/core","versions":{"stable":"1.7.1"},"revision":1}`,
		"/formula/old.json":  `{"name":"old","versions":{"stable":"2.0"},"deprecated":true,"deprecation_date":"2026-01-01","deprecation_reason":"unmaintained","deprecation_replacement_formula":"new"}`,
		"/formula/dead.json": `{"name":"dead","versions":{"stable":"1.0"},"disabled":true,"disable_reason":"does not build"}`,
		"/cask/firefox.json": `{"token":"firefox","tap":"homebrew/cask","version":"130.0","sha256":"abc","auto_updates":true,"artifacts":[{"app":["Firefox.app"]}]}`,
		"/cask/sketchy.json": `{"token":"sketchy","version":"latest","sha256":"no_check","artifacts":[{"pkg":["x.pkg"]},{"postflight":null}]}`,
		"/cask/gone.json":    `{"token":"gone","version":"1","sha256":"abc","disabled":true,"disable_reason":"fails Gatekeeper"}`,
		"/cask/plain.json":   `{"token":"plain","version":"1","sha256":"abc"}`,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/formula/flaky.json" {
			http.Error(w, "boom", http.StatusBadGateway)
			return
		}
		d, ok := docs[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, d)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestBrewPreflight(t *testing.T) {
	withIsolatedConfigHome(t)
	t.Setenv(guardAllowlistEnv, filepath.Join(t.TempDir(), "allow.json"))
	invalidateGuardAllowlistCache()
	t.Cleanup(invalidateGuardAllowlistCache)
	api := fakeBrewAPI(t)
	h := func(name, kind string) packageSpec {
		return packageSpec{Ecosystem: "homebrew", Name: name, HomebrewKind: kind}
	}
	specs := []packageSpec{
		h("jq", ""), h("old", ""), h("dead", ""), h("firefox", ""), h("sketchy", "cask"),
		h("gone", "cask"), h("plain", "cask"), h("user/tap/tool", ""), h("nosuch", ""), h("flaky", ""),
		{Ecosystem: "homebrew", Origin: "file:./x.rb"}, {Ecosystem: "npm", Name: "jq"},
	}
	out, verdicts, notices := brewPreflight(context.Background(), http.DefaultClient, api, specs)

	if out[0].Version != "1.7.1_1" || out[0].HomebrewKind != "formula" {
		t.Errorf("jq resolved to %+v", out[0])
	}
	if out[3].Version != "130.0" || out[3].HomebrewKind != "cask" {
		t.Errorf("firefox should fall back to the cask: %+v", out[3])
	}
	got := map[string]guardVerdict{}
	for _, v := range verdicts {
		got[v.Spec.Name] = v
	}
	for name, want := range map[string]struct {
		block    bool
		severity string
		reason   string
	}{
		"old":           {false, guardSeverityHomebrewDeprecated, "deprecated by Homebrew on 2026-01-01 (unmaintained); replacement: new"},
		"dead":          {true, guardSeverityHomebrewDisabled, "formula disabled by Homebrew (does not build)"},
		"firefox":       {false, guardSeverityHomebrewCask, "updates itself outside Homebrew"},
		"sketchy":       {false, guardSeverityHomebrewCask, "not checksum-pinned"},
		"gone":          {true, guardSeverityHomebrewDisabled, "fails Gatekeeper"},
		"user/tap/tool": {true, guardSeverityHomebrewTap, "chainsaw guard allow homebrew:user/tap/tool"},
	} {
		v, ok := got[name]
		if !ok {
			t.Errorf("%s: no verdict", name)
			continue
		}
		if v.Block != want.block || v.Severity != want.severity || !strings.Contains(v.Reason, want.reason) {
			t.Errorf("%s: got %+v, want block=%v %s ~%q", name, v, want.block, want.severity, want.reason)
		}
	}
	if s := got["sketchy"].Reason; !strings.Contains(s, "vendor installer") || !strings.Contains(s, "hooks") {
		t.Errorf("sketchy reason misses facts: %q", s)
	}
	for _, clean := range []string{"jq", "plain", "nosuch", "flaky"} {
		if _, ok := got[clean]; ok {
			t.Errorf("%s: unexpected verdict %+v", clean, got[clean])
		}
	}
	if len(verdicts) != 6 {
		t.Errorf("verdicts = %d, want 6", len(verdicts))
	}
	joined := strings.Join(notices, "\n")
	if !strings.Contains(joined, "could not verify homebrew:nosuch") || !strings.Contains(joined, "could not verify homebrew:flaky") || len(notices) != 2 {
		t.Errorf("notices = %q", notices)
	}

	// A reviewed tap, allowed locally, warns instead of refusing.
	if err := executeRootArgs(t, "guard", "allow", "homebrew:user/tap/tool"); err != nil {
		t.Fatalf("guard allow: %v", err)
	}
	invalidateGuardAllowlistCache()
	_, verdicts, _ = brewPreflight(context.Background(), http.DefaultClient, api, []packageSpec{h("user/tap/tool", "")})
	if len(verdicts) != 1 || verdicts[0].Block || !strings.Contains(verdicts[0].Reason, "allowed by your local allowlist") {
		t.Fatalf("allowed tap: %+v", verdicts)
	}
}

func TestBrewPreflightOffline(t *testing.T) {
	t.Setenv("CHAINSAW_OFFLINE", "1")
	orig := brewAPIClient
	brewAPIClient = func() homebrew.Doer { t.Fatal("network client requested while offline"); return nil }
	t.Cleanup(func() { brewAPIClient = orig })
	specs := []packageSpec{{Ecosystem: "homebrew", Name: "jq"}}
	out, verdicts, notices := runBrewPreflight(context.Background(), specs)
	if len(verdicts) != 0 || len(notices) != 1 || !strings.Contains(notices[0], "CHAINSAW_OFFLINE") || out[0].Version != "" {
		t.Fatalf("got %+v %+v %q", out, verdicts, notices)
	}
}

func stubBrewOutput(t *testing.T, fn func(args ...string) ([]byte, error)) {
	t.Helper()
	orig := brewOutput
	brewOutput = fn
	t.Cleanup(func() { brewOutput = orig })
}

func TestBrewCommandRouting(t *testing.T) {
	for argv, want := range map[string]*cobra.Command{
		"brew install jq":          brewGuardCmd,
		"brew --cask install x":    brewGuardCmd,
		"brew bundle":              brewGuardCmd,
		"brew env --write":         brewEnvCmd,
		"brew inventory --dry-run": brewInventoryCmd,
	} {
		c, _, err := rootCmd.Find(strings.Fields(argv))
		if err != nil || c != want {
			t.Errorf("%q resolved to %v (%v), want %s", argv, c.CommandPath(), err, want.CommandPath())
		}
	}
	found := false
	for _, g := range guardedTools {
		found = found || (g.fn == "brew" && g.tool == "brew")
	}
	if !found {
		t.Error("brew is not shimmed by guard init")
	}
	if ecosystemFor("brew") != "homebrew" {
		t.Error("ecosystemFor(brew)")
	}
}

func TestServerPreflightSendsHomebrewFormulaeOnly(t *testing.T) {
	var sent []scanPkg
	mux := http.NewServeMux()
	mux.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Packages []scanPkg `json:"packages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		sent = req.Packages
		_ = json.NewEncoder(w).Encode(scanAPIResponse{Results: []scanResultItem{{
			Name: "jq", Version: "1.7.1_1", Status: "vulnerable", Severity: "critical", CVEs: []string{"CVE-X"},
		}}})
	})
	configureGuardPreflight(t, mux)
	verdicts, blocked, notice := serverInstallPreflight(context.Background(), []packageSpec{
		{Ecosystem: "homebrew", Name: "jq", Version: "1.7.1_1", HomebrewKind: "formula"},
		{Ecosystem: "homebrew", Name: "firefox", Version: "130.0", HomebrewKind: "cask"},
		{Ecosystem: "homebrew", Name: "a/b/c", Version: "1", HomebrewKind: "formula"},
		{Ecosystem: "homebrew", Name: "unresolved"},
	})
	if notice != "" || !blocked || len(verdicts) != 1 || verdicts[0].Spec.Ecosystem != "homebrew" {
		t.Fatalf("verdicts=%+v blocked=%v notice=%q", verdicts, blocked, notice)
	}
	if len(sent) != 1 || sent[0] != (scanPkg{Name: "jq", Version: "1.7.1_1", Ecosystem: "homebrew"}) {
		t.Fatalf("sent %+v", sent)
	}
}

func TestValidateBrewEnv(t *testing.T) {
	for body, wantErr := range map[string]string{
		"# org policy\n\nHOMEBREW_FORBIDDEN_FORMULAE=a b\r\nHOMEBREW_CASK_OPTS=--require-sha\n": "",
		"HOMEBREW_FORBID_PACKAGES_FROM_PATHS=1\n":                                               "",
		"export HOMEBREW_X=1\n":                   "not a comment",
		"PATH=/tmp\n":                             "not a comment",
		"HOMEBREW_lower=1\n":                      "not a comment",
		"HOMEBREW_CURL_PATH=/tmp/evil\n":          "run a program",
		"HOMEBREW_EDITOR=vim\n":                   "run a program",
		"HOMEBREW_BREW_GIT_REMOTE=https://evil\n": "run a program",
		"HOMEBREW_X=a\x1b[2Jb\n":                  "control character",
		"# >>> chainsaw-brew-policy >>>\n":        "marker",
		"<html>oops</html>\n":                     "not a comment",
	} {
		_, err := validateBrewEnv(body)
		if (wantErr == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), wantErr)) {
			t.Errorf("validateBrewEnv(%q) = %v, want %q", body, err, wantErr)
		}
	}
}

func newBrewEnvTestCmd(flags map[string]string) *cobra.Command {
	c := &cobra.Command{}
	c.Flags().String("repo", "", "")
	c.Flags().Bool("write", false, "")
	c.Flags().Bool("system", false, "")
	for k, v := range flags {
		_ = c.Flags().Set(k, v)
	}
	c.SetOut(&bytes.Buffer{})
	return c
}

func TestBrewEnvCommand(t *testing.T) {
	const policy = "# compiled\nHOMEBREW_FORBIDDEN_FORMULAE=evil\n"
	var gotRepo, gotAccept string
	body := policy
	mux := http.NewServeMux()
	mux.HandleFunc("/api/homebrew/brew.env", func(w http.ResponseWriter, r *http.Request) {
		gotRepo, gotAccept = r.URL.Query().Get("repo"), r.Header.Get("Accept")
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, body)
	})
	configureGuardPreflight(t, mux)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")

	c := newBrewEnvTestCmd(map[string]string{"repo": "brew-main"})
	if err := runBrewEnv(c, nil); err != nil {
		t.Fatal(err)
	}
	if out := c.OutOrStdout().(*bytes.Buffer).String(); out != policy || gotRepo != "brew-main" || gotAccept != "text/plain" {
		t.Fatalf("stdout=%q repo=%q accept=%q", out, gotRepo, gotAccept)
	}

	userEnv := filepath.Join(home, ".homebrew", "brew.env")
	_ = os.MkdirAll(filepath.Dir(userEnv), 0o755)
	_ = os.WriteFile(userEnv, []byte("HOMEBREW_NO_ANALYTICS=1\n"), 0o644)
	if err := runBrewEnv(newBrewEnvTestCmd(map[string]string{"write": "true"}), nil); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(userEnv)
	if !strings.Contains(string(b), "HOMEBREW_NO_ANALYTICS=1") || !strings.Contains(string(b), "HOMEBREW_FORBIDDEN_FORMULAE=evil") {
		t.Fatalf("user brew.env:\n%s", b)
	}

	// A hostile response is refused and nothing is written.
	body = "HOMEBREW_GIT_PATH=/tmp/x\n"
	err := runBrewEnv(newBrewEnvTestCmd(map[string]string{"write": "true"}), nil)
	var ec *ExitCodeError
	if !errors.As(err, &ec) || ec.Code != ExitOpError {
		t.Fatalf("hostile body: %v", err)
	}
	if b2, _ := os.ReadFile(userEnv); !bytes.Equal(b, b2) {
		t.Fatal("hostile response modified brew.env")
	}

	// --system needs root and never escalates.
	orig := brewEnvGeteuid
	brewEnvGeteuid = func() int { return 501 }
	t.Cleanup(func() { brewEnvGeteuid = orig })
	err = runBrewEnv(newBrewEnvTestCmd(map[string]string{"system": "true"}), nil)
	if !errors.As(err, &ec) || ec.Code != ExitUsage || !strings.Contains(err.Error(), "sudo chainsaw brew env --system") {
		t.Fatalf("--system as non-root: %v", err)
	}
	sys := filepath.Join(t.TempDir(), "etc", "brew.env")
	origSys := hook.BrewSystemEnvPath
	hook.BrewSystemEnvPath = sys
	t.Cleanup(func() { hook.BrewSystemEnvPath = origSys })
	brewEnvGeteuid = func() int { return 0 }
	body = policy
	if err := runBrewEnv(newBrewEnvTestCmd(map[string]string{"system": "true"}), nil); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(sys); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("system brew.env: %v %v", info, err)
	}
	if err := runBrewEnv(newBrewEnvTestCmd(map[string]string{"system": "true", "write": "true"}), nil); !errors.As(err, &ec) || ec.Code != ExitUsage {
		t.Fatalf("--write --system: %v", err)
	}
}

func newBrewInventoryTestCmd(flags map[string]string) *cobra.Command {
	c := &cobra.Command{}
	c.Flags().String("target", "", "")
	c.Flags().Bool("dry-run", false, "")
	c.Flags().String("file", "", "")
	for k, v := range flags {
		_ = c.Flags().Set(k, v)
	}
	c.SetOut(&bytes.Buffer{})
	return c
}

func TestBrewInventoryCommand(t *testing.T) {
	const inv = `{"formulae":[{"name":"jq","installed":[{"version":"1.7.1"}]}],"casks":[{"token":"firefox"}]}`
	var gotTarget, gotBody string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/homebrew/inventory", func(w http.ResponseWriter, r *http.Request) {
		gotTarget = r.URL.Query().Get("target")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		_, _ = io.WriteString(w, `{"target":"mac-1","formulae":1,"casks":1,"accepted":1,"skipped":[{"name":"firefox","reason":"casks have no advisories"}]}`)
	})
	configureGuardPreflight(t, mux)
	calls := 0
	stubBrewOutput(t, func(args ...string) ([]byte, error) {
		calls++
		if strings.Join(args, " ") != "info --json=v2 --installed" {
			t.Errorf("ran brew %v", args)
		}
		return []byte(inv), nil
	})

	c := newBrewInventoryTestCmd(map[string]string{"target": "mac-1"})
	if err := runBrewInventory(c, nil); err != nil {
		t.Fatal(err)
	}
	out := c.OutOrStdout().(*bytes.Buffer).String()
	if gotTarget != "mac-1" || gotBody != inv || calls != 1 ||
		!strings.Contains(out, "1 accepted, 1 skipped") || !strings.Contains(out, "skipped firefox: casks have no advisories") {
		t.Fatalf("target=%q body=%q out=%q", gotTarget, gotBody, out)
	}

	// --dry-run sends nothing.
	gotTarget = ""
	c = newBrewInventoryTestCmd(map[string]string{"target": "mac-1", "dry-run": "true"})
	if err := runBrewInventory(c, nil); err != nil || gotTarget != "" ||
		!strings.Contains(c.OutOrStdout().(*bytes.Buffer).String(), "would upload 1 formulae and 1 casks") {
		t.Fatalf("dry run: %v target=%q", err, gotTarget)
	}

	// --file skips brew.
	f := filepath.Join(t.TempDir(), "inv.json")
	_ = os.WriteFile(f, []byte(inv), 0o644)
	if err := runBrewInventory(newBrewInventoryTestCmd(map[string]string{"file": f, "target": "t2"}), nil); err != nil || calls != 2 || gotTarget != "t2" {
		t.Fatalf("--file: %v calls=%d target=%q", err, calls, gotTarget)
	}

	// Not a brew info document / brew missing.
	_ = os.WriteFile(f, []byte(`[1,2]`), 0o644)
	var ec *ExitCodeError
	if err := runBrewInventory(newBrewInventoryTestCmd(map[string]string{"file": f}), nil); !errors.As(err, &ec) || ec.Code != ExitUsage {
		t.Fatalf("bad doc: %v", err)
	}
	stubBrewOutput(t, func(...string) ([]byte, error) { return nil, errors.New("brew not found on PATH") })
	if err := runBrewInventory(newBrewInventoryTestCmd(nil), nil); !errors.As(err, &ec) || ec.Code != ExitOpError || !strings.Contains(err.Error(), "--file") {
		t.Fatalf("no brew: %v", err)
	}
}

func TestScanListsBrewfileRowsNotAssessed(t *testing.T) {
	reg, non := splitNonRegistry([]scanPkg{
		{Name: "jq", Ecosystem: "homebrew"},
		{Name: "a/b/c", Ecosystem: "homebrew", Origin: "git+https://github.com/a/homebrew-b"},
		{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"},
	})
	if len(reg) != 1 || len(non) != 2 {
		t.Fatalf("reg=%v non=%v", reg, non)
	}
	rows := nonRegistryResults(non, nil)
	if rows[0].Status != statusNotAssessed || !strings.Contains(rows[0].OriginReason, "current recipe") {
		t.Fatalf("row %+v", rows[0])
	}
}

// Review 2026-11-04: `brew bundle --global` reads the user-config-home
// Brewfile (~/.homebrew/Brewfile — a directory the brew hook creates) when it
// exists or ~/.Brewfile does not, and --global beats --file. The guard read
// ~/.Brewfile, so it checked nothing while brew installed everything.
func TestBrewfilePathMirrorsBrew(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOMEBREW_XDG_CONFIG_HOME", "")
	t.Setenv("HOMEBREW_BUNDLE_FILE", "")
	t.Setenv("HOMEBREW_BUNDLE_FILE_GLOBAL", "")
	write := func(p string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("brew \"jq\"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	dotBrewfile := filepath.Join(home, ".Brewfile")
	userDir := filepath.Join(home, ".homebrew")
	userBrewfile := filepath.Join(userDir, "Brewfile")

	if got := brewfilePath("", true); got != dotBrewfile {
		t.Fatalf("no config dir: %s", got)
	}
	if err := os.MkdirAll(userDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := brewfilePath("", true); got != userBrewfile {
		t.Fatalf("config dir, no Brewfiles: got %s want %s", got, userBrewfile)
	}
	write(dotBrewfile)
	if got := brewfilePath("", true); got != dotBrewfile {
		t.Fatalf("only ~/.Brewfile exists: %s", got)
	}
	write(userBrewfile)
	if got := brewfilePath("", true); got != userBrewfile {
		t.Fatalf("both exist: got %s want the config-home one", got)
	}
	if got := brewfilePath("other/Brewfile", true); got != userBrewfile {
		t.Fatalf("--global must win over --file: %s", got)
	}
	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)
	write(filepath.Join(xdg, "homebrew", "Brewfile"))
	if got := brewfilePath("", true); got != filepath.Join(xdg, "homebrew", "Brewfile") {
		t.Fatalf("XDG: %s", got)
	}
	t.Setenv("HOMEBREW_BUNDLE_FILE_GLOBAL", "/x/G")
	if got := brewfilePath("", true); got != "/x/G" {
		t.Fatalf("env global: %s", got)
	}
	if got := brewfilePath("F", false); got != "F" {
		t.Fatalf("--file: %s", got)
	}
}

// Tests never run the real brew to resolve a name.
func init() {
	brewLocalInfo = func(string) (string, string, bool) { return "", "", false }
}

// Review 2026-11-04: a short name the API 404s as both formula and cask was
// waved through — a formula from an installed third-party tap (brew resolves
// "toolname" to evil/tap/toolname) skipped the tap refusal, and an alias
// skipped the disabled/deprecated lane and the server preflight.
func TestBrewPreflightResolvesViaLocalBrew(t *testing.T) {
	withIsolatedConfigHome(t)
	t.Setenv(guardAllowlistEnv, filepath.Join(t.TempDir(), "allow.json"))
	invalidateGuardAllowlistCache()
	t.Cleanup(invalidateGuardAllowlistCache)
	orig := brewLocalInfo
	brewLocalInfo = func(name string) (string, string, bool) {
		switch name {
		case "toolname":
			return "evil/tap/toolname", "evil/tap", true
		case "deadalias":
			return "dead", "homebrew/core", true
		case "jqalias":
			return "jq", "homebrew/core", true
		}
		return "", "", false
	}
	t.Cleanup(func() { brewLocalInfo = orig })
	api := fakeBrewAPI(t)
	specs := []packageSpec{
		{Ecosystem: "homebrew", Name: "toolname"},
		{Ecosystem: "homebrew", Name: "deadalias"},
		{Ecosystem: "homebrew", Name: "jqalias"},
		{Ecosystem: "homebrew", Name: "nosuch"},
	}
	out, verdicts, notices := brewPreflight(context.Background(), http.DefaultClient, api, specs)
	got := map[string]guardVerdict{}
	for _, v := range verdicts {
		got[v.Spec.Name] = v
	}
	if v, ok := got["evil/tap/toolname"]; !ok || !v.Block || v.Severity != guardSeverityHomebrewTap {
		t.Errorf("third-party tap via short name not refused: %+v", verdicts)
	}
	if v, ok := got["dead"]; !ok || !v.Block || v.Severity != guardSeverityHomebrewDisabled {
		t.Errorf("alias of a disabled formula not refused: %+v", verdicts)
	}
	if out[2].Name != "jq" || out[2].Version != "1.7.1_1" {
		t.Errorf("alias not resolved to the canonical formula: %+v", out[2])
	}
	if len(verdicts) != 2 || len(notices) != 1 || !strings.Contains(notices[0], "could not verify homebrew:nosuch") {
		t.Errorf("verdicts=%+v notices=%q", verdicts, notices)
	}
}

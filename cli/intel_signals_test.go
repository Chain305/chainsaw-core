package cli

// `chainsaw intel signals` used to go through newV1Client, so listing a
// static, compiled-in catalogue required a server URL AND a token. These
// tests pin the two halves of the fix: the local fallback exists, and it is
// never presented as though it came from the server.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/chain305/chainsaw-core/risk"
)

func newIntelSignalsTestCmd(t *testing.T) (*cobra.Command, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	out, errBuf := &bytes.Buffer{}, &bytes.Buffer{}
	c := &cobra.Command{Use: "signals", RunE: runIntelSignals}
	c.Flags().Bool("local", false, "")
	c.Flags().Bool("json", false, "")
	c.Flags().String("format", "", "")
	c.Flags().String("output", "", "")
	c.SetOut(out)
	c.SetErr(errBuf)
	return c, out, errBuf
}

// withNoServer blanks the server URL so newV1Client fails the way it does for
// a user who has never run `chainsaw setup`.
func withNoServer(t *testing.T) {
	t.Helper()
	prev := viper.GetString("server_url")
	viper.Set("server_url", "")
	t.Cleanup(func() { viper.Set("server_url", prev) })
}

// TestIntelSignals_NoServerPrintsLocalCatalogue is the headline behaviour: an
// unauthenticated user with no server configured gets the catalogue, exit 0.
func TestIntelSignals_NoServerPrintsLocalCatalogue(t *testing.T) {
	withNoServer(t)
	cmd, out, _ := newIntelSignalsTestCmd(t)

	if err := runIntelSignals(cmd, nil); err != nil {
		t.Fatalf("intel signals should succeed with no server; got %v", err)
	}
	body := out.String()
	if len(risk.AllSignals()) == 0 {
		t.Fatal("risk registry is empty — the CLI does not link core/risk")
	}
	for _, want := range []string{"sc.known_malicious", "vuln.kev"} {
		if !strings.Contains(body, want) {
			t.Errorf("catalogue is missing %q:\n%s", want, body)
		}
	}
}

// TestIntelSignals_LocalOutputIsLabelled: the local table must never read as
// if it came from the server. A policy author who cannot tell the two apart
// will reference an ID the server has never registered and find out at
// enforcement time.
func TestIntelSignals_LocalOutputIsLabelled(t *testing.T) {
	withNoServer(t)
	cmd, out, _ := newIntelSignalsTestCmd(t)

	if err := runIntelSignals(cmd, nil); err != nil {
		t.Fatalf("runIntelSignals: %v", err)
	}
	first := strings.SplitN(out.String(), "\n", 2)[0]
	if !strings.Contains(first, "LOCAL") {
		t.Errorf("first line does not label the source as local: %q", first)
	}
	if strings.Contains(first, "SERVER") {
		t.Errorf("local output claims to be the server catalogue: %q", first)
	}
}

// TestIntelSignals_JSONCarriesSource pins the machine-readable half of the
// label, and that the pre-existing envelope keys survive.
func TestIntelSignals_JSONCarriesSource(t *testing.T) {
	withNoServer(t)
	cmd, _, _ := newIntelSignalsTestCmd(t)
	if err := cmd.Flags().Set("json", "true"); err != nil {
		t.Fatalf("set --json: %v", err)
	}
	// PrintJSONTo writes to the RESULT sink (os.Stdout unless --output is
	// set), not to cmd.OutOrStdout — so capture via --output.
	dest := filepath.Join(t.TempDir(), "signals.json")
	if err := cmd.Flags().Set("output", dest); err != nil {
		t.Fatalf("set --output: %v", err)
	}
	if err := runIntelSignals(cmd, nil); err != nil {
		t.Fatalf("runIntelSignals: %v", err)
	}
	raw, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read --output file: %v", err)
	}

	var payload struct {
		Source        string            `json:"source"`
		EngineVersion string            `json:"engineVersion"`
		Warnings      []string          `json:"warnings"`
		Data          []v1SignalSummary `json:"data"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("decode --json output: %v\n%s", err, raw)
	}
	if payload.Source != "local" {
		t.Errorf(`source = %q, want "local"`, payload.Source)
	}
	if payload.EngineVersion != risk.EngineVersion {
		t.Errorf("engineVersion = %q, want %q", payload.EngineVersion, risk.EngineVersion)
	}
	if len(payload.Warnings) == 0 {
		t.Error("local JSON carries no warning about the source")
	}
	if len(payload.Data) != len(risk.AllSignals()) {
		t.Errorf("data has %d signals, registry has %d", len(payload.Data), len(risk.AllSignals()))
	}
}

// TestLocalSignals_MirrorsServerMapping: localSignals() must be the same
// field-for-field projection server.handleV1IntelSignals performs, or the two
// sources would differ for reasons that have nothing to do with version drift.
func TestLocalSignals_MirrorsServerMapping(t *testing.T) {
	got := localSignals()
	all := risk.AllSignals()
	if len(got) != len(all) {
		t.Fatalf("localSignals returned %d, registry has %d", len(got), len(all))
	}
	byID := make(map[string]v1SignalSummary, len(got))
	for _, s := range got {
		byID[s.ID] = s
	}
	for _, s := range all {
		g, ok := byID[s.ID]
		if !ok {
			t.Fatalf("signal %s missing from localSignals()", s.ID)
		}
		if g.Category != string(s.Category) || g.Severity != string(s.Severity) ||
			g.Weight != s.Weight || g.Title != s.Title || g.Description != s.Description {
			t.Errorf("signal %s was not mapped verbatim: %+v", s.ID, g)
		}
	}
}

// TestIntelSignals_LocalFlagSkipsAConfiguredServer: --local must not touch the
// network even when a server is configured. 127.0.0.1:9 (discard) would fail
// loudly if it did.
func TestIntelSignals_LocalFlagSkipsAConfiguredServer(t *testing.T) {
	prev := viper.GetString("server_url")
	viper.Set("server_url", "http://127.0.0.1:9")
	t.Cleanup(func() { viper.Set("server_url", prev) })
	t.Setenv("CHAINSAW_TOKEN", "not-a-real-token")

	cmd, out, _ := newIntelSignalsTestCmd(t)
	if err := cmd.Flags().Set("local", "true"); err != nil {
		t.Fatalf("set --local: %v", err)
	}
	if err := runIntelSignals(cmd, nil); err != nil {
		t.Fatalf("--local should never contact the server; got %v", err)
	}
	if !strings.Contains(out.String(), "LOCAL") {
		t.Errorf("--local output is not labelled local:\n%s", out.String())
	}
}

// TestDisplayPath_CollapsesHome guards the help-text/error-message path
// renderer. The collapse is what keeps the generating machine's username out
// of the published CLI reference.
func TestDisplayPath_CollapsesHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("displayPath deliberately leaves Windows paths absolute")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("no home directory")
	}
	if got := displayPath(filepath.Join(home, ".chainsaw", "config.yaml")); got != "~/.chainsaw/config.yaml" {
		t.Errorf("displayPath = %q, want ~/.chainsaw/config.yaml", got)
	}
	if got := displayPath("/etc/chainsaw/config.yaml"); got != "/etc/chainsaw/config.yaml" {
		t.Errorf("a path outside $HOME must be left alone; got %q", got)
	}
	if got := displayPath(""); got != "" {
		t.Errorf("displayPath(\"\") = %q, want empty", got)
	}
}

// TestConfigPathHelpTextIsResolved: the three help/error strings that used to
// hardcode ~/.chainsaw must now track platform.ConfigHome. Asserting against
// the resolver (rather than a literal) is the point — the test would have
// failed on Windows and Linux before the fix, exactly where users did.
func TestConfigPathHelpTextIsResolved(t *testing.T) {
	want := displayPath(configFilePath())
	if want == "" {
		t.Skip("no resolvable config home in this environment")
	}
	if !strings.Contains(setupCmd.Long, want) {
		t.Errorf("setup --help does not name the resolved config file %q:\n%s", want, setupCmd.Long)
	}
	if !strings.Contains(setupCmd.Long, displayPath(setupProgressPath())) {
		t.Errorf("setup --help does not name the resolved progress file:\n%s", setupCmd.Long)
	}
	if src := cargoCredsYAMLSource(); !strings.Contains(src, want) {
		t.Errorf("cargo credential source = %q, does not name the resolved config file", src)
	}
	for _, s := range []string{setupCmd.Long, guardAllowCmd.Long, cargoCredsYAMLSource()} {
		if runtime.GOOS != "darwin" && strings.Contains(s, "~/.chainsaw") {
			t.Errorf("a macOS-only path is hardcoded in user-facing text:\n%s", s)
		}
	}
}

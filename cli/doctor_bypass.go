package cli

// `chainsaw doctor --bypass-check` reads the user's local package-manager
// config files and reports any registry URL that points away from the
// configured Chainsaw server.
//
// Scope: this is a pure read of *config files* (the same posture as
// existing doctor checks). It does not parse user source code, scan
// repositories, or contact any registry. Missing config files are
// treated as "n/a" — no error, no scary output, just a status line.

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

// bypassFinding is one row in the bypass-check report.
type bypassFinding struct {
	Ecosystem  string `json:"ecosystem"`
	ConfigPath string `json:"config_path"`
	Status     string `json:"status"` // ok | drift | missing | error
	Configured string `json:"configured,omitempty"`
	Expected   string `json:"expected,omitempty"`
	Note       string `json:"note,omitempty"`
}

type bypassReport struct {
	ChainsawURL string          `json:"chainsaw_url"`
	Findings    []bypassFinding `json:"findings"`
}

func runDoctorBypassCheck(cmd *cobra.Command, _ []string) error {
	expected := strings.TrimSpace(cfgServerURL())
	if expected == "" {
		expected = strings.TrimSpace(os.Getenv("CHAINSAW_SERVER"))
	}

	rep := bypassReport{ChainsawURL: expected}

	rep.Findings = append(rep.Findings, checkNpmrc(expected))
	rep.Findings = append(rep.Findings, checkPipConf(expected))
	rep.Findings = append(rep.Findings, checkGemrc(expected))
	rep.Findings = append(rep.Findings, checkCargoConfig(expected))

	if useJSON(cmd) {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}

	printBypassReport(cmd.OutOrStdout(), rep)

	emit("cli.doctor.bypass_check", map[string]any{
		"chainsaw_url": expected,
		"findings":     len(rep.Findings),
	})
	return nil
}

func printBypassReport(w io.Writer, rep bypassReport) {
	if rep.ChainsawURL == "" {
		fmt.Fprintln(w, "warning: no Chainsaw server URL configured (run `chainsaw setup` or set CHAINSAW_SERVER); reporting raw values only")
		fmt.Fprintln(w)
	} else {
		fmt.Fprintf(w, "Comparing local config files against: %s\n\n", rep.ChainsawURL)
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ECOSYSTEM\tSTATUS\tCONFIG\tCONFIGURED")
	for _, f := range rep.Findings {
		configured := f.Configured
		if configured == "" {
			configured = "—"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", f.Ecosystem, f.Status, f.ConfigPath, configured)
	}
	tw.Flush()
	fmt.Fprintln(w)
	for _, f := range rep.Findings {
		if f.Status == "drift" {
			fmt.Fprintf(w, "drift in %s (%s):\n", f.Ecosystem, f.ConfigPath)
			fmt.Fprintf(w, "  configured: %s\n", f.Configured)
			fmt.Fprintf(w, "  expected:   %s\n", f.Expected)
			fmt.Fprintf(w, "  remediation: re-run `chainsaw install-hook %s` or update the file directly.\n\n", f.Ecosystem)
		}
	}
}

// driftCompare returns "ok" / "drift" given two URL-shaped strings.
// "Same" means same scheme + host + port. Path differences are ignored
// — chainsaw's npm proxy lives at /<repo>/, but the registry root is
// what npm cares about for routing.
func driftCompare(configured, expected string) string {
	if configured == "" {
		return "missing"
	}
	if expected == "" {
		// No reference URL; can't decide. Report informational only.
		return "ok"
	}
	c := normalizeURL(configured)
	e := normalizeURL(expected)
	if strings.HasPrefix(c, e) || strings.HasPrefix(e, c) {
		return "ok"
	}
	return "drift"
}

func normalizeURL(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimRight(s, "/")
	s = strings.ToLower(s)
	return s
}

// checkNpmrc reads ~/.npmrc and returns the registry= line.
func checkNpmrc(expected string) bypassFinding {
	home, err := os.UserHomeDir()
	if err != nil {
		return bypassFinding{Ecosystem: "npm", Status: "error", Note: err.Error()}
	}
	path := filepath.Join(home, ".npmrc")
	f := bypassFinding{Ecosystem: "npm", ConfigPath: path}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			f.Status = "n/a"
			f.Note = "no ~/.npmrc; npm will use its built-in default"
			return f
		}
		f.Status = "error"
		f.Note = err.Error()
		return f
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if strings.HasPrefix(line, "registry") {
			if i := strings.Index(line, "="); i >= 0 {
				f.Configured = strings.TrimSpace(line[i+1:])
				break
			}
		}
	}
	f.Expected = expected
	f.Status = driftCompare(f.Configured, expected)
	return f
}

// checkPipConf reads the user's pip.conf. Path varies by OS:
//   - macOS:   ~/Library/Application Support/pip/pip.conf  (also ~/.pip/pip.conf)
//   - Linux:   ~/.config/pip/pip.conf  (also ~/.pip/pip.conf)
//   - Windows: %APPDATA%/pip/pip.ini
//
// We try the modern path first, fall back to ~/.pip/pip.conf.
func checkPipConf(expected string) bypassFinding {
	home, _ := os.UserHomeDir()
	candidates := []string{}
	switch runtime.GOOS {
	case "darwin":
		candidates = append(candidates, filepath.Join(home, "Library", "Application Support", "pip", "pip.conf"))
	case "windows":
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			candidates = append(candidates, filepath.Join(appdata, "pip", "pip.ini"))
		}
	default:
		candidates = append(candidates, filepath.Join(home, ".config", "pip", "pip.conf"))
	}
	candidates = append(candidates, filepath.Join(home, ".pip", "pip.conf"))

	f := bypassFinding{Ecosystem: "pip"}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			f.ConfigPath = p
			data, err := os.ReadFile(p)
			if err != nil {
				f.Status = "error"
				f.Note = err.Error()
				return f
			}
			f.Configured = parsePipIndexURL(string(data))
			f.Expected = expected
			f.Status = driftCompare(f.Configured, expected)
			return f
		}
	}
	f.ConfigPath = candidates[0]
	f.Status = "n/a"
	f.Note = "no pip.conf found at any standard location"
	return f
}

// parsePipIndexURL returns the index-url value from a pip.conf body.
// The file is INI-style; we only care about [global] index-url.
func parsePipIndexURL(body string) string {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "index-url") || strings.HasPrefix(line, "index_url") {
			if i := strings.Index(line, "="); i >= 0 {
				return strings.TrimSpace(line[i+1:])
			}
		}
	}
	return ""
}

// checkGemrc reads ~/.gemrc.
func checkGemrc(expected string) bypassFinding {
	home, _ := os.UserHomeDir()
	path := filepath.Join(home, ".gemrc")
	f := bypassFinding{Ecosystem: "gem", ConfigPath: path}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			f.Status = "n/a"
			f.Note = "no ~/.gemrc; gem will use its built-in default"
			return f
		}
		f.Status = "error"
		f.Note = err.Error()
		return f
	}
	// .gemrc is YAML-ish; rather than pulling in a YAML parser, scan
	// for `:sources:` and grab the first list item — sufficient for the
	// drift signal.
	body := string(data)
	if i := strings.Index(body, ":sources:"); i >= 0 {
		tail := body[i:]
		for _, line := range strings.Split(tail, "\n")[1:] {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "-") {
				v := strings.TrimSpace(strings.TrimPrefix(line, "-"))
				v = strings.Trim(v, `"' `)
				f.Configured = v
				break
			}
			if line != "" && !strings.HasPrefix(line, "#") {
				break
			}
		}
	}
	f.Expected = expected
	f.Status = driftCompare(f.Configured, expected)
	return f
}

// checkCargoConfig reads ~/.cargo/config.toml (modern) or
// ~/.cargo/config (legacy). We extract any `replace-with` for the
// crates-io registry as well as the `index` URL of any custom
// registry — either is sufficient drift signal.
func checkCargoConfig(expected string) bypassFinding {
	home, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(home, ".cargo", "config.toml"),
		filepath.Join(home, ".cargo", "config"),
	}
	f := bypassFinding{Ecosystem: "cargo"}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			f.ConfigPath = p
			data, err := os.ReadFile(p)
			if err != nil {
				f.Status = "error"
				f.Note = err.Error()
				return f
			}
			body := string(data)
			f.Configured = parseCargoIndex(body)
			f.Expected = expected
			f.Status = driftCompare(f.Configured, expected)
			return f
		}
	}
	f.ConfigPath = candidates[0]
	f.Status = "n/a"
	f.Note = "no cargo config found at any standard location"
	return f
}

// parseCargoIndex returns the first `index = "..."` value found in the
// TOML body. Quick-and-dirty (no TOML lib): the [registries.x] block
// is what cargo reads for non-default registries; the value is on a
// dedicated line.
func parseCargoIndex(body string) string {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "index") {
			if i := strings.Index(line, "="); i >= 0 {
				v := strings.TrimSpace(line[i+1:])
				v = strings.Trim(v, `"' `)
				return v
			}
		}
	}
	return ""
}

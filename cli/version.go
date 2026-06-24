package cli

import (
	"encoding/json"
	"fmt"
	"runtime/debug"
	"sync"

	"github.com/spf13/cobra"
)

// Build-time variables set via -ldflags.
var (
	Version   = "dev"
	Commit    = "none"
	BuildDate = "unknown"
	// DefaultServer is the fallback server URL used when no --server flag,
	// CHAINSAW_SERVER_URL env var, or config-file value is set. Empty by
	// default so generic builds keep prompting; downstream builds bake
	// their server URL in via `-X .../internal/cli.DefaultServer=<url>`.
	DefaultServer = ""
)

// resolvedVersion holds the post-resolution view of Version/Commit/BuildDate
// after BUG-CLI-5's fallback to runtime/debug.ReadBuildInfo() runs. Computed
// once on first read so the JSON and human paths agree.
type resolvedVersion struct {
	Version  string // e.g. "dev" or "v1.2.3"
	Commit   string // git SHA, possibly "none"
	Built    string // RFC3339-ish or "unknown"
	AdHoc    bool   // true when the binary was built without -ldflags
	Modified bool   // true when VCS reports a dirty tree
}

var (
	versionOnce sync.Once
	versionInfo resolvedVersion
)

// resolveVersion fills in missing build metadata from runtime/debug.ReadBuildInfo
// when -ldflags weren't set. Go 1.18+ embeds the VCS commit, dirty bit, and
// build time into the binary, which is exactly what support tickets need from
// ad-hoc `go build` outputs. We never overwrite ldflags-injected values.
func resolveVersion() resolvedVersion {
	versionOnce.Do(func() {
		v := resolvedVersion{Version: Version, Commit: Commit, Built: BuildDate}
		// "dev" + "none" + "unknown" is the default Go binary signature.
		// Treat any of those defaults as an opportunity to enrich.
		needsCommit := v.Commit == "" || v.Commit == "none"
		needsBuilt := v.Built == "" || v.Built == "unknown"
		needsVersion := v.Version == "" || v.Version == "dev"

		if info, ok := debug.ReadBuildInfo(); ok {
			if needsVersion && info.Main.Version != "" && info.Main.Version != "(devel)" {
				v.Version = info.Main.Version
			}
			for _, s := range info.Settings {
				switch s.Key {
				case "vcs.revision":
					if needsCommit && s.Value != "" {
						v.Commit = s.Value
					}
				case "vcs.time":
					if needsBuilt && s.Value != "" {
						v.Built = s.Value
					}
				case "vcs.modified":
					if s.Value == "true" {
						v.Modified = true
					}
				}
			}
		}
		// Ad-hoc build: ldflags weren't set so Version was still the
		// hardcoded "dev" sentinel when we entered this function.
		v.AdHoc = needsVersion && (v.Version == "" || v.Version == "dev")
		if v.Version == "" {
			v.Version = "dev"
		}
		if v.Commit == "" {
			v.Commit = "none"
		}
		if v.Built == "" {
			v.Built = "unknown"
		}
		versionInfo = v
	})
	return versionInfo
}

func init() {
	rootCmd.AddCommand(&cobra.Command{
		Use:          "version",
		Short:        "Print version information",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			v := resolveVersion()
			if useJSON(cmd) {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{
					"version":    v.Version,
					"commit":     v.Commit,
					"build_date": v.Built,
					"ad_hoc":     v.AdHoc,
					"modified":   v.Modified,
				})
			}
			versionLine := "chainsaw version " + v.Version
			if v.AdHoc {
				versionLine += " (ad-hoc build)"
			}
			commitLine := "commit " + v.Commit
			if v.Modified {
				commitLine += " (modified)"
			}
			fmt.Fprintln(cmd.OutOrStdout(), versionLine)
			fmt.Fprintln(cmd.OutOrStdout(), commitLine)
			fmt.Fprintln(cmd.OutOrStdout(), "built "+v.Built)
			return nil
		},
	})
}

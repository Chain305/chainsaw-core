package cli

// `chainsaw guard update` — the ONLY networked part of the install guard, and
// only when you run it (D1-R: opt-in enrichment). Fetches the full OpenSSF
// malicious-packages dataset and writes a single local cache file that the
// guard merges on top of its built-in offline floor. After this, the guard's
// known-malicious coverage is the full set, still evaluated locally.

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chain305/chainsaw-core/malware"
	"github.com/spf13/cobra"
)

var guardCmd = &cobra.Command{
	Use:   "guard",
	Short: "Install-path guard maintenance",
}

var guardUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Fetch the full known-malicious set for offline use (opt-in; uses the network)",
	Long: `Download the OpenSSF malicious-packages dataset and write a local cache that
the install guard (chainsaw npm/pip/go) merges on top of its built-in offline
floor. This is the only part of the guard that touches the network, and only
when you run it. After updating, known-malicious coverage is the full set,
evaluated entirely on-box.`,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE:         runGuardUpdate,
}

func init() {
	guardCmd.AddCommand(guardUpdateCmd)
	rootCmd.AddCommand(guardCmd)
}

func runGuardUpdate(cmd *cobra.Command, _ []string) error {
	// The full malicious-packages feed is the only networked, account-gated part
	// of the guard. The built-in offline floor (bundled in the binary) is NOT
	// gated and keeps working with no account — only this enrichment pull does.
	if cfgToken() == "" {
		fmt.Fprintln(os.Stderr, "chainsaw: the full malicious-packages feed requires a free account.")
		fmt.Fprintln(os.Stderr, "  1. Sign up: https://chain305.com/chainsaw/signup")
		fmt.Fprintln(os.Stderr, "  2. chainsaw login")
		fmt.Fprintln(os.Stderr, "The built-in known-malicious floor stays active offline in the meantime.")
		return fmt.Errorf("not signed in: the full malicious-packages feed requires a free account")
	}

	dst := guardDBPath()
	if dst == "" {
		return fmt.Errorf("cannot determine cache path; set %s to a writable file path", guardDBEnv)
	}

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	syncDir, err := os.MkdirTemp("", "chainsaw-malware-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(syncDir)

	fmt.Fprintln(os.Stderr, "chainsaw: fetching the OpenSSF malicious-packages dataset…")
	idx := malware.NewIndex(guardLogger)
	syncer := malware.NewSyncer(idx, syncDir, guardLogger)
	if err := syncer.Sync(ctx); err != nil {
		return fmt.Errorf("fetch failed: %w", err)
	}

	entries := collectOSVEntries(filepath.Join(syncDir, "malicious-packages", "active", "osv", "malicious"))
	if len(entries) == 0 {
		return fmt.Errorf("dataset fetch produced no entries (layout change?)")
	}

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	data, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "chainsaw: wrote %d known-malicious entries to %s\n", len(entries), dst)
	fmt.Fprintln(os.Stderr, "chainsaw: the guard will now use the full set offline.")
	return nil
}

// collectOSVEntries walks a directory of OSV JSON files (the OpenSSF dataset
// layout) and parses each into an entry. Skips unreadable/unparseable files.
func collectOSVEntries(dir string) []*malware.OSVEntry {
	var entries []*malware.OSVEntry
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		if data, rerr := os.ReadFile(path); rerr == nil {
			if e, perr := malware.ParseOSVEntry(data); perr == nil {
				entries = append(entries, e)
			}
		}
		return nil
	})
	return entries
}

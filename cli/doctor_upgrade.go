package cli

// doctor --upgrade-check: server-install diagnostics that run locally
// against the same environment chainsaw-proxy would see on boot. The
// heavy lifting lives in internal/doctor; this file is the CLI glue
// (flag wiring, output formatting, --fix application).
//
// Exit-code contract (matches the `chainsaw doctor --upgrade-check`
// docstring and the acceptance bar in the wave plan):
//
//	0 = all green, safe to upgrade
//	1 = warnings; review MIGRATIONS.md before cutting over
//	2 = breaking changes present; DO NOT upgrade yet

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/doctor"
	"github.com/chain305/chainsaw-core/pgstore"
)

// pgstoreDBProber adapts a *pgstore.Store to doctor.DBProber.
// Translates pgstore.ErrNoSchemaVersion into doctor.ErrFreshDatabase
// so the doctor layer stays free of pgstore imports.
type pgstoreDBProber struct{ store *pgstore.Store }

func (p pgstoreDBProber) Ping(ctx context.Context) error {
	if p.store == nil || p.store.DB() == nil {
		return fmt.Errorf("pgstore not initialized")
	}
	return p.store.DB().PingContext(ctx)
}

func (p pgstoreDBProber) SchemaVersion(ctx context.Context) (string, error) {
	v, err := p.store.SchemaVersion(ctx)
	if err != nil {
		if errors.Is(err, pgstore.ErrNoSchemaVersion) {
			return "", doctor.ErrFreshDatabase
		}
		return "", err
	}
	return v, nil
}

// openDBProberForDoctor is the factory used by runDoctorUpgradeCheck.
// Returns (nil, nil) with no DSN: the caller interprets this as
// "leave DBProber unset", and doctor.checkDatabase emits the
// "skipping schema-version check" finding.
//
// Kept as a var so tests can stub out the pgstore dial without
// standing up a real Postgres.
var openDBProberForDoctor = func(dsn string) (doctor.DBProber, func(), error) {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		return nil, func() {}, nil
	}
	store, err := pgstore.Open(dsn)
	if err != nil {
		return nil, func() {}, err
	}
	return pgstoreDBProber{store: store}, func() { _ = store.Close() }, nil
}

// runDoctorUpgradeCheck is the RunE target when --upgrade-check or
// --fix is set. It composes doctor.Options from the command flags,
// invokes doctor.Run, renders the scorecard, applies fixes (when
// asked), then exits with the documented code. Because it calls
// os.Exit, tests substitute doctorExitOverride to observe the code
// without actually exiting.
var doctorExitOverride func(int)

// doctorPortsOverride lets tests inject the TCP port list for the
// bindability check so the all-green path doesn't depend on the conventional
// proxy ports (8787/8080/8443) being free on a dev machine. nil in
// production, where checkPorts falls back to doctor.DefaultServerPorts.
var doctorPortsOverride []int

func runDoctorUpgradeCheck(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	configPath, _ := cmd.Flags().GetString("config")
	dataDir, _ := cmd.Flags().GetString("data-dir")
	composePath, _ := cmd.Flags().GetString("docker-compose-path")
	skipNetwork, _ := cmd.Flags().GetBool("skip-network")
	fix, _ := cmd.Flags().GetBool("fix")

	// Wire a pgstore-backed DBProber when a DSN is configured and
	// --skip-network is not set. Doctor tolerates a nil prober (emits
	// a soft "deferred" finding), so a Postgres that refuses connect
	// will surface as a Breaking finding via the prober's Ping call
	// rather than blocking the rest of the report from printing.
	var dbProber doctor.DBProber
	var dbProberClose func() = func() {}
	if !skipNetwork {
		if dsn := strings.TrimSpace(os.Getenv("CHAINSAW_DATABASE_URL")); dsn != "" {
			p, closer, err := openDBProberForDoctor(dsn)
			if err != nil {
				// Surface the dial failure as a soft finding via
				// the doctor's database check rather than aborting:
				// we still want port / TLS / config findings to
				// render so the operator can fix everything in one
				// pass.
				fmt.Fprintf(cmd.ErrOrStderr(), "note: database probe disabled (%v)\n", err)
			} else {
				dbProber = p
				dbProberClose = closer
			}
		}
	}
	defer dbProberClose()

	runOpts := doctor.Options{
		Version:               Version,
		ConfigPath:            configPath,
		DataDir:               dataDir,
		DockerComposePath:     composePath,
		SkipNetwork:           skipNetwork,
		DBProber:              dbProber,
		ExpectedSchemaVersion: pgstore.CurrentSchemaVersion,
		PortsToCheck:          doctorPortsOverride,
	}
	report := doctor.Run(ctx, runOpts)

	if fix {
		applied := applyAutoFixes(cmd.OutOrStdout(), report.Findings, dataDir)
		if applied > 0 {
			// Re-run to refresh findings after fixes land.
			report = doctor.Run(ctx, runOpts)
		}
	}

	if useJSON(cmd) {
		_ = writeJSON(cmd, report)
	} else {
		printUpgradeReport(cmd, report)
	}

	exit := report.ExitCode()
	emit("cli.doctor.upgrade_check", map[string]any{
		"exit_code":      exit,
		"total_findings": len(report.Findings),
		"fix_requested":  fix,
	})

	if exit != 0 {
		if doctorExitOverride != nil {
			doctorExitOverride(exit)
			return nil
		}
		os.Exit(exit)
	}
	return nil
}

// printUpgradeReport renders the scorecard in a one-line-per-check
// format with ✓ / ⚠ / ✗ markers and a summary footer. Kept separate
// from the JSON path so --json stays machine-stable.
func printUpgradeReport(cmd *cobra.Command, r *doctor.Report) {
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "chainsaw doctor --upgrade-check\n")
	fmt.Fprintf(out, "  version : %s\n", r.Version)
	fmt.Fprintf(out, "  platform: %s\n\n", r.Platform)

	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "STATUS\tCHECK\tMESSAGE")
	for _, f := range r.Findings {
		mark := f.Severity.Mark()
		fmt.Fprintf(w, "%s\t%s\t%s\n", mark, f.Check, f.Message)
	}
	w.Flush()

	var warns, breakings int
	for _, f := range r.Findings {
		switch f.Severity {
		case doctor.SeverityWarn:
			warns++
		case doctor.SeverityBreaking:
			breakings++
		}
	}

	// Remediation footer: only show rows that have a remediation, and
	// only for non-OK severities. Keeps the primary table scannable.
	var remediations []doctor.Finding
	for _, f := range r.Findings {
		if f.Severity != doctor.SeverityOK && strings.TrimSpace(f.Remediation) != "" {
			remediations = append(remediations, f)
		}
	}
	if len(remediations) > 0 {
		fmt.Fprintln(out, "\nremediations:")
		for _, f := range remediations {
			fmt.Fprintf(out, "  [%s] %s\n      %s\n", f.Check, f.SeverityName, f.Remediation)
		}
	}

	fmt.Fprintf(out, "\nsummary: %d ok, %d warn, %d breaking\n",
		len(r.Findings)-warns-breakings, warns, breakings)
	switch r.Worst() {
	case doctor.SeverityBreaking:
		fmt.Fprintln(out, "verdict: DO NOT UPGRADE — resolve breaking findings first. See MIGRATIONS.md.")
	case doctor.SeverityWarn:
		fmt.Fprintln(out, "verdict: upgrade possible; review warnings and MIGRATIONS.md before cutover.")
	default:
		fmt.Fprintln(out, "verdict: safe to upgrade.")
	}
}

// applyAutoFixes walks the report and applies the fixes we know how
// to make safely. Returns the number of fixes applied so the caller
// can decide whether to re-run the diagnostics.
func applyAutoFixes(out io.Writer, findings []doctor.Finding, dataDir string) int {
	applied := 0
	dir := strings.TrimSpace(dataDir)
	if dir == "" {
		dir = strings.TrimSpace(os.Getenv("CHAINSAW_DATA_DIR"))
	}
	if dir == "" {
		dir = "/etc/chainsaw/data"
	}

	// Generate a JWT secret if the finding surfaces an absent
	// CHAINSAW_JWT_SECRET pinning. The same helper
	// (cmd/chainsaw-proxy/init_jwt_secret.go) handles first-boot in
	// the server — here we replicate the minimal subset so `doctor
	// --fix` can seed the file before the first `chainsaw-proxy` run.
	for _, f := range findings {
		if f.Check != "env-flip:CHAINSAW_STRICT_JWT" {
			continue
		}
		secretPath := filepath.Join(dir, "generated_jwt_secret")
		if _, err := os.Stat(secretPath); err == nil {
			continue // already exists; first-boot will adopt it
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			fmt.Fprintf(out, "fix: could not create %s: %v\n", dir, err)
			continue
		}
		secret, err := mintDoctorJWTSecret()
		if err != nil {
			fmt.Fprintf(out, "fix: could not mint JWT secret: %v\n", err)
			continue
		}
		if err := os.WriteFile(secretPath, []byte(secret+"\n"), 0o400); err != nil {
			fmt.Fprintf(out, "fix: could not write %s: %v\n", secretPath, err)
			continue
		}
		fmt.Fprintf(out, "fix: wrote generated_jwt_secret (0400) at %s\n", secretPath)
		applied++
	}

	// Chmod stale secret files to 0400.
	for _, f := range findings {
		if !f.AutoFixable {
			continue
		}
		if !strings.HasPrefix(f.Check, "data-dir:") {
			continue
		}
		name := strings.TrimPrefix(f.Check, "data-dir:")
		p := filepath.Join(dir, name)
		if err := os.Chmod(p, 0o400); err != nil {
			fmt.Fprintf(out, "fix: chmod 0400 %s failed: %v\n", p, err)
			continue
		}
		fmt.Fprintf(out, "fix: chmod 0400 %s\n", p)
		applied++
	}
	return applied
}

// mintDoctorJWTSecret mirrors cmd/chainsaw-proxy/init_jwt_secret.go's
// mintJWTSecret — 32 random bytes, base64-url encoded, no padding.
// We inline it here because init_jwt_secret.go is in package `main`
// (the proxy binary) and can't be imported. If the shared helper
// eventually moves into internal/, swap this one-liner for the import.
func mintDoctorJWTSecret() (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

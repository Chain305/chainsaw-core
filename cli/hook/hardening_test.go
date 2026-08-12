package hook

// Focused coverage for the fixes that are not naturally expressed as a
// per-manager table: the refusal paths (H1, H6, H9, H12), the org-slug and
// credential validation (H4), backup pruning (H13) and staleness (H11).

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// H12 — a rejected --server must not produce a file
// ---------------------------------------------------------------------------

func TestNugetRejectsBadServerAndWritesNothing(t *testing.T) {
	sandboxHome(t)
	m := nugetManager{}
	opts := testWireOpts()
	opts.ServerURL = `https://host/a"b`
	err := m.Wire(opts)
	if err == nil {
		t.Fatal("Wire accepted an invalid server URL")
	}
	if !strings.Contains(err.Error(), "invalid server URL") {
		t.Errorf("error does not explain the rejection: %v", err)
	}
	path, _ := m.ConfigPathForScope(ScopeUser)
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		data, _ := os.ReadFile(path)
		t.Fatalf("Wire wrote %s despite rejecting the server URL:\n%s", path, data)
	}
}

func TestNugetPlaceholderOnlyWhenNoServerConfigured(t *testing.T) {
	sandboxHome(t)
	m := nugetManager{}
	opts := testWireOpts()
	opts.ServerURL = ""
	if err := m.Wire(opts); err != nil {
		t.Fatalf("Wire without a server: %v", err)
	}
	path, _ := m.ConfigPathForScope(ScopeUser)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "your-chainsaw-server") {
		t.Errorf("expected the visible placeholder host so the config fails loud:\n%s", data)
	}
}

// ---------------------------------------------------------------------------
// H1 — the refusal must be actionable
// ---------------------------------------------------------------------------

func TestXMLRefusalPrintsMergeableFragment(t *testing.T) {
	for _, tc := range []struct {
		manager Manager
		seed    string
		want    []string
	}{
		{
			mavenManager{},
			"<?xml version=\"1.0\"?>\n<settings/>\n",
			[]string{"<mirrorOf>*</mirrorOf>", "chainproxy/repository/@acme-corp/maven-central", "<id>chainsaw-maven</id>"},
		},
		{
			nugetManager{},
			"<?xml version=\"1.0\"?>\n<configuration/>\n",
			[]string{`<add key="Chainsaw"`, "chainproxy/repository/@acme-corp/nuget-official"},
		},
	} {
		t.Run(tc.manager.Name(), func(t *testing.T) {
			sandboxHome(t)
			path, _ := tc.manager.ConfigPathForScope(ScopeUser)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(tc.seed), 0o644); err != nil {
				t.Fatal(err)
			}
			err := tc.manager.Wire(testWireOpts())
			if err == nil {
				t.Fatal("Wire did not refuse an existing foreign config")
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("refusal is not actionable — missing %q:\n%v", want, err)
				}
			}
		})
	}
}

// TestMavenRewritesItsOwnStandaloneFile is H1's one exception: a file chainsaw
// wrote is re-rendered so re-install stays idempotent.
func TestMavenRewritesItsOwnStandaloneFile(t *testing.T) {
	sandboxHome(t)
	m := mavenManager{}
	opts := testWireOpts()
	if err := m.Wire(opts); err != nil {
		t.Fatalf("first Wire: %v", err)
	}
	opts.OrgSlug = "other-org"
	if err := m.Wire(opts); err != nil {
		t.Fatalf("re-Wire of our own file: %v", err)
	}
	path, _ := m.ConfigPathForScope(ScopeUser)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "@other-org/") {
		t.Errorf("re-Wire did not refresh the org slug:\n%s", data)
	}
	if strings.Contains(string(data), "@acme-corp/") {
		t.Errorf("re-Wire left the previous org slug behind:\n%s", data)
	}
}

// ---------------------------------------------------------------------------
// H9 — refuse a malformed block, repair only on request
// ---------------------------------------------------------------------------

func TestWireRefusesMalformedSentinelInsteadOfStacking(t *testing.T) {
	sandboxHome(t)
	m := npmManager{}
	path, _ := m.ConfigPathForScope(ScopeUser)
	// The reported repro: a user deletes the end marker while debugging.
	seed := "save-exact=true\n\n" + sentinelStart + "\nregistry=https://old/\n"
	if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		err := m.Wire(testWireOpts())
		if err == nil {
			t.Fatalf("Wire %d accepted a malformed block", i+1)
		}
		if !strings.Contains(err.Error(), "--repair") {
			t.Errorf("refusal does not point at the repair path: %v", err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != seed {
		t.Fatalf("refused Wire still modified the file:\n%s", data)
	}
	if n := strings.Count(string(data), sentinelBodyStart); n != 1 {
		t.Fatalf("file accumulated %d start markers; it must not grow", n)
	}
}

func TestRepairDeletesOnlyThePreviewedLines(t *testing.T) {
	sandboxHome(t)
	m := npmManager{}
	path, _ := m.ConfigPathForScope(ScopeUser)
	seed := "save-exact=true\n" + sentinelStart + "\nregistry=https://old/\nignore-scripts=true\n"
	if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	plans, err := PlanRepair(m, ScopeUser)
	if err != nil {
		t.Fatalf("PlanRepair: %v", err)
	}
	if len(plans) != 1 {
		t.Fatalf("expected one plan, got %d", len(plans))
	}
	// The unterminated block runs to EOF; the user's first line is safe.
	if got := len(plans[0].Lines); got != 3 {
		t.Fatalf("plan covers %d lines, want 3: %+v", got, plans[0].Lines)
	}
	if plans[0].Lines[0].Number != 2 || plans[0].Lines[0].Text != sentinelStart {
		t.Fatalf("plan does not start at the marker: %+v", plans[0].Lines[0])
	}
	if err := ApplyRepair(m, ScopeUser, plans); err != nil {
		t.Fatalf("ApplyRepair: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(data)) != "save-exact=true" {
		t.Fatalf("repair did not leave exactly the user's content:\n%q", data)
	}
	// And the manager is wireable again.
	if err := m.Wire(testWireOpts()); err != nil {
		t.Fatalf("Wire after repair: %v", err)
	}
}

func TestRepairRefusesWhenTheFileChangedSinceThePreview(t *testing.T) {
	sandboxHome(t)
	m := npmManager{}
	path, _ := m.ConfigPathForScope(ScopeUser)
	if err := os.WriteFile(path, []byte("a=1\n"+sentinelStart+"\nb=2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plans, err := PlanRepair(m, ScopeUser)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("a=1\nc=3\n"+sentinelStart+"\nb=2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ApplyRepair(m, ScopeUser, plans); err == nil {
		t.Fatal("ApplyRepair deleted lines the user never saw previewed")
	}
}

func TestRepairIsANoOpOnAHealthyConfig(t *testing.T) {
	sandboxHome(t)
	m := npmManager{}
	if err := m.Wire(testWireOpts()); err != nil {
		t.Fatal(err)
	}
	if _, err := PlanRepair(m, ScopeUser); !errors.Is(err, ErrNothingToRepair) {
		t.Fatalf("PlanRepair on a healthy config = %v, want ErrNothingToRepair", err)
	}
}

func TestRepairUnsupportedForWholeDocumentManagers(t *testing.T) {
	for _, m := range []Manager{mavenManager{}, nugetManager{}, dockerManager{}} {
		if _, err := PlanRepair(m, ScopeUser); !errors.Is(err, ErrRepairUnsupported) {
			t.Errorf("PlanRepair(%s) = %v, want ErrRepairUnsupported", m.Name(), err)
		}
	}
}

func TestSentinelCorruptClassification(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"empty", "", false},
		{"no markers", "a=1\n", false},
		{"well formed", sentinelStart + "\na=1\n" + sentinelEnd + "\n", false},
		{"start only", "a=1\n" + sentinelStart + "\nb=2\n", true},
		{"end only", "a=1\n" + sentinelEnd + "\n", true},
		{"two starts", sentinelStart + "\n" + sentinelStart + "\n" + sentinelEnd + "\n", true},
		{"two complete blocks", sentinelStart + "\n" + sentinelEnd + "\n" + sentinelStart + "\n" + sentinelEnd + "\n", true},
		{"marker inside a user comment", "# see \"" + sentinelStart + "\" in the docs\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := sentinelCorrupt([]byte(tc.in), hashMarker)
			if got != tc.want {
				t.Fatalf("sentinelCorrupt = %v (%q), want %v", got, reason, tc.want)
			}
			if got && reason == "" {
				t.Error("corrupt result carries no reason")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// H4 — org slug and credential validation
// ---------------------------------------------------------------------------

func TestOrgSlugValidation(t *testing.T) {
	good := []string{"acme", "acme-corp", "a", "a1-b2", strings.Repeat("a", 63)}
	for _, slug := range good {
		if _, err := orgScopedRepoPath(slug, "npmjs"); err != nil {
			t.Errorf("orgScopedRepoPath(%q) rejected a valid slug: %v", slug, err)
		}
	}
	bad := []string{
		"acme/\n# <<< chainsaw-managed <<<\nregistry=https://evil.example/",
		`acme"); System.exit(1); uri("x`,
		"-leading-hyphen",
		"has space",
		"has/slash",
		"a&b",
		strings.Repeat("a", 64),
		"UPPER-ONLY-IS-FINE-BUT-THIS-HAS-A-DOT.",
	}
	for _, slug := range bad {
		if got, err := orgScopedRepoPath(slug, "npmjs"); err == nil {
			t.Errorf("orgScopedRepoPath(%q) accepted a hostile slug, producing %q", slug, got)
		}
	}
	// Case is normalised rather than rejected.
	got, err := orgScopedRepoPath("Acme-Corp", "npmjs")
	if err != nil {
		t.Fatalf("mixed-case slug rejected: %v", err)
	}
	if !strings.Contains(got, "@acme-corp/") {
		t.Errorf("slug was not lower-cased: %q", got)
	}
	// Empty falls back to the visible placeholder, which must itself be valid.
	got, err = orgScopedRepoPath("", "npmjs")
	if err != nil || !strings.Contains(got, placeholderOrgSlug) {
		t.Errorf("empty slug = (%q, %v), want the placeholder", got, err)
	}
}

func TestHostileOrgSlugFailsEveryWire(t *testing.T) {
	hostile := "acme/\n# <<< chainsaw-managed <<<\nregistry=https://evil.example/"
	for _, m := range All() {
		t.Run(m.Name(), func(t *testing.T) {
			sandboxHome(t)
			opts := testWireOpts()
			opts.OrgSlug = hostile
			err := m.Wire(opts)
			if m.Name() == "docker" {
				// docker deliberately does not use an org-scoped path —
				// `docker login` takes a bare host and the proxy mounts the
				// registry under a different routing rule (see orgpath.go).
				// The slug must therefore never reach the file at all.
				if err != nil {
					t.Fatalf("docker Wire failed on a slug it does not use: %v", err)
				}
				for _, p := range managerPaths(t, m, ScopeUser) {
					data, _ := os.ReadFile(p)
					if strings.Contains(string(data), "evil.example") {
						t.Fatalf("the org slug reached %s:\n%s", p, data)
					}
				}
				return
			}
			if err == nil {
				t.Fatal("Wire accepted an org slug carrying a sentinel marker and a registry override")
			}
			for _, p := range managerPaths(t, m, ScopeUser) {
				if _, statErr := os.Stat(p); statErr == nil {
					data, _ := os.ReadFile(p)
					t.Fatalf("Wire wrote %s despite the hostile slug:\n%s", p, data)
				}
			}
		})
	}
}

func TestParseCredsRejectsDangerousHalves(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		ok   bool
	}{
		{"normal", "cli-abc:s3cr3t", true},
		{"base64url secret", "cli-abc:aB3-_xYz", true},
		{"shell metacharacters are allowed and escaped downstream", "cli-abc:a;b$c", true},
		{"no colon", "cli-abc", false},
		{"empty id", ":secret", false},
		{"empty secret", "cli-abc:", false},
		{"newline in secret", "cli-abc:a\nregistry=https://evil/", false},
		{"double quote in secret", `cli-abc:a"b`, false},
		{"backslash in secret", `cli-abc:a\b`, false},
		{"sentinel end marker in secret", "cli-abc:x " + sentinelEnd, false},
		{"control char in id", "cli\x00abc:secret", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := parseCreds(tc.raw)
			if tc.ok && err != nil {
				t.Fatalf("parseCreds(%q) = %v, want success", tc.raw, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("parseCreds(%q) succeeded, want a refusal", tc.raw)
			}
		})
	}
}

func TestKotlinEscape(t *testing.T) {
	cases := map[string]string{
		`plain`:               `plain`,
		`a"b`:                 `a\"b`,
		`a\b`:                 `a\\b`,
		`${evil}`:             `\${evil}`,
		"a\nb":                `a\nb`,
		`x"); System.exit(1)`: `x\"); System.exit(1)`,
	}
	for in, want := range cases {
		if got := kotlinEscape(in); got != want {
			t.Errorf("kotlinEscape(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestShellSingleQuote(t *testing.T) {
	cases := map[string]string{
		`plain`:     `'plain'`,
		`a;b`:       `'a;b'`,
		"a$b":       `'a$b'`,
		"a`b`":      "'a`b`'",
		`a'b`:       `'a'\''b'`,
		`'; rm -rf`: `''\''; rm -rf'`,
	}
	for in, want := range cases {
		if got := shellSingleQuote(in); got != want {
			t.Errorf("shellSingleQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// H13 — backups are pruned but the newest survives
// ---------------------------------------------------------------------------

func TestBackupsArePrunedKeepingTheNewest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".npmrc")
	base := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	calls := 0
	old := timeNow
	timeNow = func() time.Time {
		t := base.Add(time.Duration(calls) * time.Second)
		calls++
		return t
	}
	t.Cleanup(func() { timeNow = old })

	var last string
	for i := 0; i < 6; i++ {
		if err := os.WriteFile(path, []byte("gen="+string(rune('0'+i))+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		dst, err := backup(path)
		if err != nil {
			t.Fatal(err)
		}
		last = dst
	}
	matches, err := filepath.Glob(path + ".chainsaw.bak.*")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != backupsKept {
		t.Fatalf("kept %d backups, want %d: %v", len(matches), backupsKept, matches)
	}
	// The newest must survive: it is xmlUnwire's restore source and the only
	// copy of a user's original GOFLAGS.
	if _, err := os.Stat(last); err != nil {
		t.Fatalf("pruning removed the newest backup %s: %v", last, err)
	}
}

func TestWireReportsTheBackupPath(t *testing.T) {
	sandboxHome(t)
	m := npmManager{}
	path, _ := m.ConfigPathForScope(ScopeUser)
	if err := os.WriteFile(path, []byte("save-exact=true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var notes []string
	opts := testWireOpts()
	opts.Notify = func(msg string) { notes = append(notes, msg) }
	if err := m.Wire(opts); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range notes {
		if strings.Contains(n, "backed up") && strings.Contains(n, ".chainsaw.bak.") {
			found = true
		}
	}
	if !found {
		t.Errorf("Wire wrote a backup without telling the user where; notes = %v", notes)
	}
}

// ---------------------------------------------------------------------------
// H11 — staleness
// ---------------------------------------------------------------------------

func TestStatusForDetectsAnExternallyRewrittenBlock(t *testing.T) {
	sandboxHome(t)
	m := goModManager{}
	opts := testWireOpts()
	if err := m.Wire(opts); err != nil {
		t.Fatal(err)
	}
	st, err := StatusFor(m, opts)
	if err != nil {
		t.Fatal(err)
	}
	if st.Stale {
		t.Fatalf("a freshly wired config reports stale: %s", st.StaleReason)
	}

	// The documented repro: `go env -w GOPROXY=...` rewrites the line INSIDE
	// our block, so marker presence still says "wired" while every module
	// fetch bypasses the proxy.
	path, _ := m.ConfigPathForScope(ScopeUser)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, ln := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "GOPROXY=") {
			ln = "GOPROXY=https://proxy.golang.org"
		}
		out = append(out, ln)
	}
	if err := os.WriteFile(path, []byte(strings.Join(out, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}

	st, err = StatusFor(m, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Wired {
		t.Fatal("Status lost the block")
	}
	if !st.Stale {
		t.Fatal("StatusFor did not flag a block whose GOPROXY was rewritten out from under it")
	}
}

func TestStatusForFlagsAnOldOrgSlug(t *testing.T) {
	sandboxHome(t)
	m := npmManager{}
	opts := testWireOpts()
	if err := m.Wire(opts); err != nil {
		t.Fatal(err)
	}
	opts.OrgSlug = "new-org"
	st, err := StatusFor(m, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Stale {
		t.Fatal("StatusFor did not flag a block carrying the previous org slug")
	}
}

func TestStatusForIsQuietForWholeDocumentManagers(t *testing.T) {
	for _, m := range []Manager{mavenManager{}, nugetManager{}, dockerManager{}} {
		t.Run(m.Name(), func(t *testing.T) {
			sandboxHome(t)
			opts := testWireOpts()
			if err := m.Wire(opts); err != nil {
				t.Fatal(err)
			}
			st, err := StatusFor(m, opts)
			if err != nil {
				t.Fatal(err)
			}
			if st.Stale {
				t.Errorf("%s claims staleness it cannot actually determine", m.Name())
			}
		})
	}
}

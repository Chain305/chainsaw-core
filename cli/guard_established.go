package cli

// guard_established.go — the ESTABLISHED TABLE: the offline guard's copy of
// the established-package clear.
//
// ─── THE DEFECT THIS CLOSES ──────────────────────────────────────────────────
//
// The server path has cleared established packages since v0.22.73–78
// (core/intelligence/typosquat_established.go: >=100k weekly downloads, or
// >=50 versions over two years, or the long-lived line). The guard — the
// OFFLINE install-time path — never got those clears: it consults only name
// similarity, so it blocked ESTABLISHED packages as typosquats. Measured on
// a real 10,428-name inventory: 28 false blocks, including pug, jsdoc and
// uglify-es. Every one of those is a refusal on the install path, the most
// expensive false positive this product has.
//
// The fix is data, not another heuristic: a per-ecosystem ESTABLISHED TABLE
// of registry-wide qualification rows (weekly downloads, version count,
// first/last publish dates), embedded at build time and consulted BEFORE the
// typosquat lane can set a verdict. A row that clears through
// risk.EstablishedClear — the SAME single definition the server path calls —
// caps the name-similarity lane at a WARNING, and is silent only when the
// install pins an exact version the table saw at build time (see THE VERSION
// GATE below). The table is qualification data,
// NOT a popularity corpus: membership does not exempt a package from
// anything else, and confers no exact-match privileges (unlike the popular
// corpus, being in this table clears nothing by itself — a row only clears
// when the qualification LINES fire).
//
// ─── THE VERSION GATE (2026-10-21) ───────────────────────────────────────────
//
// The clear used to skip the lane for ANY version, including one published
// after the table was built: a dormant lookalike that qualified years ago and
// then ships a malicious release was cleared on its history alone. A clear now
// lowers a block to a printed warning naming the lookalike target. It is
// silent only when the request is an exact pin inside the row's build-time
// release set (establishedPinnedRelease). A version check alone could not
// close this: `npm install jsonp` and `faiss-gpu>=1` reach the guard with no
// version at all, so "no version" must warn rather than clear.
//
// ─── WHAT THE CLEAR DOES NOT CLEAR ──────────────────────────────────────────
//
// Byte-level evidence is above data clears. The homoglyph arm of evaluate()
// (guard_eval.go) returns BEFORE this lookup: an established row for a
// confusable name must never clear a homoglyph block, and the same ordering
// keeps known-malicious and known-vulnerable (which return even earlier)
// untouched. The clear skips ONLY the typosquat lane and falls through — an
// established package with malicious staged bytes still blocks on the
// behavioral scan, and policy still runs.
//
// ─── LOADING ────────────────────────────────────────────────────────────────
//
// Embedded TSVs (seeds/established_*.tsv), parsed ONCE per process. No
// per-spec I/O, no network — ever. A Sigstore-verified bundle channel for
// between-releases refresh is a deliberate FOLLOW-UP and is not implemented
// here; embedded-only is this ship.
//
// The format (one row per package, '#' header lines skipped):
//
//	name<TAB>weekly_downloads(int)<TAB>version_count(int)<TAB>first_published(YYYY-MM-DD or empty)<TAB>last_published(YYYY-MM-DD or empty)[<TAB>releases(comma-separated)]
//
// The optional sixth column is the set of versions that existed at build
// time (risk.EstablishedRow.Releases). The generator writes it only for rows
// the typosquat detector can flag — every other row never reaches the clear.
// A five-column row (an older table) parses with no release set, which is
// the safe reading: its clear can only ever WARN, never go silent.
//
// Empty date fields mean unknown; unknown dates fail the lines that need
// them (see risk.EstablishedRow). Malformed rows are skipped LOUDLY — a
// silently missing row silently re-blocks an established package, which is
// the exact defect this file exists to close.

import (
	"bufio"
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chain305/chainsaw-core/risk"
	"github.com/chain305/chainsaw-core/typosquat"
)

// establishedSeedFS holds the embedded per-ecosystem tables. The glob always
// has at least one match — seeds/established_placeholder.tsv, a comment-only
// build-support file — because go:embed fails the BUILD on an empty pattern
// match, and the guard must compile before the generated tables land.
//
//go:embed seeds/established_*.tsv
var establishedSeedFS embed.FS

// guardEstablishedClears counts typosquat lanes skipped because the candidate
// cleared the established table, since process start. The per-process reader
// is GuardEstablishedClearsCount (tests, symmetry with
// GuardAnalysisIncompleteCount); the OPERATOR-facing surface is the persisted
// counter `guard status` reports (see processGuardOutcome), because a guard
// install and a `guard status` run are different processes.
var guardEstablishedClears atomic.Uint64

// GuardEstablishedClearsCount reports established-table clears since process
// start.
func GuardEstablishedClearsCount() uint64 { return guardEstablishedClears.Load() }

// establishedTableState caches the parsed tables, keyed by the GUARD'S
// ecosystem verb ("npm", "pip", "cargo", "go", "rubygems"). Parsed once per
// process under mu; tests in this package substitute their own map through
// the same state (setEstablishedTablesForTest in guard_established_test.go)
// so the ladder invariants run hermetically without touching the embedded
// seeds.
var establishedTableState struct {
	mu    sync.RWMutex
	byEco map[string]map[string]risk.EstablishedRow
}

// establishedTableEcosystem maps an ecosystem spelling — a filename stem
// (established_pypi.tsv → "pypi") or a caller's string ("pip", "python") —
// onto the guard's own ecosystem verb, the same folding
// guardCanonicalEcosystem performs for allowlist coordinates. One function
// for both sides, so a table named for the registry spelling answers a
// lookup by the guard's verb and vice versa.
func establishedTableEcosystem(ecosystem string) string {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "pypi", "python", "pip3":
		return "pip"
	case "npmjs", "node", "nodejs":
		return "npm"
	case "crates", "crates-io", "cratesio", "rust":
		return "cargo"
	case "gem", "gems", "ruby":
		return "rubygems"
	case "golang", "gomod":
		return "go"
	default:
		return strings.ToLower(strings.TrimSpace(ecosystem))
	}
}

// loadEstablishedTables parses every embedded table. Unknown-ecosystem files
// (the comment-only placeholder keys to "placeholder") parse to empty maps
// no lookup consults.
func loadEstablishedTables() map[string]map[string]risk.EstablishedRow {
	byEco := map[string]map[string]risk.EstablishedRow{}
	paths, err := fs.Glob(establishedSeedFS, "seeds/established_*.tsv")
	if err != nil {
		// fs.Glob on a literal pattern cannot error; say it anyway rather
		// than pretend an empty set is data.
		slog.Warn("chainsaw: established tables: glob failed", "err", err)
		return byEco
	}
	for _, path := range paths {
		stem := strings.TrimSuffix(strings.TrimPrefix(path, "seeds/established_"), ".tsv")
		eco := establishedTableEcosystem(stem)
		data, err := establishedSeedFS.ReadFile(path)
		if err != nil {
			slog.Warn("chainsaw: established tables: unreadable", "file", path, "err", err)
			continue
		}
		rows, skipped := parseEstablishedTable(eco, data)
		if eco != "" && len(rows) > 0 {
			byEco[eco] = rows
		}
		if skipped > 0 {
			slog.Warn("chainsaw: established table: rows skipped — a skipped row is a package this table cannot clear",
				"ecosystem", eco, "file", path, "skipped", skipped)
		}
	}
	return byEco
}

// establishedTableFor returns the row table for an ecosystem, parsing the
// embedded seeds on first use.
func establishedTableFor(ecosystem string) (map[string]risk.EstablishedRow, bool) {
	key := establishedTableEcosystem(ecosystem)
	s := &establishedTableState
	s.mu.RLock()
	if s.byEco != nil {
		rows, ok := s.byEco[key]
		s.mu.RUnlock()
		return rows, ok
	}
	s.mu.RUnlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byEco == nil {
		s.byEco = loadEstablishedTables()
	}
	rows, ok := s.byEco[key]
	return rows, ok
}

// establishedDateLayout is the only date format the tables accept.
const establishedDateLayout = "2006-01-02"

// parseEstablishedInt64 / parseEstablishedInt read a numeric TSV field,
// treating an empty field as unknown (0) rather than malformed.
func parseEstablishedInt64(s string) (int64, error) {
	if strings.TrimSpace(s) == "" {
		return 0, nil
	}
	return strconv.ParseInt(strings.TrimSpace(s), 10, 64)
}

func parseEstablishedInt(s string) (int, error) {
	if strings.TrimSpace(s) == "" {
		return 0, nil
	}
	return strconv.Atoi(strings.TrimSpace(s))
}

// parseEstablishedTable parses one ecosystem's TSV into normalized-name →
// row. Rows are keyed by the SAME normalizer the typosquat detector uses for
// the ecosystem (typosquat.NormalizerForFormat — PEP 503 for PyPI, lowercase
// for npm, hyphen-folding for cargo/rubygems), so "Django_Filter" and
// "django-filter" share one row exactly as they share one detector key.
//
// Returns the table and the count of malformed rows skipped. Skipped rows are
// the caller's business to log loudly: this is reviewed data, and a bad row
// is a build-pipeline bug someone must see, not a silent hole.
func parseEstablishedTable(ecosystem string, data []byte) (rows map[string]risk.EstablishedRow, skipped int) {
	norm := typosquat.NormalizerForFormat(ecosystem)
	rows = map[string]risk.EstablishedRow{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 5 && len(fields) != 6 {
			skipped++
			slog.Warn("chainsaw: established table: malformed row (want 5 or 6 tab-separated fields)",
				"ecosystem", ecosystem, "row", sanitizeForTerminal(line))
			continue
		}
		name := strings.TrimSpace(fields[0])
		if name == "" {
			skipped++
			continue
		}
		// Numeric fields: an EMPTY field is unknown (zero — below every
		// line, same as a failed fetch); non-numeric content is malformed.
		weekly, err := parseEstablishedInt64(fields[1])
		if err != nil {
			skipped++
			slog.Warn("chainsaw: established table: malformed weekly_downloads",
				"ecosystem", ecosystem, "name", name, "value", sanitizeForTerminal(fields[1]))
			continue
		}
		versions, err := parseEstablishedInt(fields[2])
		if err != nil {
			skipped++
			slog.Warn("chainsaw: established table: malformed version_count",
				"ecosystem", ecosystem, "name", name, "value", sanitizeForTerminal(fields[2]))
			continue
		}
		row := risk.EstablishedRow{Name: name, WeeklyDownloads: weekly, VersionCount: versions}
		bad := false
		for i, dst := range []*time.Time{&row.FirstPublished, &row.LastPublished} {
			v := strings.TrimSpace(fields[3+i])
			if v == "" {
				continue // unknown; the zero value already means that
			}
			t, err := time.Parse(establishedDateLayout, v)
			if err != nil {
				slog.Warn("chainsaw: established table: malformed date (want YYYY-MM-DD or empty)",
					"ecosystem", ecosystem, "name", name, "value", sanitizeForTerminal(v))
				bad = true
				break
			}
			*dst = t
		}
		if bad {
			skipped++
			continue
		}
		if len(fields) == 6 {
			for _, v := range strings.Split(fields[5], ",") {
				if v = strings.TrimSpace(v); v != "" {
					if row.Releases == nil {
						row.Releases = map[string]struct{}{}
					}
					row.Releases[v] = struct{}{}
				}
			}
		}
		// First occurrence wins, mirroring core/typosquat's established
		// reference: a duplicated line cannot forge a stronger row.
		key := norm(name)
		if key == "" {
			skipped++
			continue
		}
		if _, dup := rows[key]; !dup {
			rows[key] = row
		}
	}
	if err := scanner.Err(); err != nil {
		slog.Warn("chainsaw: established table: read failed mid-file",
			"ecosystem", ecosystem, "err", err)
	}
	return rows, skipped
}

// establishedClears reports whether the ESTABLISHED TABLE clears this
// candidate's typosquat lane: the row (if any) run through
// risk.EstablishedClear — the one definition the server path also calls.
//
// ok=false means "no row, or the row's data clears nothing" — both leave the
// typosquat lane exactly as it was. The lookup is name-keyed under the
// detector's own per-ecosystem normalizer (applied to the CANONICAL
// ecosystem, so an alias spelling like "python" normalizes as pip/PEP 503
// rather than falling to the generic normalizer), offline, once per process.
func establishedClears(ecosystem, name string, now time.Time) (reason string, row risk.EstablishedRow, ok bool) {
	if strings.TrimSpace(name) == "" {
		return "", risk.EstablishedRow{}, false
	}
	canon := establishedTableEcosystem(ecosystem)
	table, found := establishedTableFor(canon)
	if !found {
		return "", risk.EstablishedRow{}, false
	}
	key := typosquat.NormalizerForFormat(canon)(name)
	if key == "" {
		return "", risk.EstablishedRow{}, false
	}
	r, found := table[key]
	if !found {
		return "", risk.EstablishedRow{}, false
	}
	reason, cleared := risk.EstablishedClear(r, now)
	if !cleared {
		return "", r, false
	}
	return reason, r, true
}

// establishedPinnedRelease reports whether an install request names exactly
// one of the releases the table saw at build time — the ONLY case in which an
// established clear stays silent. Everything else warns: an empty version
// (`npm install jsonp`, `pip install faiss-gpu`), a range or tag (`^0.2.0`,
// `latest`, `>=1`), and an exact version the table never saw, which is the
// shape of a dormant cleared lookalike shipping a new release. npm and pip
// accept a leading "=" or "v" on an exact version; nothing else is folded, so
// a spelling the table does not carry errs toward the warning.
func establishedPinnedRelease(row risk.EstablishedRow, version string) bool {
	v := strings.TrimLeft(strings.TrimSpace(version), "=v")
	if v == "" || len(row.Releases) == 0 {
		return false
	}
	_, ok := row.Releases[v]
	return ok
}

// establishedWarnReason renders the warning an established clear leaves
// behind when the install is not an exact pin the table knows: the
// typosquat claim (which names the lookalike target), why the name counts as
// established, and why that was not enough to stay quiet.
func establishedWarnReason(spec packageSpec, hitReason, why string) string {
	pin := "no exact version was requested"
	if strings.TrimSpace(spec.Version) != "" {
		pin = fmt.Sprintf("version %q is not a release the established table recorded", spec.Version)
	}
	return fmt.Sprintf("%s — %s is established (%s), so this is a warning, not a refusal; %s",
		hitReason, spec.Name, why, pin)
}

// establishedClearsNotice renders the per-verdict informational line for a
// cleared candidate (printed by printGuardVerdicts, suppressed under
// --quiet: on a lockfile install of ten thousand packages, dozens of these
// are context, not signal — the malware and byte lanes that STILL ran are
// the signal).
func establishedClearsNotice(spec packageSpec, hitReason, why string) string {
	return fmt.Sprintf("%s — cleared, %s is established (%s)",
		hitReason, spec.Name, why)
}

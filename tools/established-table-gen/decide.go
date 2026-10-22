package main

// decide.go — the row shape and the small decisions on it: dates, the
// npm placeholder rule, edit distance, the previous table's names.

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
)

const (
	// weeklyDownloadsLine is risk.EstablishedWeeklyDownloads, the downloads
	// half of census admission; every ecosystem is scaled to a week so the
	// guard's runtime clear (risk.EstablishedClear) agrees with the census.
	weeklyDownloadsLine = 100_000
	// churnTotalLimit: the share of a previous census's rows a regeneration
	// may lose before it is refused.
	churnTotalLimit = 0.25
)

// row is one candidate's distilled registry truth — the unit every decision
// (clear line, rail, TSV line) works on.
type row struct {
	Name        string
	Weekly      int64 // weekly downloads (pypi/cargo/pub scaled to a week, see weeklyNote)
	Versions    int
	First       string // YYYY-MM-DD or ""
	Last        string // YYYY-MM-DD or ""
	HasData     bool   // false = 404/unpublished — no registry truth, never qualifies
	Placeholder bool   // npm security holds the name now (npmPlaceholder): never established
	// Releases is every published version at build time: the TSV's sixth
	// column, the guard's only silent case.
	Releases []string
}

func parseDate(s string) time.Time {
	if len(s) != 10 {
		return time.Time{}
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// ---------------------------------------------------------------------------
// churn rail (rail 4)

// parseTable reads a previous established TSV: # header lines, then
// name<TAB>weekly<TAB>versions<TAB>first<TAB>last. Row order is downloads
// desc, so the first 100 rows are the "top 100" the churn rail compares.
func parseTable(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var names []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) != 5 && len(cols) != 6 {
			return nil, fmt.Errorf("%s: malformed row %q (want 5 or 6 tab columns)", path, line)
		}
		names = append(names, cols[0])
	}
	return names, sc.Err()
}

// ---------------------------------------------------------------------------
// patient-attacker self-test (rail 5)

// npmPlaceholder reports whether npm security holds the name NOW: its
// highest version is a "-security" holding release. npm:http (0.0.0, then
// 0.0.1-security) is held; tslib, ckeditor5 or sass-embedded-win32-x64 carry
// an old 0.0.1-security from before their real owners published, and their
// real releases sort above it — those are not placeholders. An unparseable
// version is ignored rather than guessed at.
func npmPlaceholder(versions []string) bool {
	var maxSec, maxReal *semver.Version
	for _, v := range versions {
		sv, err := semver.NewVersion(v)
		if err != nil {
			continue
		}
		if strings.HasSuffix(v, "-security") {
			if maxSec == nil || sv.GreaterThan(maxSec) {
				maxSec = sv
			}
		} else if maxReal == nil || sv.GreaterThan(maxReal) {
			maxReal = sv
		}
	}
	return maxSec != nil && (maxReal == nil || maxSec.GreaterThan(maxReal))
}

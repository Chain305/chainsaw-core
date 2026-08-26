package metadata

// trust_score_writer_guard_test.go — a tripwire, not a prohibition.
//
// UPDATED 2026-08-26. The CONDITION is now live; the COLUMN still has no
// writer, so this guard still means what it says.
//
// trustScoreMin/trustScoreMax fire again, but not because anything started
// writing this column. interceptPolicyViolation now merges the
// freshly-computed score onto the prefetched package_metadata row in
// memory (server_repo_pipeline.go) instead of discarding it. The score is
// recomputed on the request anyway, so the merge is always fresher than a
// column would be, and it needs no writer, no migration and no epoch
// interaction.
//
// So this tripwire is no longer "the condition is dead". It is now "adding
// a WRITER is still a separate decision with its own blast radius", and
// the checklist below still applies to that decision.
//
// The distribution, measured on the 7,099-row production export before the
// merge shipped (99.4% of rows carry a rolled-up score, median 96):
//
//	trustScoreMax <= 45  ->  374 rows, ZERO of them currently `allow`
//	trustScoreMax == 60  ->  1,410 rows, 943 of them currently `allow`
//	                         — 14% of the corpus, including has-flag@4.0.0,
//	                         protobufjs and androidx.lifecycle
//
// A dense cluster of mainstream packages sits exactly at the warn
// boundary. Anything at or below 50 blocks nothing that is not already
// flagged; anything at or above it is catastrophic.
//
// THE STATE THIS PINS
//
// package_metadata.trust_score has no writer. The column is declared
// (migrate.go, migrate_packages.go) and the UPDATE builder has a
// `trust_score=?` SET clause, but nothing anywhere — production or test —
// constructs a PackageMetadataUpdate with TrustScore set, and the INSERT
// statement omits the column entirely. intelligence/adapters.go assigns
// TrustScore onto a PackageMetadata struct, but Upsert's column list drops
// it on the floor. So the column is NULL for every row that has ever
// existed.
//
// WHY THAT MATTERS
//
// Both readers correctly treat NULL as "never scored" and leave
// policy.Conditions.TrustScore nil — server_repo_pipeline.go for live
// enforcement, policy_simulate.go for the preview. Since the column is
// always NULL, the pointer is always nil, and therefore `trustScoreMin`
// and `trustScoreMax` conditions CANNOT FIRE, in production or in
// simulation. An operator who writes "block anything below trust score 40"
// gets silence, and nothing tells them.
//
// The simulator is at least honest about it: cov.mark(sigTrustScore, ...)
// reports the corpus gap in the preview panel. The live enforcement path
// has no equivalent disclosure.
//
// WHY THIS IS A TRIPWIRE RATHER THAN A FIX
//
// Wiring a writer is not a small change, and intelligence/adapters.go
// already says why: "wiring a writer later would mass-block on a value
// nobody measured". Every org that has a trustScoreMin/Max rule saved
// today has a rule that has never matched anything. Populate the column
// and those rules begin firing at once, against scores no one has ever
// looked at. That needs a measured flip, not a commit.
//
// So: if you are wiring the writer, this test SHOULD fail. Read the
// checklist in the failure message, do those things, then delete this
// test in the same commit.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// trustScoreWrite matches a WRITE of TrustScore: a composite-literal field
// (`TrustScore: x`) or an assignment (`u.TrustScore = x`).
//
// Deliberately NOT a bare mention. The first repair of this guard flagged
// three non-writes — `meta.TrustScore = int(trustScore.Int64)` (a DB read
// being scanned INTO the struct) and `update.TrustScore == nil` (the SET
// builder's own nil check) — which is how an over-broad guard becomes noise
// and then gets deleted.
// trustScoreWrite matches a write of TrustScore ON A SupplyChainUpdate —
// the only shape that reaches the column. Two forms exist in this tree:
// the composite literal (`SupplyChainUpdate{ ... TrustScore: &x ... }`)
// and a field assignment on the conventional `update` variable.
//
// Deliberately NOT any `.TrustScore =`. The second repair of this guard
// flagged `ctx.TrustScore = &ts` and `prefetchedPkgMeta.TrustScore =
// fresh.TrustScore` — both IN-MEMORY projections onto the policy context,
// neither of which touches the database. A guard that cannot tell a column
// write from a struct field assignment reports the fix for the dead
// condition as the writer it was built to prevent.
var trustScoreWrite = regexp.MustCompile(`^\s*TrustScore:\s*[^=]|\bupdate\.TrustScore\s*=[^=]`)

// supplyChainLiteral marks the start of a SupplyChainUpdate composite
// literal, so a bare `TrustScore:` field is only counted inside one.
var supplyChainLiteral = regexp.MustCompile(`SupplyChainUpdate\{`)

// updateTypeName is the struct a writer would have to populate.
//
// This guard shipped naming a type that DOES NOT EXIST — "PackageMetadataUpdate".
// The filter below skipped every file in the tree, so `writers` was always
// empty and the test could never fail. The negative control that was supposed
// to catch that was fooled in the most instructive way: the probe added to
// "prove" the guard fires itself contained the string PackageMetadataUpdate,
// so the file passed the filter and the regex matched. It proved the text
// scanner works on a file containing the text — not that any real writer is
// caught.
//
// Two lessons encoded here: name the type from the source (SupplyChainUpdate,
// core/metadata/store.go), and write the probe as a REALISTIC writer rather
// than one shaped to satisfy the matcher.
const updateTypeName = "SupplyChainUpdate"

// TestPackageMetadataTrustScoreStillHasNoWriter fails the moment PRODUCTION
// code starts populating the column.
//
// Tests are excluded on purpose: core/metadata/store_test.go and
// internal/server/server_mcp_sbom_regression_test.go both set TrustScore in a
// SupplyChainUpdate to exercise the readers, and that is correct. The claim
// being pinned is narrower and is the one that matters — nothing on a
// production path writes it, so the column is NULL in every real deployment.
func TestPackageMetadataTrustScoreStillHasNoWriter(t *testing.T) {
	// Repo root, not core/. The one real UpdateSupplyChainMetadata caller
	// lives in internal/server (checksum_enforce.go), which a core/-rooted
	// walk never reaches — the second half of the vacuity described above.
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	// core/ is exported standalone to the public chainsaw-core repo, where
	// internal/ does not exist at all. Every caller this guard exists to
	// find lives OUTSIDE the exported subtree, so in the export there is
	// genuinely nothing to assert — and the vacuity check below would fire
	// on a tree that is not at fault. Skip, rather than weakening the
	// check for the monorepo where it does its work.
	//
	// scripts/opencore-export.sh runs the export's tests standalone as a
	// release gate; without this, a guard about a caller outside core/
	// fails that gate.
	if _, statErr := os.Stat(filepath.Join(root, "internal", "server")); statErr != nil {
		t.Skip("standalone core/ export: UpdateSupplyChainMetadata callers live outside this subtree")
	}
	var writers []string
	scanned := 0
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if strings.HasSuffix(path, "trust_score_writer_guard_test.go") {
			return nil
		}
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		src := string(b)
		if !strings.Contains(src, updateTypeName) {
			return nil
		}
		// The metadata package's own store.go DEFINES the type and the SET
		// builder; its nil-checks and its DB-read scan are not callers.
		//
		// Matched WITHOUT a `core/` prefix. core/ is re-rooted when it is
		// exported to the public chainsaw-core repo — core/metadata/store.go
		// there is metadata/store.go — so a prefix-anchored match stops
		// firing in the export and the guard flags the DB read at :296 as a
		// writer. scripts/opencore-export.sh caught exactly that; the same
		// re-rooting is why .gitleaks.toml anchors its patterns `^(core/)?`.
		if filepath.Base(path) == "store.go" &&
			filepath.Base(filepath.Dir(path)) == "metadata" {
			return nil
		}
		// Tests legitimately populate the column to exercise the readers.
		// The claim being pinned is that no PRODUCTION code does.
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		scanned++
		lines := strings.Split(src, "\n")
		inLiteral := 0
		for i, line := range lines {
			if supplyChainLiteral.MatchString(line) {
				inLiteral = 12 // a literal spans at most a dozen fields
			} else if inLiteral > 0 {
				inLiteral--
			}
			if !trustScoreWrite.MatchString(line) {
				continue
			}
			// A bare `TrustScore:` only counts inside a SupplyChainUpdate
			// literal; `update.TrustScore =` counts anywhere.
			bare := !strings.Contains(line, "update.TrustScore")
			if bare && inLiteral == 0 {
				continue
			}
			writers = append(writers, rel+":"+itoa(i+1)+": "+strings.TrimSpace(line))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned == 0 {
		t.Fatalf("no PRODUCTION file mentions %s — the type was renamed or the walk "+
			"root is wrong, and this guard is scanning nothing. That is exactly how "+
			"it shipped vacuous the first time.", updateTypeName)
	}
	if len(writers) > 0 {
		t.Errorf("package_metadata.trust_score now has a writer:\n\t%s\n\n"+
			"That is a real change in enforcement behaviour, not plumbing. Every org\n"+
			"with a trustScoreMin/trustScoreMax rule saved today has a rule that has\n"+
			"NEVER matched, because the column has always been NULL and both readers\n"+
			"correctly treat NULL as \"never scored\". Populating it makes all of those\n"+
			"rules start firing at once, on scores nobody has measured.\n\n"+
			"Before landing this:\n"+
			"  1. Count the saved policies using trustScoreMin/trustScoreMax, per org.\n"+
			"  2. Run the corpus through the scorer and measure how many packages each\n"+
			"     of those rules would newly block. That number is the blast radius.\n"+
			"  3. Decide the rollout: default-off flag, or notify affected orgs first.\n"+
			"  4. Delete this test in the same commit, and say in the message what\n"+
			"     step 2 measured.",
			strings.Join(writers, "\n\t"))
	}
}

// The INSERT must also stay clear of the column — a writer could arrive
// through the insert path without any Update struct being touched.
func TestPackageMetadataInsertOmitsTrustScore(t *testing.T) {
	b, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	i := strings.Index(src, "INSERT INTO package_metadata")
	if i < 0 {
		t.Fatal("no INSERT INTO package_metadata found — this guard has rotted")
	}
	end := strings.Index(src[i:], "`")
	if end < 0 {
		end = 1200
	}
	stmt := src[i : i+end]
	if strings.Contains(stmt, "trust_score") {
		t.Error("the package_metadata INSERT now writes trust_score — see " +
			"TestPackageMetadataTrustScoreStillHasNoWriter for the blast-radius checklist")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

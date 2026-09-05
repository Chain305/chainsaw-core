package intelligence

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestIntelKeyCanonicalisesPackageName pins A4: the report identity for the
// ecosystems whose registries fold names is the FOLDED name, and every
// other ecosystem's name is passed through byte-for-byte.
//
// The controls matter as much as the positives. npm is case-preserving in
// OSV, in runNPM and in the proxy resolver, and legacy names such as
// `JSONStream` are live — lowercasing it would split the intel row from
// the proxy's row for the same bytes. go module paths and rubygems names
// are likewise identity-preserving upstream.
func TestIntelKeyCanonicalisesPackageName(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   Key
		want string
		// wantEco is the ecosystem CanonicalKey must produce. Empty means
		// "the input spelling, unchanged".
		wantEco string
	}{
		// pypi: PEP 503 — case-fold and collapse runs of [-_.] to one '-'.
		{"pypi upper", Key{Ecosystem: "pypi", Package: "REQUESTS", Version: "2.32.3"}, "requests", "pip"},
		{"pypi title", Key{Ecosystem: "pypi", Package: "Requests", Version: "2.32.3"}, "requests", "pip"},
		{"pypi underscore", Key{Ecosystem: "pypi", Package: "requests_x", Version: "1"}, "requests-x", "pip"},
		{"pypi dot", Key{Ecosystem: "pypi", Package: "requests.x", Version: "1"}, "requests-x", "pip"},
		{"pypi run", Key{Ecosystem: "pypi", Package: "requests__x", Version: "1"}, "requests-x", "pip"},
		{"pypi mixed run", Key{Ecosystem: "pypi", Package: "Requests._-X", Version: "1"}, "requests-x", "pip"},
		// The proxy writes `pip`; the same fold applies to that spelling.
		{"pip alias", Key{Ecosystem: "pip", Package: "Apache_Airflow", Version: "2.10.0"}, "apache-airflow", ""},
		// The ecosystem is folded onto the spelling the PROXY writes, so a
		// human-typed `PyPI` reaches the row `pip` already holds.
		{"pypi upper eco", Key{Ecosystem: "PyPI", Package: "Flask", Version: "3.0.0"}, "flask", "pip"},
		{"pypi padded", Key{Ecosystem: "pypi", Package: "  Flask ", Version: "3.0.0"}, "flask", "pip"},

		// nuget and composer: lowercase only (osv/bundle.go, the nuget and
		// composer proxy resolvers).
		{"nuget", Key{Ecosystem: "nuget", Package: "Newtonsoft.Json", Version: "13.0.3"}, "newtonsoft.json", ""},
		{"composer", Key{Ecosystem: "composer", Package: "Monolog/Monolog", Version: "3.5.0"}, "monolog/monolog", ""},

		// Controls: untouched, including case.
		{"npm legacy mixed case", Key{Ecosystem: "npm", Package: "JSONStream", Version: "1.3.5"}, "JSONStream", ""},
		{"npm scoped", Key{Ecosystem: "npm", Package: "@Babel/Core", Version: "7.24.0"}, "@Babel/Core", ""},
		{"go module path", Key{Ecosystem: "go", Package: "github.com/BurntSushi/toml", Version: "v1.3.2"}, "github.com/BurntSushi/toml", ""},
		{"rubygems", Key{Ecosystem: "rubygems", Package: "RAILS", Version: "7.1.0"}, "RAILS", ""},
		{"cargo", Key{Ecosystem: "cargo", Package: "Serde_JSON", Version: "1.0.0"}, "Serde_JSON", ""},
		{"maven", Key{Ecosystem: "maven", Package: "Org.SLF4J:SLF4J-Api", Version: "2.0.9"}, "Org.SLF4J:SLF4J-Api", ""},
		{"docker", Key{Ecosystem: "docker", Package: "Library/Nginx", Version: "latest"}, "Library/Nginx", ""},
		{"empty eco", Key{Ecosystem: "", Package: "Requests", Version: "1"}, "Requests", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := CanonicalKey(tc.in)
			if got.Package != tc.want {
				t.Errorf("CanonicalKey(%+v).Package = %q, want %q", tc.in, got.Package, tc.want)
			}
			wantEco := tc.wantEco
			if wantEco == "" {
				wantEco = tc.in.Ecosystem
			}
			if got.Ecosystem != wantEco {
				t.Errorf("CanonicalKey(%q).Ecosystem = %q, want %q", tc.in.Ecosystem, got.Ecosystem, wantEco)
			}
			if got.Version != tc.in.Version {
				t.Errorf("CanonicalKey rewrote Version %q -> %q", tc.in.Version, got.Version)
			}
			// Idempotent: the canonical form of a canonical key is itself.
			if again := CanonicalKey(got); again != got {
				t.Errorf("CanonicalKey is not idempotent: %+v -> %+v", got, again)
			}
		})
	}

	// The five pypi spellings in the plan collapse to exactly two identities.
	seen := map[string]bool{}
	for _, p := range []string{"REQUESTS", "Requests", "requests"} {
		seen[CanonicalKey(Key{Ecosystem: "pypi", Package: p}).Package] = true
	}
	if len(seen) != 1 {
		t.Errorf("case variants of requests produced %d identities: %v", len(seen), seen)
	}
	seen = map[string]bool{}
	for _, p := range []string{"requests_x", "requests.x", "requests__x", "requests-x"} {
		seen[CanonicalKey(Key{Ecosystem: "pypi", Package: p}).Package] = true
	}
	if len(seen) != 1 {
		t.Errorf("separator variants of requests-x produced %d identities: %v", len(seen), seen)
	}
}

// TestCanonicalNameRuleMatchesCanonicalKey pins the one-definition
// property the cleanup depends on: the ecosystem lists handed to pgstore
// are the lists CanonicalKey itself switches on, so the SQL population and
// the Go rewrite cannot drift apart.
func TestCanonicalNameRuleMatchesCanonicalKey(t *testing.T) {
	t.Parallel()
	rule := CanonicalNameRule()
	if len(rule.PEP503Ecosystems) == 0 || len(rule.LowercaseEcosystems) == 0 {
		t.Fatalf("rule has an empty ecosystem list: %+v", rule)
	}
	for _, eco := range rule.PEP503Ecosystems {
		if got := CanonicalKey(Key{Ecosystem: eco, Package: "Foo_Bar"}).Package; got != "foo-bar" {
			t.Errorf("ecosystem %q is in the PEP 503 rule but CanonicalKey folded Foo_Bar to %q", eco, got)
		}
	}
	for _, eco := range rule.LowercaseEcosystems {
		if got := CanonicalKey(Key{Ecosystem: eco, Package: "Foo_Bar"}).Package; got != "foo_bar" {
			t.Errorf("ecosystem %q is in the lowercase rule but CanonicalKey folded Foo_Bar to %q", eco, got)
		}
	}
	// Mutating the returned slices must not reach the package definition.
	rule.PEP503Ecosystems[0] = "npm"
	if CanonicalKey(Key{Ecosystem: "npm", Package: "JSONStream"}).Package != "JSONStream" {
		t.Error("CanonicalNameRule returned the package-level slice by reference")
	}
}

// fakeCanonicalBackend is an in-memory canonicalCleanupBackend that records
// the ORDER of mutations, which is the property under test: the merge write
// on the canonical row must land before the non-canonical row is deleted.
type fakeCanonicalBackend struct {
	rows       map[Key]*Report
	candidates []Key
	ops        []string
	author     map[Key]string
}

func newFakeCanonicalBackend() *fakeCanonicalBackend {
	return &fakeCanonicalBackend{rows: map[Key]*Report{}, author: map[Key]string{}}
}

func (f *fakeCanonicalBackend) put(k Key, r *Report) {
	r.Identity.Ecosystem, r.Identity.Package, r.Identity.Version = k.Ecosystem, k.Package, k.Version
	f.rows[k] = r
}

func (f *fakeCanonicalBackend) ListNonCanonicalKeys(ctx context.Context, limit int) ([]Key, error) {
	f.ops = append(f.ops, "list")
	return append([]Key(nil), f.candidates...), nil
}

func (f *fakeCanonicalBackend) Get(ctx context.Context, k Key) (*Report, error) {
	f.ops = append(f.ops, "get "+k.Package)
	r, ok := f.rows[k]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *r
	return &cp, nil
}

func (f *fakeCanonicalBackend) Author(ctx context.Context, k Key) (string, error) {
	return f.author[k], nil
}

func (f *fakeCanonicalBackend) Upsert(ctx context.Context, orgID string, r *Report) error {
	k := Key{Ecosystem: r.Identity.Ecosystem, Package: r.Identity.Package, Version: r.Identity.Version}
	f.ops = append(f.ops, "upsert "+k.Package)
	cp := *r
	f.rows[k] = &cp
	f.author[k] = orgID
	return nil
}

func (f *fakeCanonicalBackend) Rename(ctx context.Context, from, to Key) (bool, error) {
	f.ops = append(f.ops, "rename "+from.Package+"->"+to.Package)
	if _, exists := f.rows[to]; exists {
		return false, nil
	}
	r, ok := f.rows[from]
	if !ok {
		return false, nil
	}
	delete(f.rows, from)
	f.put(to, r)
	return true, nil
}

func (f *fakeCanonicalBackend) Delete(ctx context.Context, k Key) (bool, error) {
	f.ops = append(f.ops, "delete "+k.Package)
	if _, ok := f.rows[k]; !ok {
		return false, nil
	}
	delete(f.rows, k)
	return true, nil
}

// TestCanonicalCleanupMergesStickyFactsBeforeDelete is the load-bearing
// cleanup test. Sticky facts are read by EXACT key, so deleting the
// non-canonical row first would retract a fact its canonical sibling never
// held — on an org-less table, for every tenant at once.
func TestCanonicalCleanupMergesStickyFactsBeforeDelete(t *testing.T) {
	t.Parallel()
	fb := newFakeCanonicalBackend()
	// `pip` on both sides on purpose: this test owns the NAME dimension.
	// The ecosystem dimension has its own test below.
	canon := Key{Ecosystem: "pip", Package: "requests", Version: "2.32.3"}
	typed := Key{Ecosystem: "pip", Package: "Requests", Version: "2.32.3"}

	// The canonical row is Tier-1 only: no supply-chain facts.
	fb.put(canon, &Report{})
	fb.author[canon] = "org-canon"
	// The non-canonical row carries facts a Tier-3 pass observed.
	pc := true
	fb.put(typed, &Report{SupplyChain: SupplyChainSection{
		RepoLinkStatus: "missing",
		// The evidence travels with the bool: applyStickySupplyChain
		// declines to revive a publisher change it cannot name, so a
		// fixture without these lists would silently stop exercising the
		// merge this test is about.
		PublisherChanged: &pc,
		PublisherAdded:   []string{"new-maintainer"},
		TyposquatStatus:  "suspected",
	}})
	fb.candidates = []Key{typed}

	res, err := canonicaliseReportNames(context.Background(), fb, 0)
	if err != nil {
		t.Fatalf("canonicaliseReportNames: %v", err)
	}
	if res.Merged != 1 || res.Renamed != 0 || res.Retained != 0 || len(res.Errors) != 0 {
		t.Fatalf("result = %+v, want exactly one merge", res)
	}

	// Ordering: the upsert of the canonical row precedes the delete.
	ops := strings.Join(fb.ops, "\n")
	up := strings.Index(ops, "upsert requests")
	del := strings.Index(ops, "delete Requests")
	if up < 0 || del < 0 {
		t.Fatalf("expected both an upsert of the canonical row and a delete of the typed row; ops:\n%s", ops)
	}
	if up > del {
		t.Fatalf("delete ran BEFORE the merge write; ops:\n%s", ops)
	}

	// Facts survived on the canonical row; the typed row is gone.
	got, ok := fb.rows[canon]
	if !ok {
		t.Fatal("canonical row vanished")
	}
	if got.SupplyChain.RepoLinkStatus != "missing" || got.SupplyChain.TyposquatStatus != "suspected" ||
		got.SupplyChain.PublisherChanged == nil || !*got.SupplyChain.PublisherChanged {
		t.Errorf("sticky facts were not merged onto the canonical row: %+v", got.SupplyChain)
	}
	if got.Identity.Package != "requests" {
		t.Errorf("merged row identity = %q, want requests", got.Identity.Package)
	}
	if _, still := fb.rows[typed]; still {
		t.Error("non-canonical row was not deleted after the merge")
	}
	// The write is attributed to the canonical row's own author, not to a
	// phantom empty org.
	if fb.author[canon] != "org-canon" {
		t.Errorf("merge write authored_by_org = %q, want org-canon", fb.author[canon])
	}
}

// TestCanonicalCleanupRenamesWhenNoSibling: with no canonical row, the
// non-canonical row is renamed in place — no delete, no rewrite of the
// payload, nothing to merge.
func TestCanonicalCleanupRenamesWhenNoSibling(t *testing.T) {
	t.Parallel()
	fb := newFakeCanonicalBackend()
	typed := Key{Ecosystem: "nuget", Package: "Newtonsoft.Json", Version: "13.0.3"}
	fb.put(typed, &Report{SupplyChain: SupplyChainSection{RepoLinkStatus: "ok"}})
	fb.candidates = []Key{typed}

	res, err := canonicaliseReportNames(context.Background(), fb, 0)
	if err != nil {
		t.Fatalf("canonicaliseReportNames: %v", err)
	}
	if res.Renamed != 1 || res.Merged != 0 {
		t.Fatalf("result = %+v, want exactly one rename", res)
	}
	for _, op := range fb.ops {
		if strings.HasPrefix(op, "delete") || strings.HasPrefix(op, "upsert") {
			t.Errorf("rename path performed %q", op)
		}
	}
	canon := Key{Ecosystem: "nuget", Package: "newtonsoft.json", Version: "13.0.3"}
	if r, ok := fb.rows[canon]; !ok || r.SupplyChain.RepoLinkStatus != "ok" || r.Identity.Package != "newtonsoft.json" {
		t.Errorf("row was not renamed to the canonical key: %+v", fb.rows)
	}
}

// TestCanonicalCleanupRetainsMaliciousRowItCannotCarry: a malicious verdict
// on the non-canonical row whose sibling is NOT malicious is never deleted
// — the sticky rule cannot overwrite a populated MalwareStatus, so the
// delete would be the one weakening path the plan closes.
func TestCanonicalCleanupRetainsMaliciousRowItCannotCarry(t *testing.T) {
	t.Parallel()
	fb := newFakeCanonicalBackend()
	canon := Key{Ecosystem: "pip", Package: "colourama", Version: "0.1"}
	typed := Key{Ecosystem: "pip", Package: "Colourama", Version: "0.1"}
	fb.put(canon, &Report{SupplyChain: SupplyChainSection{MalwareStatus: "clean"}})
	fb.put(typed, &Report{SupplyChain: SupplyChainSection{MalwareStatus: "malicious", MalwareID: "MAL-1"}})
	fb.candidates = []Key{typed}

	res, err := canonicaliseReportNames(context.Background(), fb, 0)
	if err != nil {
		t.Fatalf("canonicaliseReportNames: %v", err)
	}
	if res.Retained != 1 || res.Merged != 0 {
		t.Fatalf("result = %+v, want the malicious row retained", res)
	}
	if _, still := fb.rows[typed]; !still {
		t.Error("malicious non-canonical row was deleted")
	}
}

// TestCanonicalCleanupSkipsKeysGoDoesNotFold: the SQL candidate list is
// advisory; a key CanonicalKey leaves unchanged is never touched, so a
// predicate that drifts wider than the Go rule cannot rename or delete
// anything.
func TestCanonicalCleanupSkipsKeysGoDoesNotFold(t *testing.T) {
	t.Parallel()
	fb := newFakeCanonicalBackend()
	k := Key{Ecosystem: "npm", Package: "JSONStream", Version: "1.3.5"}
	fb.put(k, &Report{})
	fb.candidates = []Key{k}
	res, err := canonicaliseReportNames(context.Background(), fb, 0)
	if err != nil {
		t.Fatalf("canonicaliseReportNames: %v", err)
	}
	if res.Skipped != 1 || res.Renamed != 0 || res.Merged != 0 {
		t.Fatalf("result = %+v, want the npm key skipped", res)
	}
	if _, ok := fb.rows[k]; !ok {
		t.Error("untouchable row was removed")
	}
}

// A nil store is a no-op, matching PurgeLatestSentinelCoordinates.
func TestCanonicalCleanupNilStoreIsNoop(t *testing.T) {
	t.Parallel()
	var s *Store
	if _, err := s.CanonicalNameCleanupCounts(context.Background()); err != nil {
		t.Fatal(err)
	}
	res, err := s.CanonicaliseReportNames(context.Background(), 0)
	if err != nil || res.Merged != 0 || res.Renamed != 0 {
		t.Fatalf("nil store: %+v %v", res, err)
	}
	if !errors.Is(ErrNotFound, ErrNotFound) {
		t.Fatal("unreachable")
	}
}

// TestCanonicalKeyFoldsEcosystemAliases is the ecosystem half of BUG-F-007.
//
// The name fold alone does not merge the identities: the proxy writes `pip`
// (repository.FormatPIP, internal/formats/pip/resolver.go Format()), while
// `intel scan --lockfile` writes `pypi` (internal/scan LangToEcosystem) and
// a raw `/api/v1/intel/packages/{eco}/…` path segment writes whatever the
// caller typed. Those are separate rows, so proxy-written sticky facts
// never reach the row the CLI's CI gate reads.
//
// The fold direction is therefore NOT free: it must land on the spelling
// the PROXY already writes, because folding the other way would move the
// split rather than close it and would re-key every proxy row.
func TestCanonicalKeyFoldsEcosystemAliases(t *testing.T) {
	t.Parallel()

	cases := []struct{ in, want string }{
		// PyPI. proxy = `pip` (FormatPIP); malware.NormalizeEcosystem
		// maps OSV "PyPI" -> "pip"; policy.EcoPyPI == "pip".
		{"pypi", "pip"},
		{"PyPI", "pip"},
		{"  PYPI  ", "pip"},
		{"python", "pip"},
		{"pip", "pip"},
		// crates.io. proxy = `cargo`; osv/bundle.go and provider_osv.go
		// both accept "cargo"/"crates"/"crates.io".
		{"crates.io", "cargo"},
		{"crates-io", "cargo"},
		{"crates", "cargo"},
		{"cargo", "cargo"},
		// Packagist. proxy = `composer`.
		{"packagist", "composer"},
		{"Packagist", "composer"},
		{"composer", "composer"},
		// RubyGems. proxy = `rubygems`; provider_osv.go and
		// provider_reservedns.go both carry "gem".
		{"gem", "rubygems"},
		{"rubygems", "rubygems"},
		// Go. proxy = `go` (internal/formats/gomod/resolver.go returns
		// "go"); "gomod" and "golang" are accepted aliases elsewhere.
		{"gomod", "go"},
		{"golang", "go"},
		{"go", "go"},
		// Swift. proxy = `swift`; OSV publishes "SwiftURL".
		{"swifturl", "swift"},
		{"swift", "swift"},
		// Not aliases: unknown ecosystems are lower-cased and trimmed only.
		{"conda", "conda"},
		{"Hex", "hex"},
		{"", ""},
	}
	for _, tc := range cases {
		got := CanonicalKey(Key{Ecosystem: tc.in, Package: "x", Version: "1"})
		if got.Ecosystem != tc.want {
			t.Errorf("CanonicalKey ecosystem %q -> %q, want %q", tc.in, got.Ecosystem, tc.want)
		}
		// Idempotent in the ecosystem dimension too.
		if again := CanonicalKey(got); again != got {
			t.Errorf("ecosystem fold is not idempotent: %q -> %+v -> %+v", tc.in, got, again)
		}
	}

	// The whole point: the two writers converge on ONE key.
	lockfile := CanonicalKey(Key{Ecosystem: "pypi", Package: "Requests", Version: "2.32.3"})
	proxy := CanonicalKey(Key{Ecosystem: "pip", Package: "requests", Version: "2.32.3"})
	if lockfile != proxy {
		t.Errorf("lockfile key %+v != proxy key %+v — the identity split is still open", lockfile, proxy)
	}
}

// TestCanonicalKeyNeverFoldsAProxyWrittenEcosystem is the safety guard on
// the fold DIRECTION, and it is the reason bun/yarn/gradle are excluded.
//
// For those three the non-canonical spelling is the one the PROXY writes:
// a format:bun repository keys its rows on "bun", a format:gradle one on
// "gradle". Folding bun->npm or gradle->maven at the human-typed call
// sites would take a reader OFF the proxy's row instead of onto it —
// exactly the failure this change exists to fix, in reverse. Converging
// those pairs means changing what the proxy writes, which re-keys existing
// rows and needs a production flip count first.
//
// The list mirrors internal/repository.Format (manager.go:33-53). It is a
// literal because core/ is a separate Go module and cannot import
// internal/repository; if a Format is added there, add it here too.
func TestCanonicalKeyNeverFoldsAProxyWrittenEcosystem(t *testing.T) {
	t.Parallel()
	proxyFormats := []string{
		"apt", "bun", "cargo", "cocoapods", "composer", "dnf", "docker",
		"go", "gradle", "huggingface", "maven", "npm", "nuget", "pip",
		"pub", "raw", "rubygems", "swift", "yarn", "yum",
	}
	for _, f := range proxyFormats {
		if got := CanonicalKey(Key{Ecosystem: f, Package: "x", Version: "1"}).Ecosystem; got != f {
			t.Errorf("CanonicalKey folded proxy-written ecosystem %q -> %q; that re-keys live proxy rows", f, got)
		}
	}
	// Stated positively for the three the plan's alias list would have
	// swept up: they must survive verbatim.
	for _, f := range []string{"bun", "yarn", "gradle"} {
		if got := CanonicalKey(Key{Ecosystem: f, Package: "x", Version: "1"}).Ecosystem; got != f {
			t.Errorf("%q was folded to %q — see the comment above", f, got)
		}
	}
}

// TestCanonicalEcosystemRuleMatchesCanonicalKey pins the one-definition
// property for the ecosystem dimension: the alias map handed to the SQL
// predicate is the map CanonicalKey itself resolves.
func TestCanonicalEcosystemRuleMatchesCanonicalKey(t *testing.T) {
	t.Parallel()
	rule := CanonicalNameRule()
	if len(rule.EcosystemAliases) == 0 {
		t.Fatal("rule carries no ecosystem aliases")
	}
	for alias, canon := range rule.EcosystemAliases {
		if got := CanonicalKey(Key{Ecosystem: alias, Package: "x", Version: "1"}).Ecosystem; got != canon {
			t.Errorf("rule says %q -> %q but CanonicalKey produced %q", alias, canon, got)
		}
		if alias == canon {
			t.Errorf("alias %q maps to itself; that is not an alias", alias)
		}
		// An alias target must itself be canonical, or the fold is not
		// idempotent and the cleanup could ping-pong rows.
		if got := CanonicalKey(Key{Ecosystem: canon, Package: "x", Version: "1"}).Ecosystem; got != canon {
			t.Errorf("alias target %q is itself folded to %q", canon, got)
		}
	}
	// Mutating the returned map must not reach the package definition.
	rule.EcosystemAliases["npm"] = "pip"
	if CanonicalKey(Key{Ecosystem: "npm", Package: "x", Version: "1"}).Ecosystem != "npm" {
		t.Error("CanonicalNameRule returned the package-level alias map by reference")
	}
}

// TestNonCanonicalPredicateCoversEcosystemDimension: the SQL candidate
// list must find alias-spelled and case-drifted ecosystem rows, not only
// rows whose package_name differs. Without this the cleanup would list
// nothing for the `pypi` population it exists to merge.
func TestNonCanonicalPredicateCoversEcosystemDimension(t *testing.T) {
	t.Parallel()
	pred, args := nonCanonicalPredicate(CanonicalNameRule())
	if !strings.Contains(pred, "ecosystem") {
		t.Fatalf("predicate does not mention ecosystem: %s", pred)
	}
	// `crates.io` appears in NO name-fold list, so binding it proves the
	// predicate grew a clause for the ecosystem dimension rather than
	// merely reusing the name clauses' ecosystem filter.
	bound := map[string]bool{}
	for _, a := range args {
		if v, ok := a.(string); ok {
			bound[v] = true
		}
	}
	if !bound["crates.io"] || !bound["gomod"] {
		t.Errorf("predicate does not bind the ecosystem aliases; args=%v pred=%s", args, pred)
	}
	// Case / whitespace drift on a non-alias ecosystem (`NuGet`) is only
	// reachable through this clause.
	if !strings.Contains(pred, "ecosystem <> lower(btrim(ecosystem))") {
		t.Errorf("predicate has no ecosystem case-drift clause: %s", pred)
	}
	// An empty rule must select nothing — an under-populated rule touches
	// no rows, which is the safe direction for a DELETE.
	if got, gotArgs := nonCanonicalPredicate(CanonicalNameRuleSpec{}); got != "FALSE" || len(gotArgs) != 0 {
		t.Errorf("empty rule predicate = %q %v, want FALSE", got, gotArgs)
	}
}

// TestCanonicalCleanupMergesAcrossEcosystemAlias is the ecosystem twin of
// TestCanonicalCleanupMergesStickyFactsBeforeDelete: a `pypi` row written
// by the lockfile path carries sticky facts the `pip` row the proxy writes
// has never seen. The merge write must land before the delete.
func TestCanonicalCleanupMergesAcrossEcosystemAlias(t *testing.T) {
	t.Parallel()
	fb := newFakeCanonicalBackend()
	canon := Key{Ecosystem: "pip", Package: "requests", Version: "2.32.3"}
	typed := Key{Ecosystem: "pypi", Package: "Requests", Version: "2.32.3"}

	fb.put(canon, &Report{})
	fb.author[canon] = "org-canon"
	pc := true
	fb.put(typed, &Report{SupplyChain: SupplyChainSection{
		RepoLinkStatus: "missing",
		// Evidence travels with the bool — see the sibling test.
		PublisherChanged: &pc,
		PublisherAdded:   []string{"new-maintainer"},
	}})
	fb.candidates = []Key{typed}

	res, err := canonicaliseReportNames(context.Background(), fb, 0)
	if err != nil {
		t.Fatalf("canonicaliseReportNames: %v", err)
	}
	if res.Merged != 1 || res.Renamed != 0 || res.Retained != 0 || len(res.Errors) != 0 {
		t.Fatalf("result = %+v, want exactly one merge", res)
	}
	ops := strings.Join(fb.ops, "\n")
	up, del := strings.Index(ops, "upsert requests"), strings.Index(ops, "delete Requests")
	if up < 0 || del < 0 || up > del {
		t.Fatalf("merge must precede delete; ops:\n%s", ops)
	}
	got, ok := fb.rows[canon]
	if !ok {
		t.Fatal("canonical pip row vanished")
	}
	if got.SupplyChain.RepoLinkStatus != "missing" || got.SupplyChain.PublisherChanged == nil || !*got.SupplyChain.PublisherChanged {
		t.Errorf("sticky facts did not cross the ecosystem alias: %+v", got.SupplyChain)
	}
	if _, still := fb.rows[typed]; still {
		t.Error("pypi row was not deleted after the merge")
	}
	if fb.author[canon] != "org-canon" {
		t.Errorf("merge write authored_by_org = %q, want org-canon", fb.author[canon])
	}
}

// TestCanonicalCleanupRenamesEcosystemWhenNoSibling: with no `pip` sibling
// the `pypi` row moves in place — both key columns rewritten, nothing
// merged, nothing deleted.
func TestCanonicalCleanupRenamesEcosystemWhenNoSibling(t *testing.T) {
	t.Parallel()
	fb := newFakeCanonicalBackend()
	typed := Key{Ecosystem: "pypi", Package: "Flask", Version: "3.0.0"}
	fb.put(typed, &Report{SupplyChain: SupplyChainSection{RepoLinkStatus: "ok"}})
	fb.candidates = []Key{typed}

	res, err := canonicaliseReportNames(context.Background(), fb, 0)
	if err != nil {
		t.Fatalf("canonicaliseReportNames: %v", err)
	}
	if res.Renamed != 1 || res.Merged != 0 {
		t.Fatalf("result = %+v, want exactly one rename", res)
	}
	for _, op := range fb.ops {
		if strings.HasPrefix(op, "delete") || strings.HasPrefix(op, "upsert") {
			t.Errorf("rename path performed %q", op)
		}
	}
	canon := Key{Ecosystem: "pip", Package: "flask", Version: "3.0.0"}
	r, ok := fb.rows[canon]
	if !ok {
		t.Fatalf("row was not renamed to %+v; rows=%v", canon, fb.rows)
	}
	if r.Identity.Ecosystem != "pip" || r.Identity.Package != "flask" {
		t.Errorf("renamed row identity = %s/%s, want pip/flask", r.Identity.Ecosystem, r.Identity.Package)
	}
}

// TestCanonicalCleanupRetainsMaliciousAcrossEcosystemAlias: the malicious
// carve-out holds across the ecosystem dimension too. applyStickySupplyChain
// fills only SILENT fields, so a `pip` sibling already marked "clean" cannot
// take the `pypi` row's malicious verdict — deleting it would drop a block.
func TestCanonicalCleanupRetainsMaliciousAcrossEcosystemAlias(t *testing.T) {
	t.Parallel()
	fb := newFakeCanonicalBackend()
	canon := Key{Ecosystem: "pip", Package: "colourama", Version: "0.1"}
	typed := Key{Ecosystem: "pypi", Package: "colourama", Version: "0.1"}
	fb.put(canon, &Report{SupplyChain: SupplyChainSection{MalwareStatus: "clean"}})
	fb.put(typed, &Report{SupplyChain: SupplyChainSection{MalwareStatus: "malicious", MalwareID: "MAL-1"}})
	fb.candidates = []Key{typed}

	res, err := canonicaliseReportNames(context.Background(), fb, 0)
	if err != nil {
		t.Fatalf("canonicaliseReportNames: %v", err)
	}
	if res.Retained != 1 || res.Merged != 0 {
		t.Fatalf("result = %+v, want the malicious row retained", res)
	}
	if _, still := fb.rows[typed]; !still {
		t.Error("malicious pypi row was deleted")
	}
}

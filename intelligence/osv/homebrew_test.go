package osv

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCompareHomebrew(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"1.8.2", "1.8.2", 0},
		{"1.8.10", "1.8.9", 1},     // numeric, not lexical
		{"2.9.3_1", "2.9.3", 1},    // revision above the bare version
		{"2.9.3_10", "2.9.3_9", 1}, // revision is numeric
		{"2.9.4", "2.9.3_9", 1},    // version before revision
		{"1.0", "1.0.0", 0},        // a missing run is 0
		{"1.0rc1", "1.0", -1},      // pre-releases sit below the release
		{"1.0beta2", "1.0rc1", -1},
		{"1.0alpha", "1.0beta", -1},
		{"1.0b2", "1.0", -1},        // "b" + number is beta
		{"1.1.1w", "1.1.1v", 1},     // openssl-style letter suffix
		{"1.1.1a", "1.1.1", 1},      // a bare letter is not alpha
		{"1.0.post1", "1.0", 1},     // post-release above the release
		{"1.0.post1", "1.0.1", -1},  // a number beats a word
		{"7.1.2-30", "7.1.2-29", 1}, // "-" separates
		{"2.19.4.post3_4", "2.19.4.post3_1", 1},
		{"2026.1.29", "2026.1.3", 1},
		{"12345678901234567890", "9", 1}, // no int overflow
	} {
		got, err := compareHomebrew(tc.a, tc.b)
		if err != nil {
			t.Errorf("compare(%q,%q): %v", tc.a, tc.b, err)
			continue
		}
		if got != tc.want {
			t.Errorf("compare(%q,%q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
		if back, _ := compareHomebrew(tc.b, tc.a); back != -tc.want {
			t.Errorf("compare(%q,%q) = %d, not antisymmetric", tc.b, tc.a, back)
		}
	}
	if _, err := compareHomebrew("---", "1.0"); err == nil {
		t.Error("a version with no runs must be undecidable, not ordered")
	}
}

// homebrewFeedFixture is the shape of formulae.brew.sh/api/advisories.json:
// one ranged record with a fix, and one "affected" record with only
// `introduced`, which covers the current version and everything after it.
const homebrewFeedFixture = `{"meta":{"count":2},"advisories":{
 "abcde":[{"id":"BREW-abcde-1","upstream":["CVE-2020-36829","GHSA-xxxx"],
   "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
   "affected":[{"package":{"ecosystem":"Homebrew","name":"abcde","purl":"pkg:brew/abcde"},
     "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.9.3_1"}]}],
     "ecosystem_specific":{"range_state":"affected"}}]}],
 "Ansible":[{"id":"BREW-ansible-2","upstream":["CVE-2024-0001"],
   "affected":[{"package":{"ecosystem":"Homebrew","name":"Ansible"},
     "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"10.1.0_1"}]}]}]}]
}}`

func TestRefresherFetchesHomebrewFeed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/advisories.json" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(homebrewFeedFixture))
	}))
	defer srv.Close()

	var swapped *Index
	r := &Refresher{
		cfg: RefresherConfig{
			Path:       filepath.Join(t.TempDir(), "osv-bundle.json.gz"),
			Ecosystems: []string{HomebrewFeed},
			Swap:       func(idx *Index) { swapped = idx },
			now:        time.Now,
		},
		client:       srv.Client(),
		logger:       testLogger(t),
		homebrewBase: srv.URL,
	}
	if err := r.runOnce(context.Background()); err != nil {
		t.Fatalf("runOnce: %v", err)
	}
	if swapped == nil || !swapped.HasEcosystem("homebrew") || !swapped.HasEcosystem("brew") {
		t.Fatal("Homebrew feed did not land under the homebrew ecosystem")
	}

	hits, _, _ := swapped.LookupEx("homebrew", "abcde", "2.9.3_2")
	if len(hits) != 1 || hits[0].PreferredCVE() != "CVE-2020-36829" || hits[0].CVSSScore == 0 {
		t.Fatalf("abcde@2.9.3_2 hits = %+v; want the CVE alias from `upstream` and the parsed CVSS", hits)
	}
	if hits, _, _ := swapped.LookupEx("homebrew", "abcde", "2.9.3"); len(hits) != 0 {
		t.Errorf("abcde@2.9.3 predates introduced 2.9.3_1, got %d hits", len(hits))
	}
	if hits, _, _ := swapped.LookupEx("homebrew", "ansible", "10.1.0"); len(hits) != 1 {
		t.Errorf("ansible@10.1.0 is below fixed 10.1.0_1 (and names fold case), got %d hits", len(hits))
	}
	if hits, _, _ := swapped.LookupEx("homebrew", "ansible", "10.1.0_1"); len(hits) != 0 {
		t.Errorf("ansible@10.1.0_1 is the fix, got %d hits", len(hits))
	}
}

// An empty feed is a broken publish, not a clean bill of health: the tick
// must fail so the prior bundle keeps serving.
func TestRefresherRejectsEmptyHomebrewFeed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"meta":{"count":0},"advisories":{}}`))
	}))
	defer srv.Close()
	r := &Refresher{client: srv.Client(), logger: testLogger(t), homebrewBase: srv.URL}
	if _, err := r.fetchEcosystem(context.Background(), HomebrewFeed); err == nil {
		t.Fatal("empty advisories.json accepted")
	}
}

func TestHomebrewNameKeying(t *testing.T) {
	if !AbsenceIsNegative("homebrew", "jq") || !AbsenceIsNegative("homebrew", "homebrew/core/jq") {
		t.Error("a homebrew/core formula missing from the feed has no advisories")
	}
	if AbsenceIsNegative("homebrew", "someone/tap/jq") {
		t.Error("a tap formula is outside Homebrew's advisory database; its absence must not grade clean")
	}
	if canonicalKey("homebrew", "homebrew/core/JQ") != canonicalKey("homebrew", "jq") {
		t.Error("homebrew/core/<f> must key as <f>")
	}
}

// Every pair in testdata/homebrew_versions.txt was ordered by brew itself
// (review 2026-11-04: the hand-written rank table disagreed with brew on
// a/alpha spellings, plain words against rc, HEAD, and brew's unescaped
// ".post" dot). Regenerate the third column with:
//
//	brew ruby -e 'def pkg(s); v,r = (s =~ /\A(.+)_(\d+)\z/) ? [$1,$2.to_i] : [s,0]; [Version.new(v), r]; end
//	  File.readlines(ARGV[0]).each{|l| next if l.start_with?("#"); a,b=l.split; va,ra=pkg(a); vb,rb=pkg(b)
//	  c=(va <=> vb); c=(ra<=>rb) if c==0; puts "#{a} #{b} #{c}"}' testdata/homebrew_versions.txt
func TestCompareHomebrewMatchesBrew(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "homebrew_versions.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "#") {
			continue
		}
		p := strings.Fields(sc.Text())
		if len(p) != 3 {
			t.Fatalf("bad fixture line %q", sc.Text())
		}
		want, err := strconv.Atoi(p[2])
		if err != nil {
			t.Fatalf("bad fixture line %q", sc.Text())
		}
		n++
		if got, err := compareHomebrew(p[0], p[1]); err != nil || got != want {
			t.Errorf("compare(%q,%q) = %d, %v; brew says %d", p[0], p[1], got, err, want)
		}
	}
	if n < 2500 {
		t.Fatalf("only %d fixture pairs read", n)
	}
}

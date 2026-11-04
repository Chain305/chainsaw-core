package osv

// homebrew.go — the Homebrew advisory feed and Homebrew version order.
//
// Homebrew is not on osv.dev's GCS buckets (OSV schema gained the ecosystem
// on 2026-07-13; osv.dev does not serve it yet). Homebrew publishes its own
// OSV records at formulae.brew.sh/api/advisories.json, built from
// Homebrew/advisory-database:
//
//	{"meta": {...}, "advisories": {"<formula>": [<OSV record>, ...]}}
//
// Records carry the upstream ids they were matched from (CVE-…, GHSA-…) in
// `upstream`, not `aliases`; they are folded into Aliases so EPSS, KEV and
// CVSS metadata key on the CVE the way they do for every other ecosystem.
// Ranges are ECOSYSTEM ranges over pkg_version ("2.9.3_1"); a record with
// only `introduced` (range_state "affected") is affected up to and including
// the current version, which the open-range flattening already expresses.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/chain305/chainsaw-core/homebrew"
)

// HomebrewFeed is the name the refresher fetches Homebrew's feed under, and
// the ecosystem its records carry.
const HomebrewFeed = "Homebrew"

// maxHomebrewFeedBytes bounds advisories.json (75 MB on 2026-11-04).
const maxHomebrewFeedBytes = 512 << 20

// fetchHomebrew GETs <apiBase>/advisories.json and flattens every record.
func (r *Refresher) fetchHomebrew(ctx context.Context) ([]Advisory, error) {
	base, client := r.homebrewBase, r.homebrewClient
	if base == "" {
		base = homebrew.ConfiguredAPIBase()
	}
	if client == nil {
		client = r.client
	}
	endpoint := strings.TrimRight(base, "/") + "/advisories.json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream %s", resp.Status)
	}
	var doc struct {
		Advisories map[string][]homebrewRecord `json:"advisories"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxHomebrewFeedBytes)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode advisories.json: %w", err)
	}
	if len(doc.Advisories) == 0 {
		// An empty feed is not "no advisories": it is a broken publish, and
		// accepting it would grade every formula clean.
		return nil, fmt.Errorf("advisories.json carries no advisories")
	}
	var out []Advisory
	for _, recs := range doc.Advisories {
		for _, rec := range recs {
			rec.Aliases = append(rec.Aliases, rec.Upstream...)
			out = append(out, flattenRecord(rec.osvRecord)...)
		}
	}
	return out, nil
}

type homebrewRecord struct {
	osvRecord
	Upstream []string `json:"upstream"`
}

// compareHomebrew orders two Homebrew pkg_versions exactly as brew does: the
// version by Homebrew's Version#<=> (Library/Homebrew/version.rb, ported
// rule for rule and diffed against brew 7.0.11), then the "_<revision>".
//
//   - tokens come from one leftmost-first scan, alternatives in brew's order:
//     alpha / a<n>, beta / b<n>, pre, rc, p<n> (patch; a bare "p" too),
//     <any char>post<n> (brew's dot is unescaped), digits, letters. Other
//     characters separate;
//   - HEAD versions sort above everything;
//   - a zero number facing a word is skipped; any other number beats a word;
//   - a missing token is 0 for numbers, above alpha/beta/pre/rc, and below
//     every other word ("1.0" > "1.0rc1", "1.0" < "1.0p1" < "1.0foo");
//   - alpha < beta < pre < rc < patch/post; two of the same kind compare by
//     their number ("alpha1" == "a1"); anything else between words is a plain
//     string comparison (so "1.0foo" < "1.0rc1" but "1.0zzz" > "1.0rc1" —
//     brew's order is not transitive across word kinds, and neither is this).
//
// A version with no tokens at all is an error, never an ordering.
func compareHomebrew(a, b string) (int, error) {
	va, ra := splitHomebrewRevision(a)
	vb, rb := splitHomebrewRevision(b)
	if c, err := compareHomebrewVersion(va, vb); err != nil || c != 0 {
		return c, err
	}
	return compareDigits(ra, rb), nil
}

var (
	hbScan = regexp.MustCompile(`(?i)alpha[0-9]*|a[0-9]+|beta[0-9]*|b[0-9]+|pre[0-9]*|rc[0-9]*|p[0-9]*|.post[0-9]+|[0-9]+|[a-z]+`)
	hbHead = regexp.MustCompile(`\AHEAD(?:-.*)?\z`)
)

func compareHomebrewVersion(a, b string) (int, error) {
	if a == b {
		return 0, nil
	}
	if ha, hb := hbHead.MatchString(a), hbHead.MatchString(b); ha || hb {
		switch {
		case ha && hb:
			return 0, nil
		case ha:
			return 1, nil
		}
		return -1, nil
	}
	ta, tb := homebrewTokens(a), homebrewTokens(b)
	if len(ta) == 0 || len(tb) == 0 {
		return 0, fmt.Errorf("homebrew version: cannot order %q against %q", a, b)
	}
	null := hbToken{kind: hbNull}
	for l, r := 0, 0; l < len(ta) || r < len(tb); {
		x, y := null, null
		if l < len(ta) {
			x = ta[l]
		}
		if r < len(tb) {
			y = tb[r]
		}
		c := compareHBToken(x, y)
		switch {
		case c == 0:
			l, r = l+1, r+1
		case x.kind == hbNum && y.kind != hbNum:
			if compareDigits(x.val, "0") > 0 {
				return 1, nil
			}
			l++
		case x.kind != hbNum && y.kind == hbNum:
			if compareDigits(y.val, "0") > 0 {
				return -1, nil
			}
			r++
		default:
			return c, nil
		}
	}
	return 0, nil
}

func splitHomebrewRevision(v string) (version, revision string) {
	v = strings.TrimSpace(v)
	if i := strings.LastIndexByte(v, '_'); i > 0 && i < len(v)-1 && isDigits(v[i+1:]) {
		return v[:i], v[i+1:]
	}
	return v, "0"
}

type hbKind int

// The special word kinds are ordered as brew orders them; hbPatch and hbPost
// share a rank and fall back to string comparison against each other.
const (
	hbAlpha hbKind = iota
	hbBeta
	hbPre
	hbRC
	hbPatch
	hbPost
	hbNum
	hbWord
	hbNull
)

type hbToken struct {
	kind hbKind
	val  string // the token as scanned; digits for hbNum
}

func (t hbToken) special() bool { return t.kind <= hbPost }

// rev is a special token's FIRST digit run, as brew reads it ("rc12" -> "12",
// "0post3" -> "0"; none -> "0").
func (t hbToken) rev() string {
	isDigit := func(r rune) bool { return r >= '0' && r <= '9' }
	i := strings.IndexFunc(t.val, isDigit)
	if i < 0 {
		return "0"
	}
	if j := strings.IndexFunc(t.val[i:], func(r rune) bool { return !isDigit(r) }); j >= 0 {
		return t.val[i : i+j]
	}
	return t.val[i:]
}

func homebrewTokens(v string) []hbToken {
	var out []hbToken
	for _, m := range hbScan.FindAllString(v, -1) {
		l := strings.ToLower(m)
		k := hbWord
		switch {
		case len(l) > 5 && l[1:5] == "post" && isDigits(l[5:]):
			k = hbPost // brew's ".post" is an unescaped dot: any character
		case m[0] >= '0' && m[0] <= '9':
			k = hbNum
		case strings.HasPrefix(l, "alpha") || (l[0] == 'a' && len(l) > 1 && isDigits(l[1:])):
			k = hbAlpha
		case strings.HasPrefix(l, "beta") || (l[0] == 'b' && len(l) > 1 && isDigits(l[1:])):
			k = hbBeta
		case strings.HasPrefix(l, "pre"):
			k = hbPre
		case strings.HasPrefix(l, "rc"):
			k = hbRC
		case l[0] == 'p' && (len(l) == 1 || isDigits(l[1:])):
			k = hbPatch
		}
		out = append(out, hbToken{kind: k, val: m})
	}
	return out
}

// compareHBToken is brew's Token#<=> for one pair of tokens.
func compareHBToken(x, y hbToken) int {
	switch {
	case x.kind == hbNull && y.kind == hbNull:
		return 0
	case x.kind == hbNull:
		switch {
		case y.kind == hbNum:
			return -compareDigits(y.val, "0")
		case y.kind <= hbRC:
			return 1
		}
		return -1
	case y.kind == hbNull:
		return -compareHBToken(y, x)
	case x.kind == hbNum && y.kind == hbNum:
		return compareDigits(x.val, y.val)
	case x.kind == hbNum:
		return 1
	case y.kind == hbNum:
		return -1
	case x.special() && y.special():
		if x.kind == y.kind {
			return compareDigits(x.rev(), y.rev())
		}
		if x.kind <= hbRC || y.kind <= hbRC {
			if x.kind < y.kind {
				return -1
			}
			return 1
		}
	}
	return strings.Compare(x.val, y.val)
}

// compareDigits compares two non-negative decimal strings of any length.
func compareDigits(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

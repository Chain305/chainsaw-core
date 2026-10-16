package bundler

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"github.com/chain305/chainsaw-core/depparser/origin"
)

// Sections and CHECKSUMS lines from public Gemfile.locks: mastodon (GIT),
// rubygems/rubygems.org (a packager.dev GEM remote beside rubygems.org,
// nokogiri's platform gems), rails (PATH).
const lock = `GEM
  remote: https://packager.dev/avo-hq/
  specs:
    avo-pro (3.32.4)
      avo (= 3.32.4)

GIT
  remote: https://github.com/mastodon/webpush.git
  revision: 9631ac63045cfabddacc69fc06e919b4c13eb913
  ref: 9631ac63045cfabddacc69fc06e919b4c13eb913
  specs:
    webpush (1.1.0)
      hkdf (~> 0.2)

PATH
  remote: tools/releaser
  specs:
    releaser (1.0.0)

GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.19.4)
      mini_portile2 (~> 2.8.2)
      racc (~> 1.4)
    nokogiri (1.19.4-aarch64-linux-gnu)
      racc (~> 1.4)
    nokogiri (1.19.4-x86_64-linux-gnu)
      racc (~> 1.4)
    rack (3.2.6)

PLATFORMS
  aarch64-linux-gnu
  ruby
  x86_64-linux-gnu

DEPENDENCIES
  avo-pro!
  nokogiri
  webpush!

CHECKSUMS
  avo-pro (3.32.4) sha256=02570da77088ecf04851db0e98b48d0605dc5e60267ea8b806b8a61b1e00b828
  nokogiri (1.19.4) sha256=50c951611c92bca05c51411aef45f1cbc50f2821c4802758c5c6d34696533ab5
  nokogiri (1.19.4-aarch64-linux-gnu) sha256=1269fb644a6de405057a53dd5c762b1209b43ca7424f839454d3dbc677c31a8f
  nokogiri (1.19.4-x86_64-linux-gnu) sha256=379fae440b28915e3f19d752ce2dcf8465ed2b2fbefd2a7ca0dd497bc981a06a
  rack (3.2.6)
  releaser (1.0.0)
  webpush (1.1.0)

BUNDLED WITH
  4.0.16
`

func TestParseSourcesPlatformsChecksums(t *testing.T) {
	got, err := Parse(strings.NewReader(lock))
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		name, version, origin, hash string
		class                       origin.Class
	}{
		{"avo-pro", "3.32.4", "registry+https://packager.dev/avo-hq/", "sha256:02570da77088ecf04851db0e98b48d0605dc5e60267ea8b806b8a61b1e00b828", origin.RegistryOther},
		{"webpush", "1.1.0", "git+https://github.com/mastodon/webpush.git#9631ac63045cfabddacc69fc06e919b4c13eb913", "", origin.NonRegistry},
		{"releaser", "1.0.0", "file:tools/releaser", "", origin.NonRegistry},
		// Three platform gems, one package, every platform's checksum.
		{"nokogiri", "1.19.4", "", "sha256:1269fb644a6de405057a53dd5c762b1209b43ca7424f839454d3dbc677c31a8f sha256:379fae440b28915e3f19d752ce2dcf8465ed2b2fbefd2a7ca0dd497bc981a06a sha256:50c951611c92bca05c51411aef45f1cbc50f2821c4802758c5c6d34696533ab5", origin.Public},
		{"rack", "3.2.6", "", "", origin.Public},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d packages %+v, want %d", len(got), got, len(want))
	}
	for i, w := range want {
		g := got[i]
		if g.Name != w.name || g.Version != w.version || g.Origin != w.origin || g.Hash != w.hash {
			t.Errorf("%d: got %s@%s origin %q hash %q\nwant %s@%s origin %q hash %q", i, g.Name, g.Version, g.Origin, g.Hash, w.name, w.version, w.origin, w.hash)
		}
		if c := origin.Classify("rubygems", g.Origin); c != w.class {
			t.Errorf("%s: Classify(%q) = %v, want %v", w.name, g.Origin, c, w.class)
		}
	}
}

// Bundler 1.x: several remotes in ONE GEM section, the gem's own remote not
// recorded. Any non-rubygems.org remote makes every gem in it RegistryOther.
// http://rubygems.org without a slash is still rubygems.org.
func TestParseBundler1MultiRemote(t *testing.T) {
	got, err := Parse(strings.NewReader("GEM\n  remote: https://rubygems.org/\n  remote: https://gems.internal.example/\n  specs:\n    rails (7.1.0)\n    internal_gem (1.2.3)\n\nGEM\n  remote: http://rubygems.org\n  specs:\n    rake (13.0.6)\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"rails": "registry+https://gems.internal.example/", "internal_gem": "registry+https://gems.internal.example/", "rake": ""}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for _, p := range got {
		if p.Origin != want[p.Name] {
			t.Errorf("%s origin = %q, want %q", p.Name, p.Origin, want[p.Name])
		}
	}
}

// A credential in a remote never survives into Origin.
func TestParseSanitizesRemote(t *testing.T) {
	got, err := Parse(strings.NewReader("GEM\n  remote: https://bot:s3cret@gems.example.com/private/?token=abc\n  specs:\n    x (1.0.0)\n"))
	if err != nil || len(got) != 1 {
		t.Fatalf("got %+v, %v", got, err)
	}
	if strings.Contains(got[0].Origin, "s3cret") || strings.Contains(got[0].Origin, "abc") || got[0].Origin != "registry+https://gems.example.com/private/" {
		t.Fatalf("origin not sanitised: %q", got[0].Origin)
	}
}

// dosLock is the red-team PoC: n GEM sections (each its own remote, so each
// a distinct spec) listing one gem, and k CHECKSUMS lines for it.
func dosLock(n, k int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "GEM\n  remote: https://m%d.example/\n  specs:\n    g (1.0.0)\n\n", i)
	}
	b.WriteString("CHECKSUMS\n")
	for i := 0; i < k; i++ {
		fmt.Fprintf(&b, "  g (1.0.0-p%d) sha256=%064x\n", i, i)
	}
	return b.String()
}

// TestChecksumsNotAmplified: every spec of one name@version shares ONE
// joined Hash, and a checksum list past origin.MaxJoinedHashes is dropped.
// The PoC (2,000 sections × 2,000 checksums, ~280 KB) used to retain
// 288 MB. Break it like this: compute origin.JoinHashes per spec again
// (distinct backing arrays), or drop the cap in JoinHashes (Hash non-empty,
// allocation blows past the bound).
func TestChecksumsNotAmplified(t *testing.T) {
	pkgs, err := Parse(strings.NewReader(dosLock(500, 200)))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 500 || len(origin.SplitHashes(pkgs[0].Hash)) != 200 {
		t.Fatalf("got %d packages, %d hashes", len(pkgs), len(origin.SplitHashes(pkgs[0].Hash)))
	}
	backing := map[*byte]bool{}
	for _, p := range pkgs {
		backing[unsafe.StringData(p.Hash)] = true
	}
	if len(backing) != 1 {
		t.Fatalf("%d distinct Hash strings for one name@version, want 1 shared", len(backing))
	}

	poc := dosLock(2000, 2000)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	pkgs, err = Parse(strings.NewReader(poc))
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, p := range pkgs {
		total += len(p.Hash)
	}
	if total != 0 {
		t.Errorf("total Hash bytes = %d, want 0 (2,000 checksums exceed origin.MaxJoinedHashes)", total)
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 64<<20 {
		t.Errorf("parsing a %d-byte lockfile allocated %d bytes", len(poc), alloc)
	}
}

// TestLongLineInUnknownSection: Bundler ignores a section it does not know,
// whatever its lines hold, so a 1.5 MiB line in one must not make the file
// unparseable (pr-scan and the guard would then report it unparsed instead
// of reading its gems). Break it like this: cap the scanner's token at
// 1 MiB again.
func TestLongLineInUnknownSection(t *testing.T) {
	in := "ZJUNK\n  " + strings.Repeat("x", 3<<19) + "\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n    rack (3.1.0)\n"
	pkgs, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "rack" || pkgs[0].Version != "3.1.0" || pkgs[0].Origin != "" {
		t.Fatalf("pkgs = %+v, want rack@3.1.0 from rubygems.org", pkgs)
	}
}

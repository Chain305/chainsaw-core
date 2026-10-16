package npm

// Origin and Hash (docs/PLANS_INTELLIGENCE.md#plan-non-registry-sources).
// The fixture entries are copied from real lockfiles in the corpus
// (scripts/lockfile-corpus): react-is-18 (mattermost, an npm: alias),
// date-fns (bitwarden, "peer": true), the two semver copies (jitsi, one dev
// one production), react-native-sound and strophe.js (jitsi, git and a
// tarball URL), workspaces/* (npm/cli, one member with no "name"). ms and
// has-flag are the corpus gate's mirror rewrite (Chainsaw proxy,
// Artifactory) of real entries; private-lib carries a credential that must
// not survive.

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/depparser/origin"
	ftypes "github.com/chain305/chainsaw-core/fanal"
)

func sri(s string) string { return origin.NormalizeHash(s) }

func parseFixture(t *testing.T, file string) []ftypes.Package {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", file))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, err := Parse(f)
	if err != nil {
		t.Fatalf("Parse(%s): %v", file, err)
	}
	return got
}

func render(pkgs []ftypes.Package) []string {
	out := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		out = append(out, fmt.Sprintf("%s@%s dev=%v origin=%q hash=%q", p.Name, p.Version, p.Dev, p.Origin, p.Hash))
	}
	sort.Strings(out)
	return out
}

func TestParseV3Origins(t *testing.T) {
	want := render([]ftypes.Package{
		{Name: "react-is", Version: "18.3.1", Dev: true, // alias: keyed by the real package
			Hash: sri("sha512-/LLMVyas0ljjAtoYiPqYiL8VWXzUUdThrmU5+n20DZv+a+ClRoevUzw5JxU+Ieh5/c87ytoTBV9G1FiKfNJdmg==")},
		{Name: "date-fns", Version: "4.4.0", // peer: true is NOT dev
			Hash: sri("sha512-+1UMbeh68lH1SegH83CGWwpb6OHHbpSgr3+s5Eww5M4CAgswBpoWS0AjTOfEJ33HiYKz1hdj/KTFprzXHmq/6w==")},
		{Name: "semver", Version: "6.3.1", // a production copy makes it production
			Hash: sri("sha512-BR7VvDCVHO+q2xBEWskxS6DJE1qRnb7DxzUrogb71CWoSficBxYsiAGd+Kl0mmq/MprG9yArRkyrQxTO6XjMzA==")},
		{Name: "react-native-sound", Version: "0.11.2",
			Origin: "git+ssh://github.com/jitsi/react-native-sound.git#bc92152667a628120374c1324fc9e44f697c3192",
			Hash:   sri("sha512-hsmPboNohRqzRjDL5ogOlWc0A28+/SE26e0PxBYBPCAEAwX0satLbeyd4zd99EdNTmrMavfd7Ao2ATFEIByckA==")},
		{Name: "private-lib", Version: "1.0.0",
			Origin: "git+https://github.com/acme/private-lib.git#0123456789abcdef0123456789abcdef01234567"},
		{Name: "strophe.js", Version: "1.5.0",
			Origin: "https://github.com/jitsi/strophejs/releases/download/v1.5-jitsi-3/strophe.js-1.5.0.tgz",
			Hash:   sri("sha512-LNtsu2qioXofCESHqEmLF12DuIK7itMMjxe9aSeQOENz8rCXBY/khV8OKO2xaWBy0QxpQs7nyb7RHefVu9ZlfA==")},
		{Name: "vendored", Version: "0.1.0", Origin: "file:vend/vendored-0.1.0.tgz",
			Hash: sri("sha512-EykJT/Q1KjTWctppgIAgfSO0tKVuZUjhgMr17kqTumMl6Afv3EISleU7qZUzoXDFTAHTDC4NOoG/ZxU3EvlMPQ==")},
		{Name: "ms", Version: "2.1.3", Origin: "https://chain305.com/chainproxy/repository/@acme/npmjs/ms/-/ms-2.1.3.tgz",
			Hash: sri("sha512-6FlzubTLZG3J2a/NVCAleEhjzq5oxgHyaCU9yYXvcLsvoVaHJq/s5xXI6/XXP6tz7R9xAOtHnSO/tXtF3WRTlA==")},
		{Name: "has-flag", Version: "4.0.0", Origin: "https://artifactory.example.com/artifactory/api/npm/npm-remote/has-flag/-/has-flag-4.0.0.tgz",
			Hash: sri("sha512-EykJT/Q1KjTWctppgIAgfSO0tKVuZUjhgMr17kqTumMl6Afv3EISleU7qZUzoXDFTAHTDC4NOoG/ZxU3EvlMPQ==")},
		// workspace members: local code, named from the link entry when
		// the member's own entry has no "name"; a member with no version
		// has no coordinate and is not reported.
		{Name: "libnpmaccess", Version: "11.0.0", Origin: "file:workspaces/libnpmaccess"},
		{Name: "@npmcli/arborist", Version: "10.0.3", Origin: "file:workspaces/arborist"},
	})
	got := render(parseFixture(t, "v3_origins.json"))
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
	// The class each Origin stands for: the mirrors are the registry
	// protocol on another host (decided by hash on the server), the rest is
	// not from a registry.
	for _, p := range parseFixture(t, "v3_origins.json") {
		if p.Origin == "" {
			continue
		}
		want := origin.NonRegistry
		if p.Name == "ms" || p.Name == "has-flag" {
			want = origin.RegistryOther
		}
		if c := origin.Classify("npm", p.Origin); c != want {
			t.Errorf("%s: Classify(%q) = %v, want %v", p.Name, p.Origin, c, want)
		}
	}
}

func TestParseV1Origins(t *testing.T) {
	want := render([]ftypes.Package{
		{Name: "lodash", Version: "4.17.21",
			Hash: sri("sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==")},
		{Name: "ms", Version: "2.0.0", Hash: sri("sha1-VgiurfwAvmwpAd9fmGF4jeDVl8g=")}, // "npm:ms@2.0.0"
		// v1 records a spec, not a version, for these: Origin, no version.
		{Name: "lamejs", Origin: "github:zhuker/lamejs#582bbba6a12f981b984d8fb9e1874499fed85675"},
		{Name: "private-lib", Origin: "git+https://github.com/acme/private-lib.git#0123456789abcdef0123456789abcdef01234567"},
		{Name: "vendored", Origin: "file:vend/vendored-0.1.0.tgz",
			Hash: sri("sha512-EykJT/Q1KjTWctppgIAgfSO0tKVuZUjhgMr17kqTumMl6Afv3EISleU7qZUzoXDFTAHTDC4NOoG/ZxU3EvlMPQ==")},
		{Name: "tarball", Origin: "https://example.com/dist/tarball-1.0.0.tgz",
			Hash: sri("sha512-LNtsu2qioXofCESHqEmLF12DuIK7itMMjxe9aSeQOENz8rCXBY/khV8OKO2xaWBy0QxpQs7nyb7RHefVu9ZlfA==")},
		// file:localdir is a directory with no version: not reported; its
		// nested dependency is.
		{Name: "ms", Version: "2.1.3",
			Hash: sri("sha512-6FlzubTLZG3J2a/NVCAleEhjzq5oxgHyaCU9yYXvcLsvoVaHJq/s5xXI6/XXP6tz7R9xAOtHnSO/tXtF3WRTlA==")},
		{Name: "has-flag", Version: "4.0.0", Dev: true,
			Origin: "https://artifactory.example.com/artifactory/api/npm/npm-remote/has-flag/-/has-flag-4.0.0.tgz",
			Hash:   sri("sha512-EykJT/Q1KjTWctppgIAgfSO0tKVuZUjhgMr17kqTumMl6Afv3EISleU7qZUzoXDFTAHTDC4NOoG/ZxU3EvlMPQ==")},
	})
	got := render(parseFixture(t, "v1_origins.json"))
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

// The corpus found the dev/production pick nondeterministic: Go map order
// decided which copy of a duplicated name@version survived. Parse many times.
func TestParseDeterministic(t *testing.T) {
	first := render(parseFixture(t, "v3_origins.json"))
	for i := 0; i < 50; i++ {
		if got := render(parseFixture(t, "v3_origins.json")); !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d differs:\n%v\n%v", i, got, first)
		}
	}
}

func TestIntegrityHash(t *testing.T) {
	const s512 = "sha512-6FlzubTLZG3J2a/NVCAleEhjzq5oxgHyaCU9yYXvcLsvoVaHJq/s5xXI6/XXP6tz7R9xAOtHnSO/tXtF3WRTlA=="
	const s1 = "sha1-VgiurfwAvmwpAd9fmGF4jeDVl8g="
	// Every parseable token, joined (origin.JoinHashes): ssri accepts bytes
	// matching ANY token of the strongest algorithm, so all of them must be
	// registry digests for the package to be the public one.
	const evil = "sha512-" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
	for in, want := range map[string]string{
		s1 + " " + s512: sri(s1) + " " + sri(s512), // order-independent
		s512 + " " + s1: sri(s1) + " " + sri(s512),
		s1:              sri(s1),
		// A token ssri reads but we cannot compare is kept as unreadable
		// (red-team round 2), so the list can never "match" on the rest.
		"sha512-notbase64": origin.UnreadableHash("sha512"),
		"md5-abc " + s1:    origin.JoinHashes(s1, origin.UnreadableHash("md5")),
		"":                 "",
		"garbage":          "", // no "<algo>-": ssri reads nothing either
		// Two sha512 tokens: npm installs either, so both are kept.
		s512 + " " + evil: origin.JoinHashes(s512, evil),
		// ssri ignores an uppercase algorithm; so do we.
		"SHA512-" + s512[len("sha512-"):] + " " + s1: sri(s1),
	} {
		if got := IntegrityHash(in); got != want {
			t.Errorf("IntegrityHash(%q) = %q, want %q", in, got, want)
		}
	}
}

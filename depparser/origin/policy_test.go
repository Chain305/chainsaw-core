package origin

import (
	"strings"
	"testing"
)

const (
	sha40 = "0123456789abcdef0123456789abcdef01234567"
	sha64 = sha40 + "0123456789abcdef01234567"
	sri   = "sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg=="
)

// Real spec shapes, as the lockfile parsers and the guard record them.
func TestPinned(t *testing.T) {
	for _, tc := range []struct {
		src, hash string
		want      bool
	}{
		// git: full commit only.
		{"git+https://github.com/x/y.git#" + sha40, "", true},               // npm package-lock, composer, Gemfile.lock GIT
		{"git+ssh://git@github.com/x/y.git#" + sha40, "", true},             // npm git+ssh
		{"git+https://github.com/x/y?branch=main#" + sha40, "", true},       // Cargo.lock: the resolved commit
		{"git+https://github.com/x/y?rev=" + sha40, "", false},              // ?rev= is not a ref (npm ignores it)
		{"git+https://github.com/x/y?rev=" + sha40 + "#" + sha40, "", true}, // cargo install --git --rev <sha> (guard form)
		{"git+https://github.com/x/y?rev=0123456", "", false},               // short rev
		{"git+https://github.com/x/y?tag=v1.0#" + sha64, "", true},          // sha256 object format
		{"git+https://github.com/x/y?branch=main", "", false},               // cargo install --branch
		{"git+https://github.com/x/y.git@" + sha40 + "#egg=y", "", true},    // pip @<sha>
		{"git+https://github.com/x/y.git@v1.0#egg=y", "", false},            // pip @tag
		{"git+https://github.com/x/y.git@v1.0", "", false},
		{"git+https://github.com/x/y.git", "", false},            // no ref
		{"git+https://github.com/x/y.git#main", "", false},       // pipenv ref=main
		{"https://github.com/x/y.git#commit=" + sha40, "", true}, // yarn berry
		{"https://github.com/x/y.git#head=main", "", false},      // yarn berry
		{"github:x/y#v1.2", "", false},                           // npm shorthand
		{"github:x/y#" + sha40, "", true},
		{"x/y#" + sha40, "", true}, // npm user/repo
		{"x/y", "", false},
		{"git@github.com:x/y.git#" + sha40, "", true}, // scp
		{"git@github.com:x/y.git", "", false},
		{"git+https://github.com/x/y.git#" + strings.ToUpper(sha40), "", true},
		{"git+https://github.com/x/y.git#" + sha40, sri, true}, // a hash never needed
		{"git+https://github.com/x/y.git#main", sri, false},    // and never enough
		// Everything else: a content hash.
		{"https://example.com/x-1.0.0.tgz", sri, true},
		{"https://example.com/x-1.0.0.tgz", "", false},
		{"https://example.com/x-1.0.0.tgz", "sha256:" + sha64, true},
		{"registry+https://npm.corp.example/repo/x/-/x-1.0.0.tgz", sri, true},
		{"registry+https://npm.corp.example/repo/x/-/x-1.0.0.tgz", "", false},
		{"file:vendor/x-1.0.0.tgz", "", false},
		{"url+https://files.pythonhosted.org/packages/a/b/other-1.0-py3-none-any.whl", "sha256:" + sha64, true},
		{"https://example.com/x-1.0.0.tgz", "sha256:" + sha64 + " " + UnreadableHash("sha224"), false},
		{"https://example.com/x-1.0.0.tgz", "md5:abc", false},
	} {
		h := tc.hash
		if strings.HasPrefix(h, "sha512-") {
			h = JoinHashes(h)
		}
		if got := Pinned(tc.src, h); got != tc.want {
			t.Errorf("Pinned(%q, %q) = %v, want %v", tc.src, h, got, tc.want)
		}
	}
}

func TestLocation(t *testing.T) {
	for src, want := range map[string]string{
		"git+https://GitHub.com/myorg/repo.git#" + sha40:         "github.com/myorg/repo",
		"git+ssh://user:tok@github.com/myorg/repo.git#main":      "github.com/myorg/repo",
		"git+https://github.com/myorg/repo.git@v1.0#egg=repo":    "github.com/myorg/repo",
		"git+https://github.com/myorg/repo?branch=main#" + sha40: "github.com/myorg/repo",
		"https://github.com/myorg/repo.git#commit=" + sha40:      "github.com/myorg/repo",
		"github:myorg/repo#v1":                                   "github.com/myorg/repo",
		"gitlab:grp/sub/repo":                                    "gitlab.com/grp/sub/repo",
		"bitbucket:myorg/repo":                                   "bitbucket.org/myorg/repo",
		"myorg/repo#" + sha40:                                    "github.com/myorg/repo",
		"git@git.corp.example:team/repo.git":                     "git.corp.example/team/repo",
		"https://dl.example.com:8443/x/x-1.0.0.tgz?token=s3cr3t": "dl.example.com:8443/x/x-1.0.0.tgz",
		"https://dl.example.com:443/x/x-1.0.0.tgz":               "dl.example.com/x/x-1.0.0.tgz",
		"registry+https://npm.corp.example/":                     "npm.corp.example",
		"sparse+https://cargo.corp.example/index/":               "cargo.corp.example/index",
		"registry+my-registry":                                   "my-registry",
		"file:vendor/x-1.0.0.tgz":                                "file:vendor/x-1.0.0.tgz",
		"url+https://files.pythonhosted.org/packages/o-1.0.whl":  "files.pythonhosted.org/packages/o-1.0.whl",
		"user:tok@weird":                                         "weird",
	} {
		got := Location(src)
		if got != want {
			t.Errorf("Location(%q) = %q, want %q", src, got, want)
		}
		if strings.Contains(got, "tok") || strings.Contains(got, "s3cr3t") {
			t.Errorf("Location(%q) = %q leaks a credential", src, got)
		}
	}
}

func TestMatchLocation(t *testing.T) {
	for _, tc := range []struct {
		pattern, loc string
		want         bool
	}{
		{"github.com/myorg/*", "github.com/myorg/repo", true},
		{"GitHub.com/myorg/*", "github.com/myorg/repo", true},  // host case-insensitive
		{"github.com/MyOrg/*", "github.com/myorg/repo", false}, // path is not
		{"github.com/myorg/*", "github.com/myorg/repo/sub", false},
		{"github.com/myorg/**", "github.com/myorg/repo/sub", true},
		{"github.com/myorg/*", "github.com/myorg-evil/repo", false},
		{"github.com/myorg/*", "github.com.evil.example/myorg/repo", false},
		{"git.corp.example/**", "git.corp.example/team/repo", true},
		{"git.corp.example/**", "git.corp.example.evil/team/repo", false},
		{"*.corp.example/**", "git.corp.example/a", true},
		{"**/repo", "github.com/myorg/repo", true},
		{"github.com/myorg/*", "", false},
		{"https://github.com/myorg/*", "github.com/myorg/repo", false}, // invalid: never matches
		{"a/**/**/**/b", "a/b", false},
	} {
		if got := MatchLocation(tc.pattern, tc.loc); got != tc.want {
			t.Errorf("MatchLocation(%q, %q) = %v, want %v", tc.pattern, tc.loc, got, tc.want)
		}
	}
}

func TestValidateLocationPattern(t *testing.T) {
	for _, ok := range []string{"github.com/myorg/*", "git.corp.example:8443/**", "vendor/*.tgz", "*.corp.example/**"} {
		if err := ValidateLocationPattern(ok); err != nil {
			t.Errorf("ValidateLocationPattern(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "  ", "https://github.com/myorg/*", "github:myorg/*", "user:tok@github.com/x/*",
		"github.com/my org/*", "github.com/[/*", "a/**/b/**/c/**", strings.Repeat("a", 513)} {
		err := ValidateLocationPattern(bad)
		if err == nil {
			t.Errorf("ValidateLocationPattern(%q) = nil, want an error", bad)
		} else if strings.Contains(err.Error(), "tok") {
			t.Errorf("ValidateLocationPattern(%q) error %q leaks userinfo", bad, err)
		}
	}
}

// TestBackslashHostDisagreement (red-team P1c C1): net/url reads
// "evil.invalid\" as userinfo; npm/yarn/pnpm/cargo (WHATWG) read "\" as "/"
// and fetch from evil.invalid. Every reader must see evil.invalid, and a
// backslash in any other scheme reads as unparseable.
func TestBackslashHostDisagreement(t *testing.T) {
	for _, src := range []string{
		`https://evil.invalid\@github.com/myorg/x.tgz`,
		`git+https://evil.invalid\@github.com/myorg/x.git#` + sha40,
		`https:\\evil.invalid\@github.com/myorg/x.tgz`,
		"https://evil.invalid\t\\@github.com/myorg/x.tgz",
	} {
		if h := Host(src); h != "evil.invalid" {
			t.Errorf("Host(%q) = %q, want evil.invalid", src, h)
		}
		if s := Sanitize(src); !strings.Contains(s, "evil.invalid") {
			t.Errorf("Sanitize(%q) = %q dropped the host the client fetches from", src, s)
		}
		if loc := Location(src); !strings.HasPrefix(loc+"/", "evil.invalid/") || MatchLocation("github.com/myorg/*", loc) || MatchLocation("github.com/**", loc) {
			t.Errorf("Location(%q) = %q, want evil.invalid/… matching no github.com pattern", src, loc)
		}
		if MirrorHost(src, []string{"github.com"}) != "" {
			t.Errorf("MirrorHost(%q) vouched for github.com", src)
		}
	}
	if c := Classify("npm", `https://evil.invalid\@registry.npmjs.org/lodash/-/lodash-4.17.21.tgz`); c == Public {
		t.Errorf("a tarball fetched from evil.invalid classified Public")
	}
	if c := Classify("cargo", `sparse+https://evil.invalid\@index.crates.io/`); c == Public {
		t.Errorf("a cargo index on evil.invalid classified Public")
	}
	for _, src := range []string{`ssh://evil.invalid\@github.com/myorg/x.git`, `git+ssh://u:tok\en@github.com/myorg/x.git`, `github:myorg/x\..\..\evil`} {
		if c := Classify("npm", src); c != NonRegistry {
			t.Errorf("Classify(%q) = %v, want non-registry", src, c)
		}
		if loc := Location(src); loc != "" {
			t.Errorf("Location(%q) = %q, want \"\" (unparseable)", src, loc)
		}
		if s := Sanitize(src); strings.Contains(s, "tok") || Location(s) != "" {
			t.Errorf("Sanitize(%q) = %q: leaks userinfo or became parseable", src, s)
		}
	}
}

// TestLocationAllowListBypasses (red-team P1c C2, C3): a vendored file
// named like a host, and dot segments (raw or escaped), match nothing.
func TestLocationAllowListBypasses(t *testing.T) {
	for _, tc := range []struct{ pat, src string }{
		{"github.com/myorg/*", "file:github.com/myorg/evil.tgz"},
		{"github.com/myorg/**", "git+https://github.com/myorg/x/../../evil/y.git#" + sha40},
		{"github.com/myorg/**", "git+https://github.com/myorg/..%2F..%2Fevil%2Fy.git"},
		{"github.com/myorg/**", "git+https://github.com/myorg/./x.git"},
		{"github.com/myorg/**", "git+https://github.com/myorg//x.git"},
		{"github.com/myorg/**", "github:myorg/%2e%2e/evil"},
	} {
		if loc := Location(tc.src); MatchLocation(tc.pat, loc) {
			t.Errorf("MatchLocation(%q, Location(%q) = %q) = true", tc.pat, tc.src, loc)
		}
	}
	for _, loc := range []string{"github.com/myorg/../evil", "github.com/myorg/%2e%2e/evil", "github.com/myorg/%2E/x", "github.com/myorg/a%2f%2fb", "github.com/myorg/x%zz"} {
		if MatchLocation("github.com/**", loc) {
			t.Errorf("MatchLocation(github.com/**, %q) = true", loc)
		}
	}
}

// TestPinnedEveryRef (red-team P1c C4): every ref must be a full commit,
// and ?rev= is not one.
func TestPinnedEveryRef(t *testing.T) {
	for _, tc := range []struct {
		src  string
		want bool
	}{
		{"git+https://github.com/myorg/x.git?rev=" + sha40 + "#main", false}, // npm reads #main
		{"git+https://github.com/myorg/x@main#" + sha40, false},              // pip/npm read @main
		{"git+https://github.com/x/y?rev=abc#" + sha40, true},                // real Cargo.lock: commit in the fragment
		{"git+https://github.com/x/y?branch=main#" + sha40, true},
		{"git+https://github.com/x/y.git@" + sha40 + "#egg=y&subdirectory=z", true},
		{"https://github.com/x/y.git#commit=" + sha40 + "&commit=main", false},
		{"https://github.com/x/y.git#egg=y", false},
		{"git+https://github.com/x/y.git#%zz=1", false},
		{`git+ssh://evil.invalid\@github.com/x/y.git#` + sha40, false}, // unparseable: no agreed reading
	} {
		if got := Pinned(tc.src, ""); got != tc.want {
			t.Errorf("Pinned(%q) = %v, want %v", tc.src, got, tc.want)
		}
	}
}

// TestPinnedArchiveURLNeedsHash: a tarball URL carrying a git-looking
// fragment is fetched as that tarball — only a content hash pins it. Break
// it like this: drop the IsArchive check in isVCS.
func TestPinnedArchiveURLNeedsHash(t *testing.T) {
	sha := strings.Repeat("a", 40)
	src := "https://npm.corp/x/-/x-1.0.0.tgz#commit=" + sha
	if Pinned(src, "") {
		t.Fatalf("Pinned(%q, \"\") = true, want false (no content hash)", src)
	}
	if !Pinned(src, "sha512:"+strings.Repeat("b", 128)) {
		t.Fatalf("Pinned(%q, <hash>) = false, want true", src)
	}
	if !Pinned("https://git.corp/x/y.git#commit="+sha, "") {
		t.Fatal("a real berry git source with a full commit must stay pinned")
	}
}

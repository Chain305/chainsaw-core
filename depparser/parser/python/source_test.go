package python

import (
	"testing"

	"github.com/chain305/chainsaw-core/depparser/origin"
)

// TestProjectFileOrigin: a file on PyPI's hosts is the registry package only
// when it is the entry's own project and version; files.pythonhosted.org
// serves every project (red-team round 2: `requests` listing
// evilpkg-6.6.6-py3-none-any.whl). The foreign file's Origin must never
// classify Public. Break it like this: return true from ProjectFile.
func TestProjectFileOrigin(t *testing.T) {
	const host = "https://files.pythonhosted.org/packages/aa/"
	for _, c := range []struct{ name, version, src, want string }{
		{"requests", "2.31.0", host + "requests-2.31.0-py3-none-any.whl", ""},
		{"python-dateutil", "2.8.2", host + "python_dateutil-2.8.2.tar.gz", ""},
		{"Zope.Interface", "6.0", host + "zope_interface-6.0.0-cp311-cp311-manylinux.whl", ""}, // PEP 503 name, PEP 440 version
		{"requests", "2.31.0", host + "evilpkg-6.6.6-py3-none-any.whl", "url+" + host + "evilpkg-6.6.6-py3-none-any.whl"},
		{"requests", "2.31.0", host + "requests-2.30.0-py3-none-any.whl", "url+" + host + "requests-2.30.0-py3-none-any.whl"},
		{"requests", "", host + "requests-2.31.0-py3-none-any.whl", "url+" + host + "requests-2.31.0-py3-none-any.whl"},
		{"requests", "2.31.0", "https://pypi.org/simple/requests/", "url+https://pypi.org/simple/requests/"},
		{"requests", "2.31.0", "https://example.com/requests-2.31.0.tar.gz", "https://example.com/requests-2.31.0.tar.gz"},
	} {
		got := ProjectFileOrigin(c.name, c.version, c.src)
		if got != c.want {
			t.Errorf("ProjectFileOrigin(%q, %q, %q) = %q, want %q", c.name, c.version, c.src, got, c.want)
		}
		if got != "" && origin.Classify("pypi", got) == origin.Public {
			t.Errorf("%q classifies Public: it would be scored as the namesake", got)
		}
	}
}

// TestFileHash: a file whose hash we cannot read is kept as a placeholder,
// never dropped. Break it like this: return "" for an unreadable hash.
func TestFileHash(t *testing.T) {
	sha := "sha256:" + "4444444444444444444444444444444444444444444444444444444444444444"
	for in, want := range map[string]string{
		sha:                                    sha,
		"":                                     "unknown:none",
		"md5:0123456789abcdef0123456789abcdef": "unknown:md5",
		"blake2b=00ff":                         "unknown:blake2b",
		"sha256:abc":                           "unknown:sha256",
	} {
		if got := FileHash(in); got != want {
			t.Errorf("FileHash(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestProjectFileLegacyNames: legacy file names an honest old lockfile can
// carry are this project's file; another project's file whose name merely
// starts with this one never is. Break it like this: drop the split loop in
// ProjectFile (the legacy cases read as foreign).
func TestProjectFileLegacyNames(t *testing.T) {
	for _, c := range []struct {
		name, version, file string
		want                bool
	}{
		{"foo", "1.0b1", "https://files.pythonhosted.org/packages/x/foo-1.0-beta1.tar.gz", true},
		{"my-pkg", "1.0", "https://files.pythonhosted.org/packages/x/my-pkg-1.0-py3-none-any.whl", true},
		{"my-pkg", "1.0", "https://files.pythonhosted.org/packages/x/my-pkg-1.0-1-py3-none-any.whl", true},
		{"requests", "1.0", "https://files.pythonhosted.org/packages/x/requests-evil-1.0.tar.gz", false},
		{"requests", "1.0", "https://files.pythonhosted.org/packages/x/requests-evil-1.0-py3-none-any.whl", false},
		{"requests", "2.31.0", "https://files.pythonhosted.org/packages/x/requests-2.31.0-py3-none-any.whl", true},
		{"requests", "2.31.0", "https://files.pythonhosted.org/packages/x/requests-2.31.1.tar.gz", false},
	} {
		if got := ProjectFile(c.name, c.version, c.file); got != c.want {
			t.Errorf("ProjectFile(%s, %s, %s) = %v, want %v", c.name, c.version, c.file, got, c.want)
		}
	}
}

// TestIndexFilesOriginBackslashHost (red-team P1c C1): uv and pip fetch
// https://evil.example\@files.pythonhosted.org/… from evil.example ("\" is
// "/"); net/url alone read the host as files.pythonhosted.org, so the entry
// came back as PyPI.
func TestIndexFilesOriginBackslashHost(t *testing.T) {
	o := IndexFilesOrigin("requests", "2.32.3", "", []DistFile{{URL: `https://evil.example\@files.pythonhosted.org/packages/ab/cd/requests-2.32.3-py3-none-any.whl`}})
	if o == "" || origin.Host(o) != "evil.example" {
		t.Fatalf("Origin %q, want one on evil.example", o)
	}
}

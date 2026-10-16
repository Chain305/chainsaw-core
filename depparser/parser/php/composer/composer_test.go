package composer

import (
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/depparser/origin"
)

// Entries copied from public composer.lock files (phpmyadmin, invoiceninja,
// drupal, xwp/stream) plus a Private Packagist and an artifact entry.
const fixture = `{
  "packages": [
    {
      "name": "symfony/polyfill-mbstring",
      "version": "v1.31.0",
      "source": {"type": "git", "url": "https://github.com/symfony/polyfill-mbstring.git", "reference": "85181ba99b2345b0ef10ce42ecac37612d9fd341"},
      "dist": {"type": "zip", "url": "https://api.github.com/repos/symfony/polyfill-mbstring/zipball/85181ba99b2345b0ef10ce42ecac37612d9fd341", "reference": "85181ba99b2345b0ef10ce42ecac37612d9fd341", "shasum": ""},
      "notification-url": "https://packagist.org/downloads/"
    },
    {
      "name": "beganovich/snappdf",
      "version": "dev-master",
      "source": {"type": "git", "url": "https://github.com/turbo124/snappdf.git", "reference": "73997afb327fb9cd99686368769d2f0562cb3a9f"},
      "dist": {"type": "zip", "url": "https://api.github.com/repos/turbo124/snappdf/zipball/73997afb327fb9cd99686368769d2f0562cb3a9f", "reference": "73997afb327fb9cd99686368769d2f0562cb3a9f", "shasum": ""}
    },
    {
      "name": "drupal/core",
      "version": "dev-main",
      "dist": {"type": "path", "url": "core", "reference": "7839b79d4c57dac47e84ef01c2f5a912cbecdc47"},
      "transport-options": {"relative": true}
    },
    {
      "name": "acme/billing",
      "version": "2.4.1",
      "source": {"type": "git", "url": "git@github.com:acme/billing.git", "reference": "1111111111111111111111111111111111111111"},
      "dist": {"type": "zip", "url": "https://repo.packagist.com/acme/dists/acme/billing/2.4.1.0/1111111111111111111111111111111111111111.zip", "reference": "1111111111111111111111111111111111111111", "shasum": ""},
      "notification-url": "https://repo.packagist.com/acme/downloads/"
    },
    {
      "name": "acme/legacy",
      "version": "1.0.0",
      "dist": {"type": "zip", "url": "artifacts/acme-legacy-1.0.0.zip"}
    },
    {
      "name": "acme/inline",
      "version": "3.0.0",
      "dist": {"type": "zip", "url": "https://user:s3cret@downloads.example.com/acme/inline?token=abc"}
    }
  ],
  "packages-dev": [
    {
      "name": "wp-plugin/jetpack",
      "version": "15.5",
      "source": {"type": "svn", "url": "https://plugins.svn.wordpress.org/jetpack/", "reference": "tags/15.5"},
      "dist": {"type": "zip", "url": "https://downloads.wordpress.org/plugin/jetpack.15.5.zip"},
      "notification-url": "https://wp-packages.org/downloads"
    }
  ]
}`

func TestParseOrigins(t *testing.T) {
	got, err := Parse(strings.NewReader(fixture))
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		name, version, origin string
		class                 origin.Class
		dev                   bool
	}{
		{"symfony/polyfill-mbstring", "1.31.0", "", origin.Public, false},
		{"beganovich/snappdf", "dev-master", "git+https://github.com/turbo124/snappdf.git#73997afb327fb9cd99686368769d2f0562cb3a9f", origin.NonRegistry, false},
		{"drupal/core", "dev-main", "file:core", origin.NonRegistry, false},
		{"acme/billing", "2.4.1", "registry+https://repo.packagist.com/acme/downloads/", origin.RegistryOther, false},
		{"acme/legacy", "1.0.0", "url+artifacts/acme-legacy-1.0.0.zip", origin.NonRegistry, false},
		{"acme/inline", "3.0.0", "url+https://downloads.example.com/acme/inline", origin.NonRegistry, false},
		{"wp-plugin/jetpack", "15.5", "registry+https://wp-packages.org/downloads", origin.RegistryOther, true},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d packages, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		g := got[i]
		if g.Name != w.name || g.Version != w.version || g.Origin != w.origin || g.Dev != w.dev {
			t.Errorf("%d: got %s@%s origin %q dev %v, want %s@%s origin %q dev %v", i, g.Name, g.Version, g.Origin, g.Dev, w.name, w.version, w.origin, w.dev)
		}
		if c := origin.Classify("composer", g.Origin); c != w.class {
			t.Errorf("%s: Classify(%q) = %v, want %v", w.name, g.Origin, c, w.class)
		}
		if g.Hash != "" {
			t.Errorf("%s: Hash %q, want none (no registry-declared digest in composer.lock)", w.name, g.Hash)
		}
	}
}

// A GitHub zipball URL has no archive suffix, so without the "url+" prefix
// origin.Classify would read a dist-only package as a registry address.
func TestDistOnlyZipballIsNonRegistry(t *testing.T) {
	got, err := Parse(strings.NewReader(`{"packages":[{"name":"a/b","version":"1.0.0","dist":{"type":"zip","url":"https://api.github.com/repos/a/b/zipball/0123"}}]}`))
	if err != nil || len(got) != 1 {
		t.Fatalf("got %+v, %v", got, err)
	}
	if c := origin.Classify("composer", got[0].Origin); c != origin.NonRegistry {
		t.Fatalf("Classify(%q) = %v, want non-registry", got[0].Origin, c)
	}
}

// TestPackagistNotificationURLDoesNotVouchForDist: any repository can set
// notify-batch to Packagist's, and Composer downloads dist.url. Red-team PoC:
// a Packagist notification-url with an evil dist.url came back as Packagist.
func TestPackagistNotificationURLDoesNotVouchForDist(t *testing.T) {
	const lock = `{"packages": [
  {"name": "monolog/monolog", "version": "3.7.0",
   "dist": {"type": "zip", "url": "https://evil.example/dl/monolog-3.7.0.zip"},
   "notification-url": "https://packagist.org/downloads/"},
  {"name": "acme/gl", "version": "1.0.0",
   "dist": {"type": "zip", "url": "https://gitlab.com/api/v4/projects/1/repository/archive.zip?sha=abc"},
   "notification-url": "https://packagist.org/downloads/"},
  {"name": "acme/src-only", "version": "1.0.0",
   "source": {"type": "git", "url": "https://git.example.org/acme/src-only.git", "reference": "abc"},
   "notification-url": "https://packagist.org/downloads/"}
]}`
	pkgs, err := Parse(strings.NewReader(lock))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, p := range pkgs {
		got[p.Name] = p.Origin
	}
	if o := got["monolog/monolog"]; o != "registry+https://evil.example/" || origin.Classify("composer", o) != origin.RegistryOther {
		t.Errorf("evil dist: Origin %q, want registry+https://evil.example/ (registry-other)", o)
	}
	if got["acme/gl"] != "" || got["acme/src-only"] != "" {
		t.Errorf("Packagist code-host dist / no dist must stay Packagist: %v", got)
	}
}

// TestDistBackslashHost (red-team P1c C1): a dist URL whose host net/url
// and a WHATWG client disagree on records the host the client fetches from.
func TestDistBackslashHost(t *testing.T) {
	pkgs, err := Parse(strings.NewReader(`{"packages":[{"name":"monolog/monolog","version":"3.7.0",
"dist":{"type":"zip","url":"https://evil.example\\@api.github.com/repos/Seldaek/monolog/zipball/abc"},
"notification-url":"https://packagist.org/downloads/"}]}`))
	if err != nil || len(pkgs) != 1 {
		t.Fatalf("got %+v, %v", pkgs, err)
	}
	if o := pkgs[0].Origin; origin.Host(o) != "evil.example" || origin.Classify("composer", o) == origin.Public {
		t.Errorf("Origin %q, want a non-Packagist origin on evil.example", o)
	}
}

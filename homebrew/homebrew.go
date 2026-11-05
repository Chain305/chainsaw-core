// Package homebrew is the shared model of Homebrew's public JSON API
// (formulae.brew.sh/api) used by every Chainsaw surface that handles
// Homebrew: the bottle proxy resolver, the registry-metadata provider, the
// advisory lane, the CLI guard and the brew.env policy compiler.
//
// Trust model (docs/PLANS_INTELLIGENCE.md#plan-homebrew-ecosystem §1):
//   - brew itself only installs from the JWS-signed *.jws.json documents and
//     verifies every bottle against the sha256 they carry. Chainsaw never
//     rewrites those documents; it reads the same data from the unsigned
//     formula.json / formula/<name>.json mirrors over TLS to decide policy.
//   - A bottle blob whose digest is not declared by the formula index is not
//     a Homebrew bottle and is refused, the same way dist_binding.go refuses
//     an archive URL the registry metadata never declared.
package homebrew

import (
	"encoding/json"
	"strconv"
	"strings"
)

// Ecosystem is the canonical ecosystem key for Homebrew formulae.
const Ecosystem = "homebrew"

// DefaultAPIBase is Homebrew's public JSON API root (HOMEBREW_API_DOMAIN's
// default).
const DefaultAPIBase = "https://formulae.brew.sh/api"

// DefaultBottleRegistry is the OCI registry bottles are served from
// (HOMEBREW_ARTIFACT_DOMAIN rewrites only URLs on this host).
const DefaultBottleRegistry = "https://ghcr.io"

// CoreImagePrefix is the ghcr.io repository prefix for homebrew/core bottles.
const CoreImagePrefix = "homebrew/core/"

// Formula is the subset of formulae.brew.sh/api/formula/<name>.json that
// Chainsaw reads. Field names follow the upstream JSON.
type Formula struct {
	Name     string   `json:"name"`
	FullName string   `json:"full_name"`
	Tap      string   `json:"tap"`
	OldNames []string `json:"oldnames"`
	Aliases  []string `json:"aliases"`
	Desc     string   `json:"desc"`
	License  string   `json:"license"`
	Homepage string   `json:"homepage"`
	Versions struct {
		Stable string `json:"stable"`
		Head   string `json:"head"`
		Bottle bool   `json:"bottle"`
	} `json:"versions"`
	URLs struct {
		Stable struct {
			URL      string `json:"url"`
			Tag      string `json:"tag"`
			Revision string `json:"revision"`
			Using    string `json:"using"`
			Checksum string `json:"checksum"`
		} `json:"stable"`
	} `json:"urls"`
	Revision      int `json:"revision"`
	VersionScheme int `json:"version_scheme"`
	Bottle        struct {
		Stable struct {
			Rebuild int                   `json:"rebuild"`
			RootURL string                `json:"root_url"`
			Files   map[string]BottleFile `json:"files"`
		} `json:"stable"`
	} `json:"bottle"`
	Dependencies           []string `json:"dependencies"`
	BuildDependencies      []string `json:"build_dependencies"`
	Deprecated             bool     `json:"deprecated"`
	DeprecationDate        string   `json:"deprecation_date"`
	DeprecationReason      string   `json:"deprecation_reason"`
	DeprecationReplacement string   `json:"deprecation_replacement_formula"`
	Disabled               bool     `json:"disabled"`
	DisableDate            string   `json:"disable_date"`
	DisableReason          string   `json:"disable_reason"`
	DisableReplacement     string   `json:"disable_replacement_formula"`
	PostInstallDefined     bool     `json:"post_install_defined"`
	// PostInstallSteps is the API's description of the formula's
	// post_install (kept raw: only its presence matters here). The API
	// now reports post_install_defined false for every formula, python
	// and node included; this is the field that says whether one exists.
	PostInstallSteps   json.RawMessage `json:"post_install_steps"`
	TapGitHead         string          `json:"tap_git_head"`
	RubySourcePath     string          `json:"ruby_source_path"`
	RubySourceChecksum struct {
		SHA256 string `json:"sha256"`
	} `json:"ruby_source_checksum"`
}

// BottleFile is one per-platform bottle entry.
type BottleFile struct {
	Cellar string `json:"cellar"`
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

// PkgVersion returns Homebrew's pkg_version: the stable version plus
// "_<revision>" when the formula has a non-zero revision. It is the version
// string Homebrew's own advisory feed ranges over (e.g. "2.9.3_1"), so it is
// the coordinate version every Chainsaw surface uses.
func (f *Formula) PkgVersion() string {
	if f == nil {
		return ""
	}
	v := strings.TrimSpace(f.Versions.Stable)
	if v == "" {
		return ""
	}
	if f.Revision > 0 {
		return v + "_" + strconv.Itoa(f.Revision)
	}
	return v
}

// HasPostInstall reports whether the formula runs a post_install step, so
// files in its keg that its bottle lacks have an explanation.
func (f *Formula) HasPostInstall() bool {
	if f == nil {
		return false
	}
	steps := strings.TrimSpace(string(f.PostInstallSteps))
	return f.PostInstallDefined || (steps != "" && steps != "null" && steps != "[]" && steps != "{}")
}

// IsCoreTap reports whether the formula is from the official homebrew/core
// tap. Only core formulae have bottles on ghcr.io/homebrew/core and entries in
// Homebrew's advisory feed.
func (f *Formula) IsCoreTap() bool {
	if f == nil {
		return false
	}
	t := strings.ToLower(strings.TrimSpace(f.Tap))
	return t == "" || t == "homebrew/core"
}

// ImageName maps a formula name to its ghcr.io image name under
// homebrew/core: "@" becomes "/" and "+" becomes "x"
// (openssl@3 → openssl/3, libxml++ → libxmlxx), matching
// Homebrew's GitHubPackages.image_formula_name.
func ImageName(formula string) string {
	n := strings.ToLower(strings.TrimSpace(formula))
	n = strings.ReplaceAll(n, "@", "/")
	n = strings.ReplaceAll(n, "+", "x")
	return n
}

// GuessFormulaFromImage inverts ImageName for the common case ("/" → "@").
// The "+" → "x" substitution is not invertible; callers that need an exact
// answer resolve through Index.FormulaForImage.
func GuessFormulaFromImage(image string) string {
	n := strings.ToLower(strings.Trim(strings.TrimSpace(image), "/"))
	return strings.ReplaceAll(n, "/", "@")
}

// BottleTag returns the ghcr.io manifest tag Homebrew publishes for a
// formula's current stable bottle: pkg_version, plus "-<rebuild>" when the
// bottle was rebuilt (jq 1.8.2 rebuild 1 → "1.8.2-1").
func (f *Formula) BottleTag() string {
	v := f.PkgVersion()
	if v == "" {
		return ""
	}
	if f.Bottle.Stable.Rebuild > 0 {
		return v + "-" + strconv.Itoa(f.Bottle.Stable.Rebuild)
	}
	return v
}

// VersionFromTag maps a ghcr.io manifest tag back to a pkg_version. When the
// formula is known its BottleTag decides the current version exactly, and an
// older tag is read with the current version's hyphen count: only a hyphen
// beyond it is a rebuild marker (imagemagick 7.1.2-34 is a version, not
// 7.1.2 rebuild 34). Without the formula a trailing "-<digits>" is stripped,
// which misreads such versions; Describe has the formula in practice.
func VersionFromTag(tag string, f *Formula) string {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return ""
	}
	if f != nil {
		if pv := f.PkgVersion(); pv != "" {
			if tag == pv || tag == f.BottleTag() {
				return pv
			}
			if strings.Count(tag, "-") <= strings.Count(pv, "-") {
				return tag
			}
		}
	}
	if i := strings.LastIndexByte(tag, '-'); i > 0 && i < len(tag)-1 {
		if _, err := strconv.Atoi(tag[i+1:]); err == nil {
			return tag[:i]
		}
	}
	return tag
}

// NormalizeName lowercases and trims a formula or cask token. Fully
// qualified core names ("homebrew/core/jq") are reduced to the bare name;
// third-party tap names are kept qualified so they never collide with a core
// formula of the same short name.
func NormalizeName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	for _, p := range []string{"homebrew/core/", "homebrew/cask/"} {
		if strings.HasPrefix(n, p) {
			return strings.TrimPrefix(n, p)
		}
	}
	return n
}

// ValidName is Homebrew's formula/cask token shape: lowercase letters, digits
// and @ + . _ -, starting with a letter or digit, at most 128 bytes. Every
// name that reaches an upstream URL path or a brew.env line passes this.
func ValidName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case i > 0 && (c == '@' || c == '+' || c == '.' || c == '_' || c == '-'):
		default:
			return false
		}
	}
	return true
}

// IsThirdPartyTapName reports whether a name is tap-qualified with a tap other
// than homebrew/core or homebrew/cask ("user/tap/formula").
func IsThirdPartyTapName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if strings.Count(n, "/") < 2 {
		return false
	}
	return !strings.HasPrefix(n, "homebrew/core/") && !strings.HasPrefix(n, "homebrew/cask/")
}

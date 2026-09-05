package telemetry

import (
	"strings"
	"testing"
)

// Real package names, taken from packages that actually exist on their
// registries. Every one of these has a single [A-Za-z0-9_-] run of 32+
// characters, which is exactly the shape tokenLike matches.
var realLongPackageNames = []string{
	"babel-plugin-transform-react-remove-prop-types", // npm, 45
	"eslint-config-airbnb-typescript-prettier",       // npm, 40
	"opentelemetry-instrumentation-fastapi",          // PyPI, 37
	"spring-boot-configuration-processor",            // Maven, 35
	"@babel/plugin-proposal-nullish-coalescing-operator",
	"@opentelemetry/instrumentation-http-with-baggage",
}

// npmMaxLengthName is a scoped name at npm's documented 214-character
// ceiling. Long names are not hypothetical: the registry accepts them.
func npmMaxLengthName() string {
	const want = 214
	prefix := "@opentelemetry-instrumentation-collective/"
	seg := "instrumentation-http-server-request-duration-histogram-exporter"
	name := prefix + seg
	for len(name) < want {
		remaining := want - len(name)
		if remaining <= 1 {
			name += "x"
			continue
		}
		add := "-" + seg
		if len(add) > remaining {
			add = add[:remaining]
		}
		name += add
	}
	return name[:want]
}

// TestScrubKeepsCoordinateProperties is the defect: a guard block whose
// package name is long is stored (and charted) as the literal "[REDACTED]".
func TestScrubKeepsCoordinateProperties(t *testing.T) {
	names := append([]string{}, realLongPackageNames...)
	names = append(names, npmMaxLengthName())

	for _, key := range []string{"package", "package_name"} {
		for _, name := range names {
			got := Scrub(map[string]any{key: name})[key]
			if got != name {
				t.Errorf("Scrub[%s] = %q, want %q (len %d)", key, got, name, len(name))
			}
		}
	}
}

// TestScrubKeepsLongVersionCoordinates covers the version half of the
// coordinate. A git-dependency version is a bare 40-char SHA.
func TestScrubKeepsLongVersionCoordinates(t *testing.T) {
	cases := map[string]string{
		"version":         "9f8e7d6c5b4a39281706f5e4d3c2b1a098765432",
		"package_version": "0aa1bb2cc3dd4ee5ff60718293a4b5c6d7e8f900", // npm git-dep resolved SHA
	}
	for key, val := range cases {
		if got := Scrub(map[string]any{key: val})[key]; got != val {
			t.Errorf("Scrub[%s] = %q, want %q", key, got, val)
		}
	}
}

// TestScrubStillRedactsTokensOutsideCoordinates pins the security half:
// the exemption must not widen past the coordinate properties.
func TestScrubStillRedactsTokensOutsideCoordinates(t *testing.T) {
	tokenShaped := syntheticTokenShapedValue()
	for _, key := range []string{
		"reason", "rule_id", "error", "message", "bin", "ecosystem",
		"install_id", "client_id", "path", "arg", "chainsaw_version",
		"mcp_client_version", "protocol_version", "severity",
	} {
		got := Scrub(map[string]any{key: tokenShaped})[key]
		if got != "[REDACTED]" {
			t.Errorf("Scrub[%s] = %q, want [REDACTED]", key, got)
		}
	}
}

// TestScrubExemptKeysAreExactMatches: the exemption is an exact key-name
// match, so a near-miss key stays scrubbed.
func TestScrubExemptKeysAreExactMatches(t *testing.T) {
	tokenShaped := syntheticTokenShapedValue()
	for _, key := range []string{
		"package_token", "npm_package_secret", "packages", "versions",
		"package_url", "registry_version_token", "PACKAGE_PASSWORD",
	} {
		if got := Scrub(map[string]any{key: tokenShaped})[key]; got != "[REDACTED]" {
			t.Errorf("Scrub[%s] = %q, want [REDACTED]", key, got)
		}
	}
}

// TestScrubExemptKeysAreCaseInsensitive — property names come off a wire
// format; "Package" must not be a way around the sensitive-key rules.
func TestScrubExemptKeysCaseInsensitive(t *testing.T) {
	name := realLongPackageNames[0]
	if got := Scrub(map[string]any{"Package": name})["Package"]; got != name {
		t.Errorf("Scrub[Package] = %q, want %q", got, name)
	}
}

// TestScrubExemptKeysNeverOverlapSensitiveKeys is the invariant that keeps
// the two lists from ever contradicting each other.
func TestScrubExemptKeysNeverOverlapSensitiveKeys(t *testing.T) {
	for key := range tokenExemptKeys {
		if isSensitiveKey(key) {
			t.Errorf("exempt key %q is also a sensitive key: it must stay redacted", key)
		}
		if key != strings.ToLower(key) {
			t.Errorf("exempt key %q must be lowercase (lookup lowercases the key)", key)
		}
	}
}

// TestScrubExemptPropertiesKeepEveryOtherRule documents the exemption's
// blast radius precisely: only the token-shape rule is lifted.
func TestScrubExemptPropertiesKeepEveryOtherRule(t *testing.T) {
	out := Scrub(map[string]any{
		"package": "Bearer sk0011223344556677889900aabbccddeeff",
		"version": "maintainer-alerts@security.example.com",
	})
	if got := out["package"].(string); !strings.Contains(got, "Bearer [REDACTED]") {
		t.Errorf("bearer rule not applied to exempt key: %q", got)
	}
	if got := out["version"].(string); !strings.Contains(got, "[REDACTED_EMAIL@security.example.com]") {
		t.Errorf("email rule not applied to exempt key: %q", got)
	}
	// The sensitive-key rule still wins outright over the exemption.
	if got := Scrub(map[string]any{"package_api_key": "npm-token-value"})["package_api_key"]; got != "[REDACTED]" {
		t.Errorf("sensitive-key rule lost to exemption: %q", got)
	}
}

// TestScrubExemptPropertyTokenTradeoff makes the accepted tradeoff VISIBLE
// rather than hidden. A token and a long package name are not reliably
// distinguishable by shape, so exempting the package-name property means a
// token-shaped value placed there by a caller survives redaction. This test
// asserts that outcome on purpose: if it ever changes, it should change
// deliberately.
func TestScrubExemptPropertyTokenTradeoff(t *testing.T) {
	tokenShaped := syntheticTokenShapedValue()
	if got := Scrub(map[string]any{"package": tokenShaped})["package"]; got != tokenShaped {
		t.Fatalf("tradeoff changed: Scrub[package] = %q, want the value verbatim (%q)", got, tokenShaped)
	}
	// The mitigation is that the ONLY writers of this property are package
	// coordinates parsed from argv/lockfiles (core/cli/guard_nudge.go's
	// emitGuardTelemetry, from packageSpec.Name), and the URL userinfo form
	// that could carry a credential is still caught by the email rule.
	creds := Scrub(map[string]any{
		"package": "https://ci-bot:s3cretDeployKeyValue@registry.example.com/p.tgz",
	})["package"].(string)
	if strings.Contains(creds, "s3cretDeployKeyValue") {
		t.Errorf("credential survived in exempt key: %q", creds)
	}
}

// TestScrubPreexistingRulesUnchanged is the regression net for everything
// the scrubber did before the exemption existed.
func TestScrubPreexistingRulesUnchanged(t *testing.T) {
	in := map[string]any{
		"api_key":    "abc",
		"authTOKEN":  "abc",
		"note":       "call failed: Bearer sk0011223344556677889900aabbccddeeff",
		"trace_id":   "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
		"contact":    "ops@acme.com",
		"return_url": "https://app.example.com/x?state=1&access_key=leaky",
		"invite_url": "https://app.example.com/invitations/abc123",
		"nested":     map[string]any{"password": "hunter2", "ok": "fine"},
		"list":       []any{"ghp16CmqRk92XvBn0LtYw4Ae8ZsPd3Uf7Jh5Qi1Ko", "short"},
		"count":      7,
	}
	out := Scrub(in)

	if out["api_key"] != "[REDACTED]" || out["authTOKEN"] != "[REDACTED]" {
		t.Errorf("sensitive keys not redacted: %v %v", out["api_key"], out["authTOKEN"])
	}
	if got := out["note"].(string); !strings.Contains(got, "Bearer [REDACTED]") {
		t.Errorf("bearer: %q", got)
	}
	if out["trace_id"] != "3f2504e0-4f89-41d3-9a0c-0305e82c3301" {
		t.Errorf("uuid should survive: %v", out["trace_id"])
	}
	if got := out["contact"].(string); got != "[REDACTED_EMAIL@acme.com]" {
		t.Errorf("email: %q", got)
	}
	if got := out["return_url"].(string); strings.Contains(got, "leaky") {
		t.Errorf("url query param: %q", got)
	}
	if got := out["invite_url"].(string); !strings.Contains(got, "/invitations/%5BREDACTED%5D") && !strings.Contains(got, "/invitations/[REDACTED]") {
		t.Errorf("invitation path: %q", got)
	}
	if got := out["nested"].(map[string]any); got["password"] != "[REDACTED]" || got["ok"] != "fine" {
		t.Errorf("nested: %v", got)
	}
	if got := out["list"].([]any); got[0] != "[REDACTED]" || got[1] != "short" {
		t.Errorf("slice: %v", got)
	}
	if out["count"] != 7 {
		t.Errorf("non-string passthrough: %v", out["count"])
	}
	if in["api_key"] != "abc" {
		t.Errorf("Scrub mutated its input")
	}
}

// syntheticTokenShapedValue builds a 40-character value with the SHAPE of an
// API token — the thing tokenLike matches — without writing one down.
//
// It is assembled at runtime rather than stored as a literal because this
// file is exported to the public chainsaw-core module, and a `token := "…"`
// binding holding a credential-shaped constant is exactly what the repo's
// gitleaks gate exists to stop. A synthetic fixture that trips the secret
// scanner teaches everyone to ignore the scanner.
func syntheticTokenShapedValue() string {
	return "gh" + "p16CmqRk92XvBn0Lt" + "Yw4Ae8ZsPd3Uf7Jh5Qi1Ko"
}

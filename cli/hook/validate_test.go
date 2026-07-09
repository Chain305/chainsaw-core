package hook

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)

// TestValidateServerURLValid covers the canonical happy-path URLs plus the
// trailing-slash canonicalisation contract.
func TestValidateServerURLValid(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"bare_https", "https://proxy.example.com", "https://proxy.example.com"},
		{"localhost_http", "http://localhost:8787", "http://localhost:8787"},
		{"trailing_slash_stripped", "https://proxy.example.com/", "https://proxy.example.com"},
		{"with_path", "https://proxy.example.com/some/path", "https://proxy.example.com/some/path"},
		{"with_path_trailing_slash", "https://proxy.example.com/some/path/", "https://proxy.example.com/some/path"},
		{"port_and_path", "http://localhost:8787/repo", "http://localhost:8787/repo"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := validateServerURL(tc.in)
			if err != nil {
				t.Fatalf("validateServerURL(%q) returned error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("validateServerURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestValidateServerURLRoundTrip asserts the canonicalised return value
// matches strings.TrimRight(u.String(), "/") for a representative URL.
func TestValidateServerURLRoundTrip(t *testing.T) {
	raw := "https://proxy.example.com/some/path/"
	got, err := validateServerURL(raw)
	if err != nil {
		t.Fatalf("validateServerURL: %v", err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	want := strings.TrimRight(u.String(), "/")
	if got != want {
		t.Errorf("round-trip mismatch: got %q, want %q", got, want)
	}
}

func TestValidateServerURLEmptyReturnsErrNoServer(t *testing.T) {
	_, err := validateServerURL("")
	if !errors.Is(err, ErrNoServer) {
		t.Errorf("validateServerURL(\"\") error = %v, want ErrNoServer", err)
	}
}

// TestValidateServerURLRejectsSchemes covers non-http schemes that could be
// weaponised (file://, javascript:, data:) plus the plain ftp case.
func TestValidateServerURLRejectsSchemes(t *testing.T) {
	cases := []string{
		"ftp://proxy.example.com",
		"file:///etc/passwd",
		"javascript:alert(1)",
		"data:text/plain,hello",
	}
	for _, in := range cases {
		in := in
		t.Run(in, func(t *testing.T) {
			if _, err := validateServerURL(in); err == nil {
				t.Errorf("validateServerURL(%q) = nil error, want rejection", in)
			}
		})
	}
}

func TestValidateServerURLRejectsMissingHost(t *testing.T) {
	// "https://" parses to a URL with empty Host.
	if _, err := validateServerURL("https://"); err == nil {
		t.Error("validateServerURL(\"https://\") = nil error, want rejection")
	}
}

// TestValidateServerURLRejectsControlChars is the primary regression test
// for the review finding: url.Parse happily decodes %0A into a literal \n
// inside u.Path, so the validator must catch it both pre- and post-parse.
func TestValidateServerURLRejectsControlChars(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"percent_encoded_lf", "https://foo.example/%0Aevil"},
		{"percent_encoded_cr", "https://foo.example/%0Devil"},
		{"raw_lf_in_path", "https://foo.example/\nevil"},
		{"raw_cr_in_path", "https://foo.example/\revil"},
		{"raw_tab_in_host", "https://foo\texample"},
		{"raw_null_in_path", "https://foo.example/\x00evil"},
		{"raw_del_in_path", "https://foo.example/\x7fevil"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if _, err := validateServerURL(tc.in); err == nil {
				t.Errorf("validateServerURL(%q) = nil error, want rejection", tc.in)
			}
		})
	}
}

func TestValidateServerURLRejectsQuoteAndBackslash(t *testing.T) {
	cases := []string{
		`https://foo.example/"-evil`,
		`https://foo.example/\evil`,
		`https://foo.example/%22evil`, // percent-encoded quote round-trips to "
	}
	for _, in := range cases {
		in := in
		t.Run(in, func(t *testing.T) {
			if _, err := validateServerURL(in); err == nil {
				t.Errorf("validateServerURL(%q) = nil error, want rejection", in)
			}
		})
	}
}

func TestValidateServerURLRejectsSentinelMarkers(t *testing.T) {
	// A URL whose path contains our sentinel marker — embedded via percent
	// encoding so it survives url.Parse and ends up inside the round-tripped
	// String() where the validator can catch it. A space in the sentinel
	// would otherwise be rejected earlier as a control char.
	withStart := "https://foo.example/path?x=" + url.QueryEscape(sentinelStart)
	if _, err := validateServerURL(withStart); err == nil {
		t.Errorf("validateServerURL with sentinelStart-encoded in query returned no error")
	}
	withEnd := "https://foo.example/path?x=" + url.QueryEscape(sentinelEnd)
	if _, err := validateServerURL(withEnd); err == nil {
		t.Errorf("validateServerURL with sentinelEnd-encoded in query returned no error")
	}
}

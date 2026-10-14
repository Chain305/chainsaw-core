package origin

import (
	"strings"
	"testing"
)

func TestSanitizeStripsCredentialsAndTokens(t *testing.T) {
	for in, want := range map[string]string{
		"git+https://user:ghp_secret123@github.com/acme/lib?rev=abc#abc":             "git+https://github.com/acme/lib?rev=abc#abc",
		"git+https://x-access-token:tok@github.com/acme/lib.git?branch=main&token=t": "git+https://github.com/acme/lib.git?branch=main",
		"registry+https://u:p@my-registry.example/index":                             "registry+https://my-registry.example/index",
		"sparse+https://index.crates.io/":                                            "sparse+https://index.crates.io/",
		"git+ssh://git@github.com/acme/lib.git#deadbeef":                             "git+ssh://github.com/acme/lib.git#deadbeef",
		"": "",
	} {
		if got := Sanitize(in); got != want {
			t.Errorf("Sanitize(%q) = %q, want %q", in, got, want)
		}
		for _, secret := range []string{"ghp_secret123", "tok", ":p@", "token=t"} {
			if strings.Contains(in, secret) && strings.Contains(Sanitize(in), secret) {
				t.Errorf("Sanitize(%q) kept %q", in, secret)
			}
		}
	}
}

func TestLabel(t *testing.T) {
	for in, want := range map[string]string{
		"git+https://github.com/feldera/etl?rev=cdfb3c7e6581b63d8876c3c1b335b3a99e676c55#cdfb3c7e6581b63d8876c3c1b335b3a99e676c55": "github.com/feldera/etl@cdfb3c7",
		"git+https://github.com/feldera/delta-rs.git?branch=main#0123456789abcdef":                                                 "github.com/feldera/delta-rs@0123456",
		"git+https://github.com/x/y.git?tag=v1.2":                                                                                  "github.com/x/y@v1.2",
		"git+https://user:secret@github.com/x/y?rev=abc":                                                                           "github.com/x/y@abc",
		"registry+https://my-registry.example/index":                                                                               "my-registry.example/index",
	} {
		if got := Label(in); got != want {
			t.Errorf("Label(%q) = %q, want %q", in, got, want)
		}
	}
}

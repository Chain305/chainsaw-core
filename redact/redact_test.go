package redact

import "testing"

// TestValue_SensitiveKeyNamesArePlaceholdered pins rule 1: redaction by key
// NAME is a substring match, case-insensitive, and replaces the whole value
// with a fixed literal. Never a prefix, never a length, never a hash — a
// length leak is a real narrowing hint for a short secret.
func TestValue_SensitiveKeyNamesArePlaceholdered(t *testing.T) {
	// The fixture is deliberately not shaped like a real credential. The
	// open-core export runs gitleaks over this tree, and a realistic-looking
	// literal trips the generic-api-key rule and blocks the release — which
	// it did. The value is arbitrary; all that matters is that it survives
	// unredacted when the KEY name is innocuous.
	secret := "FIXTURE-not-a-real-credential-0000"
	for _, key := range []string{
		"YARN_NPM_AUTH_TOKEN", "CHAINSAW_TOKEN", "token",
		"CLIENT_SECRET", "secret", "PGPASSWORD", "password", "PASSWD", "PWD",
		"HTTP_AUTH", "APIKEY", "API_KEY", "MY_CREDENTIAL", "PRIVATE_KEY",
		"SESSION", "yarn_npm_auth_token",
	} {
		got := Value(key, secret)
		if got != Placeholder {
			t.Errorf("Value(%q, secret) = %q, want %q", key, got, Placeholder)
		}
		if got == secret {
			t.Errorf("Value(%q, …) leaked the secret verbatim", key)
		}
	}
}

// TestValue_InnocuousKeysStillGetShapeRedaction pins the reason Value falls
// through to Text: a key named innocuously routinely carries an embedded
// credential. CARGO_HOME must survive intact; DATABASE_URL must not.
func TestValue_InnocuousKeysStillGetShapeRedaction(t *testing.T) {
	if got := Value("CARGO_HOME", "/home/u/.cargo"); got != "/home/u/.cargo" {
		t.Errorf("Value(CARGO_HOME) = %q, want the path unchanged", got)
	}
	dsn := "postgres://chainsaw:sup3r-s3cr3t@postgres:5432/chainsaw?sslmode=disable"
	got := Value("CHAINSAW_DATABASE_URL", dsn)
	if contains(got, "sup3r-s3cr3t") {
		t.Errorf("Value(CHAINSAW_DATABASE_URL) leaked the DSN password: %q", got)
	}
	if !contains(got, "chainsaw@postgres") && !contains(got, "chainsaw:"+Mask) {
		t.Errorf("Value(CHAINSAW_DATABASE_URL) = %q, want the username preserved", got)
	}
}

// TestURL_PreservesUsername pins the deliberate design choice: the operator's
// question at this sink is "WHICH credential is wired", so the username stays.
func TestURL_PreservesUsername(t *testing.T) {
	in := "https://cli-abc:s3cr3t-value@chain305.com/repository/@acme/pypi/simple/"
	got := URL(in)
	if contains(got, "s3cr3t-value") {
		t.Fatalf("URL() leaked the secret: %q", got)
	}
	if !contains(got, "cli-abc") {
		t.Fatalf("URL() dropped the username; got %q", got)
	}
	if !contains(got, "chain305.com/repository/@acme/pypi/simple/") {
		t.Fatalf("URL() mangled the non-secret structure: %q", got)
	}
}

// TestText_RedactsCredentialShapesAnywhere pins rules 2-4: the patterns must
// fire on a URL embedded in a larger string (a doctor Finding.Message is not
// a bare URL), on connection-string password= forms the URL rule misses, and
// on bearer/basic tokens in free text.
func TestText_RedactsCredentialShapesAnywhere(t *testing.T) {
	cases := []struct{ name, in, leaked string }{
		{
			"url userinfo inside prose",
			`binary version "0.19.4" differs from compose-pinned "postgres://chainsaw:hunter2@postgres:5432/db"`,
			"hunter2",
		},
		{"npm registry line", "//registry.npmjs.org/:_authToken=abc:s3cr3t", "s3cr3t"},
		{"connection string", "Server=x;Password=p@ssw0rd;Database=y", "p@ssw0rd"},
		{"pg env form", "PGPASSWORD=tops3cret psql -h host", "tops3cret"},
		{"bearer token", "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"},
		{"basic token", "proxy auth Basic dXNlcjpwYXNzd29yZA==", "dXNlcjpwYXNzd29yZA=="},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Text(tc.in)
			if contains(got, tc.leaked) {
				t.Errorf("Text(%q) leaked %q; got %q", tc.in, tc.leaked, got)
			}
		})
	}
}

// TestText_LeavesCleanTextAlone guards the other direction. Over-redaction in
// a diagnostic is its own wrong diagnosis: an operator who cannot read their
// own config path cannot act on the report.
func TestText_LeavesCleanTextAlone(t *testing.T) {
	for _, s := range []string{
		"npm: wired at https://chain305.com/chainproxy/repository/npmjs",
		"/Users/dev/.cargo/config.toml",
		"GOPROXY=https://proxy.golang.org,direct",
		"manager npm installed=true wired=true",
		"",
	} {
		if got := Text(s); got != s {
			t.Errorf("Text(%q) = %q, want unchanged", s, got)
		}
	}
}

// TestIdempotent pins rule 5. Redaction runs at sinks that sometimes chain
// (a Finding.Message redacted at construction and again at render); a second
// pass must be a no-op rather than corrupting the first pass's output.
func TestIdempotent(t *testing.T) {
	for _, s := range []string{
		"postgres://chainsaw:hunter2@postgres:5432/db",
		"https://cli-abc:s3cr3t@chain305.com/x",
		"Password=p@ssw0rd;",
		"Bearer eyJhbGciOiJIUzI1NiJ9",
		"nothing sensitive here",
	} {
		once := Text(s)
		if twice := Text(once); twice != once {
			t.Errorf("Text not idempotent for %q:\n once: %q\ntwice: %q", s, once, twice)
		}
	}
	v := Value("TOKEN", "abc")
	if got := Value("TOKEN", v); got != v {
		t.Errorf("Value not idempotent: once %q, twice %q", v, got)
	}
}

// TestTotal pins rule 6: never panic, and never turn a non-empty input into
// "". An empty field reads as "not configured", which is a different — and
// wrong — diagnosis than "configured, value withheld".
func TestTotal(t *testing.T) {
	for _, s := range []string{
		"", " ", "://", "http://", "a:b@", "@", "::::", "%", "%zz",
		"Bearer", "password=", "postgres://:@/",
		"\x00\x01binary\xff", "🔐 emoji password=x 🔐",
	} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Text(%q) panicked: %v", s, r)
				}
			}()
			got := Text(s)
			if s != "" && got == "" {
				t.Errorf("Text(%q) returned empty; an empty field reads as \"not configured\"", s)
			}
		}()
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("URL(%q) panicked: %v", s, r)
				}
			}()
			if got := URL(s); s != "" && got == "" {
				t.Errorf("URL(%q) returned empty", s)
			}
		}()
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Value(k, %q) panicked: %v", s, r)
				}
			}()
			Value("SOME_KEY", s)
			Value(s, "value")
		}()
	}
}

// TestValue_EmptyValueUnchanged — "" means the variable is unset. Replacing
// it with the placeholder would report a credential that does not exist.
func TestValue_EmptyValueUnchanged(t *testing.T) {
	if got := Value("CHAINSAW_TOKEN", ""); got != "" {
		t.Errorf("Value(CHAINSAW_TOKEN, \"\") = %q, want \"\"", got)
	}
}

func TestIsSensitiveKey(t *testing.T) {
	sensitive := []string{"TOKEN", "yarn_npm_auth_token", "ClientSecret", "DB_PASSWORD", "x-api-key"}
	safe := []string{"CARGO_HOME", "GOPROXY", "server_url", "org_id", "GRADLE_USER_HOME"}
	for _, k := range sensitive {
		if !IsSensitiveKey(k) {
			t.Errorf("IsSensitiveKey(%q) = false, want true", k)
		}
	}
	for _, k := range safe {
		if IsSensitiveKey(k) {
			t.Errorf("IsSensitiveKey(%q) = true, want false", k)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		func() bool {
			for i := 0; i+len(needle) <= len(haystack); i++ {
				if haystack[i:i+len(needle)] == needle {
					return true
				}
			}
			return false
		}()
}

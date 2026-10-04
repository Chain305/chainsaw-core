package codesmell

import (
	"strings"
	"testing"
)

// A fake GitHub token, shaped like the real ones (ghp_ + 36).
const fakeGHToken = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"

// A credential in a URL in shipped source must not be copied into a stored
// snippet. Covers the URL sample (the match is the URL itself), a line
// snippet from a regex rule, and a line long enough that the 200-byte
// truncation would cut between the secret and its '@'.
func TestSnippetsNeverCarryURLCredentials(t *testing.T) {
	url := "https://deploy:" + fakeGHToken + "@github.com/acme/private.git"
	long := strings.Repeat("x", 190)
	files := map[string][]byte{
		"package/dist/sync.js": []byte("const repo = '" + url + "';\n"),
		"package/lib/push.js":  []byte("fetch('" + url + "');\n"),
		"package/lib/long.js":  []byte("const " + long + " = fetch('https://bot:" + fakeGHToken + "@api.github.com/repos');\n"),
	}
	for name, r := range map[string]Result{
		"urls":    ScanURLs(files),
		"network": ScanNetwork(files),
	} {
		if !r.Fired || len(r.Matches) == 0 {
			t.Fatalf("%s: did not fire", name)
		}
		for _, m := range r.Matches {
			if strings.Contains(m.Snippet, "ghp_") || strings.Contains(m.Snippet, "deploy:") {
				t.Errorf("%s: credential reached the snippet: %q", name, m.Snippet)
			}
		}
	}
	if got := RedactURLCredentials("git+https://user:pw@host/a@b"); got != "git+https://REDACTED@host/a@b" {
		t.Errorf("RedactURLCredentials = %q", got)
	}
	if got := RedactURLCredentials("https://registry.npmjs.org/@babel/core"); got != "https://registry.npmjs.org/@babel/core" {
		t.Errorf("a path '@' was rewritten: %q", got)
	}
}

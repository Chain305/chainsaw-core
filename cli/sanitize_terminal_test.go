package cli

import "testing"

// TestSanitizeForTerminal verifies that untrusted single-line fields (package
// names, block reasons — which can come from a lockfile or a crafted install
// arg) cannot inject terminal control sequences when echoed. The rule: drop
// every C0 control char, DEL, and C1 control char (which includes ESC, so no
// CSI/OSC/SGR escape can start); keep all printable text, including Unicode.
func TestSanitizeForTerminal(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain name untouched", "lodash", "lodash"},
		{"scoped name untouched", "@babel/core@7.24.0", "@babel/core@7.24.0"},
		{"unicode kept", "café-utils", "café-utils"},
		{"CSI clear-screen neutralized", "evil\x1b[2Jclear", "evil[2Jclear"},
		{"OSC title-set neutralized", "\x1b]0;pwned\x07x", "]0;pwnedx"},
		{"BEL dropped", "a\x07b", "ab"},
		{"CR/LF stripped (single-line field)", "a\rb\nc", "abc"},
		{"backspace dropped", "real\x08\x08\x08\x08evil", "realevil"},
		{"NUL dropped", "a\x00b", "ab"},
		{"DEL dropped", "a\x7fb", "ab"},
		{"C1 single-byte CSI dropped", "a\x9bJb", "aJb"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sanitizeForTerminal(c.in); got != c.want {
				t.Fatalf("sanitizeForTerminal(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

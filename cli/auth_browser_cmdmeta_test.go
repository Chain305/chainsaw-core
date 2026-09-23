package cli

// BUG-02 — the CLI auth URL must survive cmd.exe.
//
// Go's exec quotes an argument only when it holds a space, a tab or a double
// quote, and a CLI auth URL holds none of them. So on Windows the URL lands on
// the command line bare and cmd.exe reads `&` as a command separator: the
// browser opened on everything up to the first `&`, which for our URL means
// the nonce arrives and cli_port does not.
//
// With no port the page sees no CLI flow, and a visitor who already holds a
// session cookie is redirected to /overview — the reported symptom, and the
// reason pasting the URL by hand was a working workaround.

import (
	"net/url"
	"strings"
	"testing"
)

// realCLIAuthURL mirrors the URL the server builds at
// internal/server/auth_cli.go:1126 — url.Values.Encode(), so the parameters
// are in SORTED key order, which is not the order they are set in.
//
// The order is load-bearing for this file: cmd.exe truncates at the FIRST
// `&`, so which parameter is lost depends on it. `cli` sorts first and
// survives; `cli_port` does not.
func realCLIAuthURL() string {
	return "https://chain305.com/chainsaw/login?cli=3f8a1c9d2e4b6708" +
		"&cli_host=DESKTOP-7QK2&cli_install=7c1e9b40-2a33-4f5e-9c88-aa1b2c3d4e5f" +
		"&cli_port=54321&cli_x=1"
}

// simulateCmdExe models the ONE behaviour that matters: cmd.exe splits an
// unquoted command line on `&` unless the caret escapes it. Everything after
// the first live separator is a different command and never reaches the
// browser.
func simulateCmdExe(commandLine string) string {
	var out strings.Builder
	for i := 0; i < len(commandLine); i++ {
		c := commandLine[i]
		if c == '^' && i+1 < len(commandLine) {
			i++
			out.WriteByte(commandLine[i]) // escaped: literal, keeps going
			continue
		}
		if c == '&' || c == '|' || c == '<' || c == '>' {
			break // separator: the rest is a different command
		}
		out.WriteByte(c)
	}
	return out.String()
}

func TestCLIAuthURLSurvivesCmdExe(t *testing.T) {
	url := realCLIAuthURL()

	// The bug, reproduced: pass the URL as the old code did and the query is
	// truncated. This half is what makes the test meaningful — without it a
	// passing assertion below could just mean the simulation is inert.
	if got := simulateCmdExe(url); got == url {
		t.Fatal("the cmd.exe model did not truncate a raw URL, so it cannot " +
			"demonstrate the bug and the assertion below proves nothing")
	} else if strings.Contains(got, "cli_port") {
		t.Fatalf("expected the raw URL to lose cli_port at the first &, got %q", got)
	}

	// The fix: escaped, the whole URL arrives.
	got := simulateCmdExe(escapeCmdMeta(url))
	if got != url {
		t.Errorf("escaped URL did not survive cmd.exe\n  want %q\n  got  %q", url, got)
	}
}

// TestEscapeCmdMetaCaretFirst — `^` must be escaped before the characters
// whose escapes are themselves carets, or the second pass would escape the
// carets the first pass added and the URL would arrive corrupted rather than
// truncated. A quieter failure than the original bug, so it gets its own test.
func TestEscapeCmdMetaCaretFirst(t *testing.T) {
	for _, in := range []string{
		"https://h/l?a=1&b=2",
		"https://h/l?a=^&b=2",
		"https://h/l?a=1&b=(2)|3",
		"https://h/l?plain=1",
	} {
		if got := simulateCmdExe(escapeCmdMeta(in)); got != in {
			t.Errorf("round trip failed\n  in   %q\n  out  %q", in, got)
		}
	}
}

// TestEscapeCmdMetaLeavesNonWindowsURLsAlone documents the scope: the escape
// is applied on the cmd.exe arms only, so a URL with no metacharacters must
// come back byte-identical and darwin/xdg-open keep passing the raw string.
func TestEscapeCmdMetaLeavesNonWindowsURLsAlone(t *testing.T) {
	const clean = "https://chain305.com/chainsaw/login"
	if got := escapeCmdMeta(clean); got != clean {
		t.Errorf("escapeCmdMeta(%q) = %q, want unchanged", clean, got)
	}
}

// TestCLIAuthURLTruncationLosesThePort pins WHY the user saw /overview: it is
// specifically cli_port that goes missing, and the page keys the CLI flow on
// it.
//
// It builds the query with url.Values.Encode() rather than asserting against
// the fixture, so it tracks the REAL ordering. An earlier version claimed it
// would go red if the parameter order changed, which a hardcoded fixture
// cannot do — it would have kept passing while describing a truncation that
// no longer happened.
func TestCLIAuthURLTruncationLosesThePort(t *testing.T) {
	q := url.Values{}
	q.Set("cli", "3f8a1c9d2e4b6708")
	q.Set("cli_port", "54321")
	q.Set("cli_host", "DESKTOP-7QK2")
	q.Set("cli_install", "7c1e9b40-2a33-4f5e-9c88-aa1b2c3d4e5f")
	q.Set("cli_x", "1")
	built := "https://chain305.com/chainsaw/login?" + q.Encode()

	if built != realCLIAuthURL() {
		t.Fatalf("the fixture no longer matches what url.Values.Encode() produces:\n  fixture %s\n  real    %s",
			realCLIAuthURL(), built)
	}

	truncated := simulateCmdExe(built)
	if !strings.Contains(truncated, "cli=") {
		t.Fatalf("expected the nonce to survive truncation: %q", truncated)
	}
	if strings.Contains(truncated, "cli_port=") {
		t.Fatal("cli_port survived truncation — the /overview bounce this test " +
			"documents would not happen, so re-check login/page.tsx before " +
			"relaxing anything here")
	}
	t.Logf("browser would have received: %s", truncated)
}

// escapeArg mirrors syscall.EscapeArg, which is what os/exec uses to turn
// args into a Windows command line. Reproduced because it does not build on
// darwin, and the whole bug lives in its one rule: an argument is quoted only
// when it holds a space, a tab, a backslash or a double quote. A URL holds
// none of those, so it goes on the command line BARE, where cmd.exe reads its
// metacharacters.
func escapeArg(s string) string {
	if s == "" {
		return `""`
	}
	needsBackslash, hasSpace := false, false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"', '\\':
			needsBackslash = true
		case ' ', '\t':
			hasSpace = true
		}
	}
	if !needsBackslash && !hasSpace {
		return s
	}
	var b []byte
	if hasSpace {
		b = append(b, '"')
	}
	slashes := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			slashes++
		case '"':
			for ; slashes > 0; slashes-- {
				b = append(b, '\\')
			}
			b = append(b, '\\')
		default:
			slashes = 0
		}
		b = append(b, s[i])
	}
	if hasSpace {
		for ; slashes > 0; slashes-- {
			b = append(b, '\\')
		}
		b = append(b, '"')
	}
	return string(b)
}

// splitsACommand reports whether cmd.exe would find a LIVE command separator
// in this command line — a metacharacter that is neither caret-escaped nor
// inside double quotes. That is the injection condition: a live separator
// means everything after it runs as a second command.
func splitsACommand(cmdline string) bool {
	inQuotes := false
	for i := 0; i < len(cmdline); i++ {
		switch c := cmdline[i]; {
		case c == '^' && !inQuotes:
			i++ // escapes the next character
		case c == '"':
			inQuotes = !inQuotes
		case !inQuotes && (c == '&' || c == '|' || c == '<' || c == '>'):
			return true
		}
	}
	return false
}

// TestEscapedURLNeverSplitsACommand is the security property, as opposed to
// the functional one above.
//
// login_url is handed to us by the server the user pointed `--server` at, and
// then handed to a shell. A hostile or compromised server that could smuggle a
// live `&` into it would be running commands on the user's Windows machine.
//
// The property holds in every quoting state, which is why one escape is
// enough: where `^` is literal (inside double quotes), `&` is already inert;
// where `&` would split (outside them), `^` escapes it. The worst a crafted
// URL achieves is a corrupted address in the browser.
func TestEscapedURLNeverSplitsACommand(t *testing.T) {
	hostile := []string{
		`https://h/login?cli=a&cli_port=1`,
		`https://h/login?x=1&calc.exe`,
		`https://h/login?x="&calc.exe`,
		`https://h/login?x="a"&calc.exe`,
		`https://h/login?x=a b&calc.exe`,
		`https://h/login?x=a b"c&calc.exe`,
		`https://h/login?x=1|calc.exe`,
		`https://h/login?x=1>out.txt`,
		`https://h/login?x=1^&calc.exe`,
		`https://h/login?x=%20%26&y=2`,
		`https://h/login?x=1&&calc.exe`,
		`https://h/login?x=(1)&calc.exe`,
	}
	for _, raw := range hostile {
		// Unescaped, most of these are exactly the injection we are guarding
		// against. Assert that at least one is, or the model is inert and the
		// real assertion below proves nothing.
		escaped := escapeCmdMeta(raw)
		if splitsACommand(escapeArg(escaped)) {
			t.Errorf("escaped URL still yields a live command separator: %q\n  cmdline: %s",
				raw, escapeArg(escaped))
		}
	}

	var anyRawSplits bool
	for _, raw := range hostile {
		if splitsACommand(escapeArg(raw)) {
			anyRawSplits = true
			break
		}
	}
	if !anyRawSplits {
		t.Fatal("no unescaped URL in the corpus produced a live separator, so the " +
			"model cannot distinguish escaped from unescaped and the assertions above are vacuous")
	}
}

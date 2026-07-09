package hook

import (
	"bytes"
	"strings"
	"testing"
)

// makeBlock builds a canonical LF-terminated chainsaw block for tests. We
// avoid buildBlock here because it stamps a timestamp; fixed fixtures make
// assertions easier to reason about.
func makeBlock(body string) []byte {
	var b strings.Builder
	b.WriteString(sentinelStart)
	b.WriteByte('\n')
	if body != "" {
		b.WriteString(strings.TrimRight(body, "\n"))
		b.WriteByte('\n')
	}
	b.WriteString(sentinelEnd)
	b.WriteByte('\n')
	return []byte(b.String())
}

func TestHasSentinel(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"empty", "", false},
		{"only start", "# >>> chainsaw-managed >>>\nfoo\n", false},
		{"only end", "foo\n# <<< chainsaw-managed <<<\n", false},
		{"both same line", "# >>> chainsaw-managed >>> # <<< chainsaw-managed <<<\n", false},
		{"markers mid-line in user comment", `# Blog: "# >>> chainsaw-managed >>>" and "# <<< chainsaw-managed <<<" strings` + "\n", false},
		{"well formed no body", "# >>> chainsaw-managed >>>\n# <<< chainsaw-managed <<<\n", true},
		{"well formed with body", "# >>> chainsaw-managed >>>\nregistry=x\n# <<< chainsaw-managed <<<\n", true},
		{"well formed with leading content", "user=keep\n\n# >>> chainsaw-managed >>>\n# <<< chainsaw-managed <<<\n", true},
		{"well formed with trailing whitespace on markers", "   # >>> chainsaw-managed >>>   \n# <<< chainsaw-managed <<<\n", true},
		{"end before start", "# <<< chainsaw-managed <<<\n# >>> chainsaw-managed >>>\n", false},
		{"two starts before end (corrupt)", "# >>> chainsaw-managed >>>\n# >>> chainsaw-managed >>>\n# <<< chainsaw-managed <<<\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasSentinel([]byte(tc.in)); got != tc.want {
				t.Errorf("hasSentinel(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestRemoveSentinel(t *testing.T) {
	cases := []struct {
		name       string
		in         string
		wantOut    string
		wantRemove bool
	}{
		{
			name:       "well formed block is removed",
			in:         "# >>> chainsaw-managed >>>\nfoo\n# <<< chainsaw-managed <<<\n",
			wantOut:    "",
			wantRemove: true,
		},
		{
			name:       "block removed preserves surrounding content",
			in:         "user=keep\n\n# >>> chainsaw-managed >>>\nfoo\n# <<< chainsaw-managed <<<\nafter=keep\n",
			wantOut:    "user=keep\nafter=keep\n",
			wantRemove: true,
		},
		{
			name:       "markers inside a user comment are not touched",
			in:         `# Blog: "# >>> chainsaw-managed >>>" and "# <<< chainsaw-managed <<<" strings` + "\n",
			wantOut:    `# Blog: "# >>> chainsaw-managed >>>" and "# <<< chainsaw-managed <<<" strings` + "\n",
			wantRemove: false,
		},
		{
			name:       "end before start is not touched",
			in:         "# <<< chainsaw-managed <<<\nfoo\n# >>> chainsaw-managed >>>\n",
			wantOut:    "# <<< chainsaw-managed <<<\nfoo\n# >>> chainsaw-managed >>>\n",
			wantRemove: false,
		},
		{
			name:       "empty file returns unchanged",
			in:         "",
			wantOut:    "",
			wantRemove: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotOut, gotRemove := removeSentinel([]byte(tc.in))
			if gotRemove != tc.wantRemove {
				t.Errorf("removed = %v, want %v", gotRemove, tc.wantRemove)
			}
			if string(gotOut) != tc.wantOut {
				t.Errorf("out = %q, want %q", gotOut, tc.wantOut)
			}
		})
	}
}

func TestReplaceOrAppend(t *testing.T) {
	block := makeBlock("body=1")

	t.Run("empty file writes block only", func(t *testing.T) {
		out := replaceOrAppend(nil, block)
		if string(out) != string(block) {
			t.Errorf("got %q, want %q", out, block)
		}
	})

	t.Run("file with no trailing newline gets newline before block", func(t *testing.T) {
		in := []byte("user=keep")
		out := replaceOrAppend(in, block)
		want := "user=keep\n\n" + string(block)
		if string(out) != want {
			t.Errorf("got %q, want %q", out, want)
		}
	})

	t.Run("existing block is replaced and surrounding content preserved", func(t *testing.T) {
		in := []byte("before=a\n\n" + string(makeBlock("old=1")) + "after=b\n")
		out := replaceOrAppend(in, block)
		want := "before=a\n\n" + string(block) + "after=b\n"
		if string(out) != want {
			t.Errorf("got %q, want %q", out, want)
		}
	})

	t.Run("markers as substring in user content are left untouched and block appended", func(t *testing.T) {
		userLine := `# Blog: "# >>> chainsaw-managed >>>" and "# <<< chainsaw-managed <<<" strings` + "\n"
		out := replaceOrAppend([]byte(userLine), block)
		want := userLine + "\n" + string(block)
		if string(out) != want {
			t.Errorf("got %q, want %q", out, want)
		}
		if !strings.Contains(string(out), userLine) {
			t.Errorf("user line was modified: %q", out)
		}
	})

	t.Run("CRLF file preserves CRLF and block is emitted with CRLF", func(t *testing.T) {
		in := []byte("a=1\r\nb=2\r\n")
		out := replaceOrAppend(in, block)
		// All \n in out should be preceded by \r; easiest invariant check.
		for i := 0; i < len(out); i++ {
			if out[i] == '\n' && (i == 0 || out[i-1] != '\r') {
				t.Fatalf("lone LF at index %d in output: %q", i, out)
			}
		}
		// Surrounding content should be unchanged.
		if !bytes.Contains(out, []byte("a=1\r\nb=2\r\n")) {
			t.Errorf("CRLF user content not preserved: %q", out)
		}
		if !bytes.Contains(out, []byte(sentinelStart+"\r\n")) {
			t.Errorf("block markers not CRLF-terminated: %q", out)
		}
	})

	t.Run("consecutive sentinels treated as corrupt", func(t *testing.T) {
		// Two starts back-to-back: findSentinelLines returns ok=false, so
		// replaceOrAppend falls through to append path and leaves the
		// corrupt content in place.
		in := []byte("# >>> chainsaw-managed >>>\n# >>> chainsaw-managed >>>\n# <<< chainsaw-managed <<<\n")
		out := replaceOrAppend(in, block)
		if !bytes.Contains(out, in) {
			t.Errorf("corrupt content should be preserved verbatim, got %q", out)
		}
		if !bytes.Contains(out, block) {
			t.Errorf("new block should be appended, got %q", out)
		}
	})
}

func TestDetectNewline(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", "\n"},
		{"no newline here", "\n"},
		{"a\nb\n", "\n"},
		{"a\r\nb\r\n", "\r\n"},
		// Mixed: first newline wins.
		{"a\r\nb\n", "\r\n"},
		{"a\nb\r\n", "\n"},
	}
	for _, tc := range cases {
		if got := detectNewline([]byte(tc.in)); got != tc.want {
			t.Errorf("detectNewline(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestReplaceOrAppendRoundTrip verifies Wire-then-Unwire on a file with
// substring-marker content restores the exact original bytes.
func TestWireUnwireRoundTripWithSubstringMarkers(t *testing.T) {
	blog := []byte(`# Blog: "# >>> chainsaw-managed >>>" and "# <<< chainsaw-managed <<<" strings` + "\n")
	// Simulate Wire: no existing block found, so our block is appended.
	afterWire := replaceOrAppend(blog, makeBlock("x=1"))
	// Unwire should strip our block but leave the blog line untouched.
	afterUnwire, removed := removeSentinel(afterWire)
	if !removed {
		t.Fatal("removeSentinel returned false after Wire")
	}
	if string(afterUnwire) != string(blog) {
		t.Errorf("round trip did not restore original:\ngot  %q\nwant %q", afterUnwire, blog)
	}
}

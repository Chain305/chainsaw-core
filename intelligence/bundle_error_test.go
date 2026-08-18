package intelligence

// L-28 — LoadBundle's open-failure message named the path twice.
//
// os.Open fails with an *os.PathError, whose Error() is already
// "open <path>: <reason>". Wrapping that in "intel bundle: open %s: %w" printed
// the absolute path once in the wrapper and once inside the wrapped error, so
// an operator debugging an offline boot read the same long path twice on one
// line and reasonably assumed two different files were involved.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadBundle_MissingFileNamesPathOnce counts occurrences rather than
// matching the message shape: the exact prose is allowed to change, but the
// path appearing twice is the defect and must stay fixed.
func TestLoadBundle_MissingFileNamesPathOnce(t *testing.T) {
	dir := t.TempDir()
	const name = "chainsaw-intel-bundle-does-not-exist.tar.gz"
	path := filepath.Join(dir, name)

	_, err := LoadBundle(context.Background(), path, BundleVerifyOptions{SkipSignature: true})
	if err == nil {
		t.Fatal("loading a nonexistent bundle must fail")
	}
	msg := err.Error()
	if n := strings.Count(msg, name); n != 1 {
		t.Errorf("the path appears %d times in %q, want exactly 1 "+
			"(*os.PathError already carries it)", n, msg)
	}
	if !strings.HasPrefix(msg, "intel bundle: ") {
		t.Errorf("the wrapper prefix must survive, got %q", msg)
	}
}

// TestLoadBundle_ParseFailureIsNotCalledRead pins the second half: the tarball
// parse error used to reuse the io.ReadAll wrapper's "read:" prefix, so two
// structurally different failures produced the same message and the bytes were
// already in memory by the time it fired.
func TestLoadBundle_ParseFailureIsNotCalledRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "not-a-tarball.tar.gz")
	if werr := os.WriteFile(path, []byte("this is not gzip, let alone a tar"), 0o644); werr != nil {
		t.Fatal(werr)
	}

	_, err := LoadBundle(context.Background(), path, BundleVerifyOptions{SkipSignature: true})
	if err == nil {
		t.Fatal("a non-tarball must fail to load")
	}
	msg := err.Error()
	if !strings.Contains(msg, "parse tarball") {
		t.Errorf("a parse failure must say so, got %q", msg)
	}
	if strings.Contains(msg, "intel bundle: read:") {
		t.Errorf("the parse failure must not reuse the read wrapper, got %q", msg)
	}
}

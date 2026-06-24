package analyzer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// ParseBytes dispatches a single in-memory lockfile to every registered
// Analyzer whose Required(filename) matches, returning the union of
// emitted Packages. The filename argument is what Required() inspects —
// callers should pass the original lockfile name (e.g. "package-lock.json",
// "Cargo.lock") so suffix/regex matchers fire correctly.
//
// Existing Analyzer.Parse takes an absolute path, so we spool the bytes
// to a temp file and clean it up before returning. This keeps the
// per-ecosystem parsers (vendored from Trivy) untouched.
//
// Used by the server's /api/v1/scan/lockfile endpoint, which receives a
// single uploaded lockfile rather than a directory tree.
func ParseBytes(ctx context.Context, filename string, content []byte) ([]Package, error) {
	if filename == "" {
		return nil, fmt.Errorf("analyzer: filename required")
	}
	analyzers := All()
	if len(analyzers) == 0 {
		return nil, nil
	}

	// Sanitize: every analyzer's Required() should already be tolerant
	// of attacker-supplied paths, but for an HTTP-uploaded filename we
	// also strip directory components before the match check. Without
	// this, a crafted name like "/etc/passwd/package-lock.json" would
	// still match (suffix-based Required), and any analyzer that does
	// `filepath.Dir` semantics could see attacker-controlled segments.
	base := filepath.Base(filename)
	matches := make([]Analyzer, 0, 2)
	for _, a := range analyzers {
		if a.Required(base) {
			matches = append(matches, a)
		}
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("analyzer: no parser matches %q", base)
	}

	dir, err := os.MkdirTemp("", "chainsaw-lockfile-*")
	if err != nil {
		return nil, fmt.Errorf("tempdir: %w", err)
	}
	defer os.RemoveAll(dir)

	path := filepath.Join(dir, base)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return nil, fmt.Errorf("write temp lockfile: %w", err)
	}

	var (
		all  []Package
		errs []error
	)
	for _, a := range matches {
		pkgs, perr := a.Parse(ctx, path)
		if perr != nil {
			errs = append(errs, fmt.Errorf("%s: %w", a.Type(), perr))
			continue
		}
		all = append(all, pkgs...)
	}
	if len(errs) > 0 && len(all) == 0 {
		return nil, errorJoin(errs)
	}
	return all, nil
}

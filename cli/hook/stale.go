package hook

// Staleness detection (H11).
//
// Manager.Status reports `Wired: hasSentinel(data)` — pure marker presence.
// It cannot tell a live hook from a dead one, so a block pointing at a
// decommissioned server, carrying an old org slug, or rewritten in place by
// `go env -w GOPROXY=https://proxy.golang.org` (Go edits the last occurrence,
// which is INSIDE our block) still reports "wired" while every fetch bypasses
// the proxy.
//
// StatusFor re-renders what the current settings WOULD write and compares it
// with what is on disk. The generated-at line is excluded — it changes on
// every run and says nothing about whether the hook still works.
//
// Only managers whose config is a sentinel block with a deterministic body
// participate. maven/nuget/docker return Stale=false: their files are whole
// documents rather than a rendered body, and a false "stale" claim is worse
// than none.

import "strings"

// bodyRenderer is implemented by managers whose Wire body is a pure function
// of WireOpts, which is what makes a re-render comparison meaningful.
type bodyRenderer interface {
	renderBody(opts WireOpts) (string, error)
	blockMarker() markerClassifier
}

func (npmManager) renderBody(o WireOpts) (string, error)   { return npmBlockBody(o) }
func (npmManager) blockMarker() markerClassifier           { return hashMarker }
func (yarnManager) renderBody(o WireOpts) (string, error)  { return yarnBlockBody(o) }
func (yarnManager) blockMarker() markerClassifier          { return hashMarker }
func (bunManager) renderBody(o WireOpts) (string, error)   { return bunBlockBody(o) }
func (bunManager) blockMarker() markerClassifier           { return hashMarker }
func (pipManager) renderBody(o WireOpts) (string, error)   { return pipBlockBody(o) }
func (pipManager) blockMarker() markerClassifier           { return hashMarker }
func (cargoManager) renderBody(o WireOpts) (string, error) { return cargoBlockBody(o) }
func (cargoManager) blockMarker() markerClassifier         { return hashMarker }

func (gradleManager) renderBody(o WireOpts) (string, error) { return gradleBlockBody(o) }
func (gradleManager) blockMarker() markerClassifier         { return gradleMarker }

// go's body also carries the user's GOFLAGS, which Wire reads off disk. Feed
// the current on-disk value back in so only a real drift (the documented
// `go env -w GOPROXY=https://proxy.golang.org` rewrite, which Go applies to
// the last occurrence — INSIDE our block) shows up as stale.
func (m goModManager) renderBody(o WireOpts) (string, error) {
	path, err := m.ConfigPathForScope(o.Scope)
	if err != nil {
		return "", err
	}
	data, err := readOrEmpty(path)
	if err != nil {
		return "", err
	}
	goflags, _ := sanitizeGoflags(existingGoflags(data))
	return goBlockBody(o, goflags)
}
func (goModManager) blockMarker() markerClassifier { return hashMarker }

// StatusFor is Status plus a staleness verdict computed against the settings
// the caller would wire with today.
func StatusFor(m Manager, opts WireOpts) (Status, error) {
	st, err := m.Status()
	if err != nil || !st.Wired {
		return st, err
	}
	r, ok := m.(bodyRenderer)
	if !ok {
		return st, nil
	}
	want, err := r.renderBody(opts)
	if err != nil {
		// A body we cannot render is not evidence about the installed one.
		return st, nil
	}
	data, err := readOrEmpty(st.ConfigPath)
	if err != nil {
		return st, nil
	}
	got, ok := extractBlockBody(data, r.blockMarker())
	if !ok {
		return st, nil
	}
	// pip drops its own `[global]` header when the file already has a
	// user-owned one, so the installed body legitimately differs from the
	// freshly rendered one by that single line. Accept either shape.
	if normalizeBody(got) == normalizeBody(want) ||
		normalizeBody(got) == normalizeBody(stripLeadingGlobalHeader(want)) {
		return st, nil
	}
	st.Stale = true
	st.StaleReason = "the installed block no longer matches the current server/org settings; re-run install-hook"
	return st, nil
}

// extractBlockBody returns the interior of the chainsaw block, minus the
// generated-at line.
func extractBlockBody(data []byte, classify markerClassifier) (string, bool) {
	lines, _ := splitLines(data)
	start, end, ok := findMarkedLines(lines, classify)
	if !ok {
		return "", false
	}
	var kept []string
	for _, ln := range lines[start+1 : end] {
		t := strings.TrimSpace(ln)
		t = strings.TrimSpace(strings.TrimPrefix(t, "//"))
		t = strings.TrimSpace(strings.TrimPrefix(t, "#"))
		if strings.HasPrefix(t, "generated-at:") {
			continue
		}
		kept = append(kept, ln)
	}
	return strings.Join(kept, "\n"), true
}

// normalizeBody makes the comparison insensitive to line-ending convention
// and to leading/trailing blank lines, which the splice path may add.
func normalizeBody(s string) string {
	lines := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	var out []string
	for _, ln := range lines {
		out = append(out, strings.TrimRight(ln, " \t"))
	}
	return strings.TrimSpace(strings.Join(out, "\n"))
}

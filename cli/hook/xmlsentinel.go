package hook

// XML-specific sentinel handling, shared by the two XML managers (maven,
// nuget) and by nothing else.
//
// Two problems live here, both from H1/H2:
//
//  1. `#` is not a comment in XML, so the shared sentinel machinery cannot
//     splice a block into an XML document. Both managers therefore emit a
//     WHOLE standalone document with the markers inside a single top-level
//     `<!-- ... -->` comment, and refuse to touch a document they did not
//     write (see mavenManager.Wire / nugetManager.Wire).
//
//  2. Releases up to now put the marker on the SAME line as the comment
//     opener (`<!-- # >>> chainsaw-managed >>>`) or the closer
//     (`# <<< chainsaw-managed <<< -->`), which the shared exact-line matcher
//     can never see. Every such install is orphaned: Status reports
//     not-wired and Unwire reports "no chainsaw-managed block found", while
//     `<mirrorOf>*</mirrorOf>` keeps redirecting all Maven traffic. xmlMarker
//     accepts BOTH the fixed own-line spelling and those two legacy shapes,
//     which is what makes those installs removable again.
//
// Unwire for XML deliberately does NOT go through removeSentinel. Stripping
// the marker lines out of a standalone settings.xml would delete the comment
// and leave the live <mirror>/<packageSources> elements in place while
// reporting success — a silent failure, strictly worse than today's loud one.
// xmlUnwire restores the newest pre-chainsaw backup instead, and deletes the
// file when there is none (we wrote the whole document, so there is nothing
// of the user's to preserve).

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// xmlMarker classifies a line of an XML document as a chainsaw marker,
// tolerating the comment delimiters the marker may share its line with.
//
// Accepted spellings, all equivalent:
//
//	# >>> chainsaw-managed >>>              (fixed, own line inside <!-- -->)
//	<!-- # >>> chainsaw-managed >>>         (legacy maven + nuget opener)
//	# <<< chainsaw-managed <<< -->          (legacy nuget closer)
func xmlMarker(line string) markerKind {
	t := strings.TrimSpace(line)
	t = strings.TrimSpace(strings.TrimPrefix(t, "<!--"))
	t = strings.TrimSpace(strings.TrimSuffix(t, "-->"))
	t = strings.TrimSpace(strings.TrimPrefix(t, "#"))
	switch t {
	case sentinelBodyStart:
		return markerStart
	case sentinelBodyEnd:
		return markerEnd
	}
	return markerNone
}

// xmlHasSentinel reports whether data is a chainsaw-written XML document,
// under either the fixed or the legacy marker spelling.
func xmlHasSentinel(data []byte) bool {
	return hasMarkedBlock(data, xmlMarker)
}

// xmlStatus builds the Status for an XML manager. It uses the XML matcher so
// already-orphaned (legacy-marker) installs report wired instead of lying.
func xmlStatus(configPathFn func() (string, error), isInstalledFn func() bool) (Status, error) {
	path, err := configPathFn()
	if err != nil {
		return Status{}, err
	}
	data, err := readOrEmpty(path)
	if err != nil {
		return Status{ConfigPath: path, Installed: isInstalledFn()}, err
	}
	return Status{
		ConfigPath: path,
		Wired:      xmlHasSentinel(data),
		Installed:  isInstalledFn(),
	}, nil
}

// xmlUnwire removes a chainsaw-written XML config: restore the newest
// pre-chainsaw backup when one exists, otherwise delete the file. Returns
// ErrNotWired when the file carries no chainsaw marker.
func xmlUnwire(path string) error {
	data, err := readOrEmpty(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) == 0 || !xmlHasSentinel(data) {
		return ErrNotWired
	}
	restore, ok, err := newestNonChainsawBackup(path)
	if err != nil {
		return err
	}
	if !ok {
		// We wrote the whole document; there is no user content under it.
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove %s: %w", path, err)
		}
		return nil
	}
	body, err := os.ReadFile(restore)
	if err != nil {
		return fmt.Errorf("read backup %s: %w", restore, err)
	}
	if err := writeAtomic(path, body); err != nil {
		return err
	}
	return nil
}

// newestNonChainsawBackup returns the most recent <path>.chainsaw.bak.* whose
// contents are NOT themselves a chainsaw-written document. Backup names carry
// a zero-padded UTC timestamp, so lexical order is chronological.
func newestNonChainsawBackup(path string) (string, bool, error) {
	matches, err := filepath.Glob(path + ".chainsaw.bak.*")
	if err != nil {
		return "", false, fmt.Errorf("list backups: %w", err)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(matches)))
	for _, m := range matches {
		data, err := os.ReadFile(m)
		if err != nil {
			continue
		}
		if xmlHasSentinel(data) {
			continue
		}
		return m, true, nil
	}
	return "", false, nil
}

// xmlRefuseError is the error both XML managers return when asked to wire a
// config file they did not author. It names the file, says why we will not
// edit it, and prints the exact document fragment the operator should merge.
//
// Refusing is deliberate. Go's encoding/xml cannot round-trip a document
// losslessly (attribute quoting, entity spelling, comment and whitespace
// placement all change), so a splicer would silently reformat a hand-
// maintained settings.xml. The previous behaviour — appending "#" comment
// lines after the closing tag — produced `[FATAL] Non-parseable settings` and
// broke every mvn invocation, and additionally leaked the plaintext client
// secret into the file.
func xmlRefuseError(manager, path, fragment string) error {
	return fmt.Errorf(`%s already exists and chainsaw did not write it.

chainsaw refuses to edit an XML config it does not own: there is no way to
splice into %s without reformatting hand-maintained content, and the previous
append-a-comment behaviour produced a non-parseable document.

Merge the following into %s by hand, then re-run `+"`chainsaw status`"+` to confirm:

%s
Alternatively, move %s aside and re-run `+"`chainsaw install-hook %s`"+` to have
chainsaw write a complete managed file.`,
		path, filepath.Base(path), path, fragment, path, manager)
}

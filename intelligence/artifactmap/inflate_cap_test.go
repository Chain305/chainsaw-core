package artifactmap

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// A bomb is one huge entry: retention keeps only its head, but tar inflates
// the rest to reach the next header. MaxInflatedBytes stops the walk there
// and reports Truncated, for tar, zip and a gem's inner data.tar.gz.
func TestBuild_InflateCapStopsTheWalk(t *testing.T) {
	big := strings.Repeat("A", 4<<20) // compresses to a few KiB
	files := map[string]string{"package/a.bin": big, "package/z.js": "after"}
	gemData := [][2]string{{"lib/a.rb", big}, {"lib/z.rb", "after"}}
	for name, payload := range map[string][]byte{
		"tgz": buildTGZ(t, files),
		"zip": buildZip(t, files),
		"gem": buildGem(t, gemData),
	} {
		capped := Build(payload, Options{MaxInflatedBytes: 1 << 20})
		if !capped.Truncated {
			t.Errorf("%s: 4 MiB inflated under a 1 MiB cap and Truncated is false", name)
		}
		full := Build(payload, Options{})
		_, gotTail := full.Files["package/z.js"]
		if _, ok := full.Files["lib/z.rb"]; ok {
			gotTail = true
		}
		if full.Truncated || !gotTail {
			t.Errorf("%s: under the default cap: truncated=%v, last entry kept=%v; want false, true", name, full.Truncated, gotTail)
		}
	}
}

// A header that understates an entry's size must not cut the head short.
func TestReadEntry_UnderstatedSizeStillReadsTheEntry(t *testing.T) {
	body := strings.Repeat("b", 5000)
	for _, declared := range []int64{0, 10, 5000, 9000} {
		head, _, err := readEntry(bytes.NewReader([]byte(body)), "x.txt", declared, Options{}.normalize())
		if err != nil || string(head) != body {
			t.Errorf("declared %d: got %d bytes err=%v, want all %d", declared, len(head), err, len(body))
		}
	}
	head, _, _ := readEntry(io.LimitReader(strings.NewReader(strings.Repeat("c", 100)), 100), "x.txt", 10, Options{PerFileCap: 50}.normalize())
	if len(head) != 50 {
		t.Errorf("understated entry past PerFileCap: kept %d bytes, want the cap (50)", len(head))
	}
}

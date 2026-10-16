package artifactmap

import (
	"bytes"
	"strings"
	"testing"
)

// A source file past PerFileCap keeps its last TailCap bytes too: a loader
// whose decoder and Function call sit at the end of a multi-MiB file must not
// be scanned head-only.
func TestBuild_TruncatedSourceKeepsTail(t *testing.T) {
	body := "HEAD" + strings.Repeat("x", 3*PerFileCap) + "Function(o)();//END"
	for name, payload := range map[string][]byte{
		"tgz": buildTGZ(t, map[string]string{"package/loader.js": body}),
		"zip": buildZip(t, map[string]string{"package/loader.js": body}),
	} {
		f := Build(payload, Options{}).Files["package/loader.js"]
		if len(f.Bytes) != PerFileCap || !bytes.HasPrefix(f.Bytes, []byte("HEAD")) {
			t.Fatalf("%s: head = %d bytes, want %d starting HEAD", name, len(f.Bytes), PerFileCap)
		}
		if len(f.Tail) != TailCap || !bytes.HasSuffix(f.Tail, []byte("Function(o)();//END")) {
			t.Fatalf("%s: tail = %d bytes, want %d ending with the Function call", name, len(f.Tail), TailCap)
		}
		joined := f.WithTail()
		if !bytes.HasPrefix(joined, []byte("HEAD")) || !bytes.HasSuffix(joined, []byte("//END")) {
			t.Fatalf("%s: WithTail lost head or tail", name)
		}
	}
}

// Just over the cap: the tail is the remainder, and WithTail is the whole
// file byte for byte.
func TestBuild_TailContiguousWhenSmall(t *testing.T) {
	body := strings.Repeat("y", PerFileCap) + "REST"
	f := Build(buildTGZ(t, map[string]string{"package/a.js": body}), Options{}).Files["package/a.js"]
	if string(f.Tail) != "REST" || string(f.WithTail()) != body {
		t.Fatalf("tail = %q, joined len %d, want REST and %d", f.Tail, len(f.WithTail()), len(body))
	}
}

// Only source files get a tail: a truncated binary or text file is unchanged.
func TestBuild_NoTailForNonSourceOrUntruncated(t *testing.T) {
	files := map[string]string{
		"package/model.js":  strings.Repeat("\x00", PerFileCap+10),
		"package/README.md": strings.Repeat("m", PerFileCap+10),
		"package/small.js":  "module.exports=1",
	}
	m := Build(buildTGZ(t, files), Options{}).Files
	for k := range files {
		if m[k].Tail != nil {
			t.Errorf("%s: unexpected tail of %d bytes", k, len(m[k].Tail))
		}
	}
}

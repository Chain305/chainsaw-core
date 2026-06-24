package codeowners

import (
	"reflect"
	"testing"
)

func TestParseSkipsCommentsAndBlanks(t *testing.T) {
	src := `# top comment

# another comment
* @global-owner
`
	got, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 mapping, got %d (%+v)", len(got), got)
	}
	if got[0].Pattern != "*" {
		t.Errorf("pattern = %q, want %q", got[0].Pattern, "*")
	}
	if !reflect.DeepEqual(got[0].Owners, []string{"@global-owner"}) {
		t.Errorf("owners = %v", got[0].Owners)
	}
	if got[0].LineNo != 4 {
		t.Errorf("lineNo = %d, want 4", got[0].LineNo)
	}
}

func TestParseEscapedHash(t *testing.T) {
	src := `path\#with-hash @owner # trailing comment
`
	got, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 mapping, got %d", len(got))
	}
	if got[0].Pattern != "path#with-hash" {
		t.Errorf("pattern = %q, want path#with-hash", got[0].Pattern)
	}
	if !reflect.DeepEqual(got[0].Owners, []string{"@owner"}) {
		t.Errorf("owners = %v", got[0].Owners)
	}
}

func TestParseAcceptsTeamAndEmailOwners(t *testing.T) {
	src := `*.go @org/backend ops@example.com @user`
	got, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []string{"@org/backend", "ops@example.com", "@user"}
	if !reflect.DeepEqual(got[0].Owners, want) {
		t.Errorf("owners = %v, want %v", got[0].Owners, want)
	}
}

func TestParseRejectsLineWithoutOwners(t *testing.T) {
	src := "*.go\n*.py @py-team\n"
	got, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 valid mapping, got %d (%+v)", len(got), got)
	}
	if got[0].Pattern != "*.py" {
		t.Errorf("pattern = %q", got[0].Pattern)
	}
}

func TestLookup(t *testing.T) {
	cases := []struct {
		name string
		src  string
		path string
		want []string
	}{
		{
			name: "wildcard catches everything",
			src:  "* @everyone\n",
			path: "src/foo.go",
			want: []string{"@everyone"},
		},
		{
			name: "last match wins over wildcard",
			src:  "* @everyone\n*.go @gophers\n",
			path: "src/foo.go",
			want: []string{"@gophers"},
		},
		{
			name: "last match wins among directories",
			src:  "/docs/ @docs\n/docs/api/ @api-docs\n",
			path: "docs/api/index.md",
			want: []string{"@api-docs"},
		},
		{
			name: "anchored root pattern only matches at root",
			src:  "/build.sh @release\n",
			path: "scripts/build.sh",
			want: nil,
		},
		{
			name: "anchored root matches at root",
			src:  "/build.sh @release\n",
			path: "build.sh",
			want: []string{"@release"},
		},
		{
			name: "unanchored bare pattern matches at any depth",
			src:  "build.sh @release\n",
			path: "scripts/nested/build.sh",
			want: []string{"@release"},
		},
		{
			name: "directory-only pattern matches files inside",
			src:  "docs/ @docs-team\n",
			path: "docs/getting-started.md",
			want: []string{"@docs-team"},
		},
		{
			name: "directory-only pattern does not match the bare name",
			src:  "/notes/ @notes\n",
			path: "notes",
			want: nil,
		},
		{
			name: "double-star matches across segments",
			src:  "src/**/*.go @gophers\n",
			path: "src/api/v2/handler.go",
			want: []string{"@gophers"},
		},
		{
			name: "double-star matches zero segments",
			src:  "src/**/*.go @gophers\n",
			path: "src/handler.go",
			want: []string{"@gophers"},
		},
		{
			name: "extension wildcard matches",
			src:  "*.md @docs\n",
			path: "deeply/nested/README.md",
			want: []string{"@docs"},
		},
		{
			name: "no match returns nil",
			src:  "*.go @gophers\n",
			path: "README.md",
			want: nil,
		},
		{
			name: "team handle survives the round trip",
			src:  "infra/ @org/sre\n",
			path: "infra/terraform/main.tf",
			want: []string{"@org/sre"},
		},
		{
			name: "email owner survives the round trip",
			src:  "secrets/ ops@example.com\n",
			path: "secrets/key.pem",
			want: []string{"ops@example.com"},
		},
		{
			name: "comment lines do not perturb ordering",
			src:  "# header\n* @everyone\n# divider\n*.go @gophers\n",
			path: "x.go",
			want: []string{"@gophers"},
		},
		{
			name: "later wildcard wins over earlier specific",
			src:  "*.go @gophers\n* @everyone\n",
			path: "x.go",
			want: []string{"@everyone"},
		},
		{
			name: "anchored directory pattern with deeper file",
			src:  "/docs/api/ @api-docs\n",
			path: "docs/api/v2/index.md",
			want: []string{"@api-docs"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ms, err := Parse([]byte(tc.src))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			got := Lookup(ms, tc.path)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Lookup(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestCleanPath(t *testing.T) {
	cases := map[string]string{
		"/foo/bar":   "foo/bar",
		"./foo/bar":  "foo/bar",
		"foo/./bar":  "foo/bar",
		"foo//bar":   "foo/bar",
		"  foo  ":    "foo",
		"foo/bar/..": "foo",
	}
	for in, want := range cases {
		if got := CleanPath(in); got != want {
			t.Errorf("CleanPath(%q) = %q, want %q", in, got, want)
		}
	}
}

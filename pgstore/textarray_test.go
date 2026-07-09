package pgstore

import (
	"reflect"
	"testing"
)

// TestPgTextArrayScan pins the Postgres text[] decoding contract that
// blocked the dashboard `/api/findings` and `/api/codeowners` reads in
// the 2026-05-03 incident. The base bug: pgx/v5/stdlib accepts []string
// as an INSERT param for text[] columns but does NOT auto-decode the
// reverse on Scan. That asymmetry meant every read of an org's findings
// in production returned CHW-5307 (findings store request failed).
//
// Each subtest exercises a real-world wire shape we observed (or
// plausibly might observe). NULL is rare in practice but kept as a
// regression guard so a future caller storing a sparse array doesn't
// break the read path again.
func TestPgTextArrayScan(t *testing.T) {
	cases := []struct {
		name string
		src  any
		want []string
		err  bool
	}{
		{name: "nil_src", src: nil, want: nil},
		{name: "empty_array_string", src: "{}", want: []string{}},
		{name: "empty_array_bytes", src: []byte("{}"), want: []string{}},
		{name: "empty_string", src: "", want: []string{}},
		{name: "single_unquoted", src: "{alice}", want: []string{"alice"}},
		{name: "two_unquoted", src: "{alice,bob}", want: []string{"alice", "bob"}},
		{name: "owner_handle_format", src: `{@org/team-a,@org/team-b}`, want: []string{"@org/team-a", "@org/team-b"}},
		{name: "quoted_with_comma", src: `{"a,b","c"}`, want: []string{"a,b", "c"}},
		{name: "quoted_with_escaped_quote", src: `{"a\"b"}`, want: []string{`a"b`}},
		{name: "null_element", src: `{NULL}`, want: []string{""}},
		{name: "mixed_null_and_value", src: `{a,NULL,c}`, want: []string{"a", "", "c"}},
		{name: "malformed_no_braces", src: "abc", err: true},
		{name: "malformed_only_open_brace", src: "{abc", err: true},
		{name: "unsupported_type", src: 42, err: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got PgTextArray
			err := got.Scan(tc.src)
			if tc.err {
				if err == nil {
					t.Fatalf("expected error, got %v", []string(got))
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual([]string(got), tc.want) {
				t.Errorf("got %#v, want %#v", []string(got), tc.want)
			}
		})
	}
}

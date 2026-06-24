package config

// Wave AA — pure-function coverage for the comma-list helpers that
// back Swift.GitHubOrgAllowList persistence. These do not need a
// database and therefore always run in `go test ./internal/config/...`.

import (
	"reflect"
	"testing"
)

func TestSplitCommaList(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"whitespace_only", "   ", nil},
		{"single", "apple", []string{"apple"}},
		{"multiple", "apple,vapor,swift-server", []string{"apple", "vapor", "swift-server"}},
		{"trims_whitespace", " apple , vapor ", []string{"apple", "vapor"}},
		{"drops_empty_segments", "apple,,vapor,", []string{"apple", "vapor"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := splitCommaList(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("splitCommaList(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestJoinCommaList(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want string
	}{
		{"nil", nil, ""},
		{"empty", []string{}, ""},
		{"single", []string{"apple"}, "apple"},
		{"multiple", []string{"apple", "vapor"}, "apple,vapor"},
		{"trims_each", []string{" apple ", "vapor "}, "apple,vapor"},
		{"drops_blanks", []string{"apple", "", "  ", "vapor"}, "apple,vapor"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := joinCommaList(tc.in)
			if got != tc.want {
				t.Fatalf("joinCommaList(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestCommaListRoundTrip asserts the symmetry property the store
// relies on: split(join(x)) == x for any reasonable input. This is
// the property that lets Swift.GitHubOrgAllowList survive the DB
// round-trip without becoming []string{""} on empty or losing
// elements on whitespace.
func TestCommaListRoundTrip(t *testing.T) {
	inputs := [][]string{
		nil,
		{"apple"},
		{"apple", "vapor", "swift-server"},
	}
	for _, in := range inputs {
		got := splitCommaList(joinCommaList(in))
		want := in
		if len(want) == 0 {
			want = nil
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("round-trip lost data: in=%v out=%v", in, got)
		}
	}
}

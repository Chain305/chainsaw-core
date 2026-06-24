package common

import (
	"reflect"
	"testing"
)

func TestSplitPathSegments(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"only slashes", "///", nil},
		{"single segment", "alpha", []string{"alpha"}},
		{"leading slash trimmed", "/alpha/beta", []string{"alpha", "beta"}},
		{"trailing slash trimmed", "alpha/beta/", []string{"alpha", "beta"}},
		{"leading and trailing slashes", "/alpha/beta/", []string{"alpha", "beta"}},
		{"empty internal segments dropped", "alpha//beta", []string{"alpha", "beta"}},
		{"whitespace-only segments dropped", "alpha/  /beta", []string{"alpha", "beta"}},
		{"interior whitespace trimmed", "/  alpha  /beta /", []string{"alpha", "beta"}},
		{"deeply nested", "a/b/c/d/e", []string{"a", "b", "c", "d", "e"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SplitPathSegments(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("SplitPathSegments(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

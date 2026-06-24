package intelligence

import (
	"context"
	"testing"
)

func TestReservedNamespacesProvider_ExtractsScopedNamespace(t *testing.T) {
	cases := []struct {
		name      string
		ecosystem string
		pkg       string
		wantNS    string
	}{
		{"npm-scoped", "npm", "@babel/core", "@babel"},
		{"npm-scoped-no-slash", "npm", "@babel", ""},
		{"npm-unscoped", "npm", "lodash", ""},
		{"npm-legacy-org", "npm", "myorg/internal-utils", "myorg"},
		{"maven-colon", "maven", "org.apache.commons:commons-lang3", "org.apache.commons"},
		{"go-subpath", "go", "golang.org/x/mod", "golang.org/x"},
		{"go-single-slash", "go", "example.com/tool", "example.com"},
		{"go-vanity-domain-prefix", "go", "git.company.com/x", "git.company.com"},
		{"go-vanity-domain-typo-distinct", "go", "git.xompany.com/x", "git.xompany.com"},
		{"composer", "composer", "symfony/http-kernel", "symfony"},
		{"docker-namespaced", "docker", "library/alpine:3.19", "library"},
		{"docker-bare-implies-library", "docker", "alpine:3.19", "library"},
		{"docker-bare-no-tag", "docker", "alpine", "library"},
		{"huggingface", "huggingface", "meta-llama/Llama-3", "meta-llama"},
		{"pypi-none", "pip", "requests", ""},
		{"pypi-explicit", "pypi", "requests", ""},
		{"rubygems-none", "rubygems", "rails", ""},
		{"cargo-none", "cargo", "serde", ""},
		{"unknown-ecosystem", "totally-made-up", "whatever", ""},
		{"empty-pkg", "npm", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractNamespace(tc.ecosystem, tc.pkg)
			if got != tc.wantNS {
				t.Fatalf("extractNamespace(%q,%q): got %q, want %q",
					tc.ecosystem, tc.pkg, got, tc.wantNS)
			}
		})
	}
}

func TestReservedNamespacesProvider_EmitsWarningWhenNamespaced(t *testing.T) {
	p := newReservedNamespacesProvider()
	partial, err := p.Run(context.Background(), Request{
		Key: Key{Ecosystem: "npm", Package: "@babel/core", Version: "7.0.0"},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if len(partial.Warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d", len(partial.Warnings))
	}
	if partial.Warnings[0].Message != "@babel" {
		t.Fatalf("warning message: got %q, want @babel", partial.Warnings[0].Message)
	}
	if partial.Warnings[0].Provider != "reservednamespaces" {
		t.Fatalf("warning provider: got %q", partial.Warnings[0].Provider)
	}
}

func TestReservedNamespacesProvider_NoNamespaceNoOutput(t *testing.T) {
	p := newReservedNamespacesProvider()
	partial, err := p.Run(context.Background(), Request{
		Key: Key{Ecosystem: "pip", Package: "requests", Version: "2.31.0"},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if len(partial.Warnings) != 0 {
		t.Fatalf("expected no warnings for non-namespaced package, got %+v", partial.Warnings)
	}
	if partial.SupplyChain != nil {
		t.Fatalf("no SupplyChain expected, got %+v", partial.SupplyChain)
	}
}

func TestReservedNamespacesProvider_AlwaysSupported(t *testing.T) {
	p := newReservedNamespacesProvider()
	for _, e := range []string{"npm", "pip", "docker", "maven", "go", "unknown-ecosystem"} {
		if !p.Supports(e) {
			t.Errorf("ecosystem %q should be supported by reservednamespaces", e)
		}
	}
}

func TestReservedNamespacesProvider_ContractShape(t *testing.T) {
	p := newReservedNamespacesProvider()
	if p.Name() != "reservednamespaces" {
		t.Errorf("Name: got %q", p.Name())
	}
	if p.Signal() != SignalReservedNamespaces {
		t.Errorf("Signal: got %v", p.Signal())
	}
	if p.Tier() != 1 {
		t.Errorf("Tier: got %d", p.Tier())
	}
	if p.NeedsArtifact() {
		t.Errorf("NeedsArtifact must be false")
	}
}

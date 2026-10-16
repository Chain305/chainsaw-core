package intelligence

import (
	"context"
	"net/http"
	"reflect"
	"testing"
)

// TestRubyGemsRegistryDigestsCoverEveryPlatform: Digests.Registry carries
// the sha256 of every .gem published under the version number — the
// default-platform gem and each platform gem — taken from the versions list
// the timeline already fetches, so a Gemfile.lock CHECKSUMS entry for a
// platform gem (nokogiri 1.16.0-x86_64-linux) compares with a published
// file. Other versions' shas never leak in.
func TestRubyGemsRegistryDigestsCoverEveryPlatform(t *testing.T) {
	const (
		ruby  = "aaaa000000000000000000000000000000000000000000000000000000000001"
		linux = "BBBB000000000000000000000000000000000000000000000000000000000002"
		mac   = "cccc000000000000000000000000000000000000000000000000000000000003"
		other = "dddd000000000000000000000000000000000000000000000000000000000004"
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/rubygems/nokogiri/versions/1.16.0.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"nokogiri","version":"1.16.0","sha":"` + ruby + `","created_at":"2023-12-27T00:00:00Z"}`))
	})
	mux.HandleFunc("/api/v1/versions/nokogiri.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
			{"number":"1.16.0","platform":"ruby","sha":"` + ruby + `","created_at":"2023-12-27T00:00:00Z"},
			{"number":"1.16.0","platform":"x86_64-linux","sha":"` + linux + `","created_at":"2023-12-27T00:00:00Z"},
			{"number":"1.16.0","platform":"arm64-darwin","sha":"` + mac + `","created_at":"2023-12-27T00:00:00Z"},
			{"number":"1.15.5","platform":"ruby","sha":"` + other + `","created_at":"2023-11-17T00:00:00Z"}
		]`))
	})
	p := newRegistryMetadataProvider()
	p.client = &http.Client{Transport: muxTransport{mux}}
	p.endpoints.rubygems = "http://rubygems.test"
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "rubygems", Package: "nokogiri", Version: "1.16.0"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.Artifact == nil {
		t.Fatalf("no artifact: %+v", pr.Warnings)
	}
	want := []string{"sha256:" + ruby, "sha256:bbbb000000000000000000000000000000000000000000000000000000000002", "sha256:" + mac}
	if got := pr.Artifact.Digests.Registry; !reflect.DeepEqual(got, want) {
		t.Fatalf("registry digests = %q, want %q", got, want)
	}
	if pr.Artifact.Digests.SHA256 != ruby {
		t.Fatalf("SHA256 = %q, want the default-platform gem's", pr.Artifact.Digests.SHA256)
	}
}

// TestRubyGemsRegistryDigestsAllOrNothing: when the versions list does not
// carry the version (failed fetch, or a list without it), Registry stays
// empty rather than holding the default-platform sha alone, which would make
// a genuine platform gem's checksum look like a foreign file.
func TestRubyGemsRegistryDigestsAllOrNothing(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/rubygems/nokogiri/versions/1.16.0.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"nokogiri","version":"1.16.0","sha":"aaaa000000000000000000000000000000000000000000000000000000000001"}`))
	})
	mux.HandleFunc("/api/v1/versions/nokogiri.json", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusNotFound)
	})
	p := newRegistryMetadataProvider()
	p.client = &http.Client{Transport: muxTransport{mux}}
	p.endpoints.rubygems = "http://rubygems.test"
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "rubygems", Package: "nokogiri", Version: "1.16.0"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.Artifact == nil || pr.Artifact.Digests.SHA256 == "" {
		t.Fatalf("artifact: %+v", pr.Artifact)
	}
	if got := pr.Artifact.Digests.Registry; len(got) != 0 {
		t.Fatalf("registry digests = %q, want none without the versions list", got)
	}
}

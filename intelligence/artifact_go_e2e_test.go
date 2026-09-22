package intelligence

// END-TO-END proof that a real Go module zip survives the whole chain:
// artifactURLFor -> fetch -> artifactmap.Build -> a file map the providers read.
// Unit tests only asserted the URL string. A wrong media type, a zip the
// builder refuses, or a cap that drops everything would all still pass those.
// Network-gated so it never runs in CI.

import (
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/chain305/chainsaw-core/intelligence/artifactmap"
)

func TestGoArtifactSurvivesTheWholeChain(t *testing.T) {
	if os.Getenv("CHAINSAW_NET_TEST") == "" {
		t.Skip("set CHAINSAW_NET_TEST=1 to run (fetches from proxy.golang.org)")
	}
	url, media := artifactURLFor("go", "github.com/gorilla/mux", "v1.8.1")
	if url == "" {
		t.Fatal("no url")
	}
	t.Logf("url=%s media=%s", url, media)

	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	t.Logf("fetched %d bytes", len(body))

	res := artifactmap.Build(body, artifactmap.Options{})
	t.Logf("artifactmap: %d files, truncated=%v", len(res.Files), res.Truncated)
	if len(res.Files) == 0 {
		t.Fatal("artifactmap produced ZERO files from a real Go module zip — " +
			"the URL is right but nothing downstream can read what it returns")
	}
	var goFiles int
	for name := range res.Files {
		if len(name) > 3 && name[len(name)-3:] == ".go" {
			goFiles++
		}
	}
	t.Logf("go source files: %d", goFiles)
	// Measured 2026-09-22 against github.com/gorilla/mux@v1.8.1:
	//   60,113 bytes fetched -> 26 files -> 16 .go sources, truncated=false.
	if goFiles == 0 {
		t.Error("no .go files — source-scanning providers would find nothing")
	}
}

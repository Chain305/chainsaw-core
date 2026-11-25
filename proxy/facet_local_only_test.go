package proxy

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/storage"
)

// A read the server decided is a local upload must never reach upstream,
// even when the stored copy vanished between that decision and this read
// (a concurrent delete): it is a 404, not the public namesake.
func TestLocalOnlyReadNeverFetchesUpstream(t *testing.T) {
	const artifact = "acme-internal/-/acme-internal-1.0.0.tgz"
	f, ls := newInternalFacet(t, nil)

	resp, err := f.Get(WithLocalOnly(context.Background()), &Request{LogicalPath: artifact, Method: http.MethodGet})
	if err != nil || resp.StatusCode != http.StatusNotFound {
		t.Fatalf("local-only miss: %v %+v, want 404", err, resp)
	}
	if _, err := ls.Get(context.Background(), artifact); err == nil {
		t.Fatal("a local-only read stored upstream bytes")
	}

	// A local-only read of a stored copy is served from it.
	if _, err := ls.Put(context.Background(), artifact, strings.NewReader("internal bytes"), storage.ContentMetadata{Uploaded: true}); err != nil {
		t.Fatal(err)
	}
	resp, err = f.Get(WithLocalOnly(context.Background()), &Request{LogicalPath: artifact, Method: http.MethodGet})
	if err != nil || resp.StatusCode != http.StatusOK || !resp.FromCache {
		t.Fatalf("local-only hit: %v %+v, want the stored copy", err, resp)
	}

	// Positive control: without the mark a miss goes upstream.
	resp, err = f.Get(context.Background(), &Request{LogicalPath: "other/-/other-1.0.0.tgz", Method: http.MethodGet})
	if err != nil || resp.StatusCode != http.StatusOK || resp.FromCache {
		t.Fatalf("unmarked miss: %v %+v, want an upstream fill", err, resp)
	}
}

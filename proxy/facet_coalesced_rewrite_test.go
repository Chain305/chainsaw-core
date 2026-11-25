package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// linkTransformer writes the link repository the request carries into the
// page, replacing whatever an earlier transform wrote (as the pip and npm
// rewriters heal their own links).
type linkTransformer struct{}

func (linkTransformer) ShouldTransform(string, *http.Response) bool { return true }
func (linkTransformer) Transform(ctx context.Context, _ string, b []byte) ([]byte, error) {
	if i := bytes.IndexByte(b, '\n'); bytes.HasPrefix(b, []byte("link:")) && i >= 0 {
		b = b[i+1:]
	}
	return append([]byte("link:"+LinkRepoName(ctx, "r")+"\n"), b...), nil
}

// Two first fetches of one page coalesce into one upstream request. Each
// waiter must still get the page rewritten for its own request: a group and
// its member asked at once used to both get the leader's links, so a client
// scoped to the group got the member's file links (and 401s). Later cache
// hits were already rewritten per request.
func TestCoalescedFetchRewritesForEachWaiter(t *testing.T) {
	release := make(chan struct{})
	arrived := make(chan struct{}, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		arrived <- struct{}{}
		<-release
		_, _ = io.WriteString(w, "page body")
	}))
	t.Cleanup(srv.Close)
	base, _ := url.Parse(srv.URL + "/")
	f := NewFacet(FacetConfig{RepoName: "member", Format: "pip", Storage: newFileStorage(t), Rewrite: linkTransformer{},
		Remote: RemoteDefinition{BaseURL: base, Client: srv.Client()}, Logger: discardLogger()})

	type result struct {
		body string
		err  error
	}
	get := func(link string, out chan<- result) {
		ctx := WithLinkRepoName(context.Background(), link)
		resp, err := f.Get(ctx, &Request{LogicalPath: "simple/acme/", Method: http.MethodGet, Header: http.Header{}})
		if err != nil {
			out <- result{err: err}
			return
		}
		rc, err := resp.Content.Open()
		if err != nil {
			out <- result{err: err}
			return
		}
		b, _ := io.ReadAll(rc)
		_ = rc.Close()
		out <- result{body: string(b)}
	}
	groupOut, memberOut := make(chan result, 1), make(chan result, 1)
	go get("group", groupOut)
	<-arrived // the leader's fetch is in flight
	go get("member", memberOut)
	time.Sleep(100 * time.Millisecond) // let the second caller join the flight
	close(release)

	g, m := <-groupOut, <-memberOut
	if g.err != nil || m.err != nil {
		t.Fatalf("errors: group=%v member=%v", g.err, m.err)
	}
	if len(arrived) != 0 {
		t.Fatalf("test premise: the two fetches did not coalesce (%d more upstream requests)", len(arrived))
	}
	if g.body != "link:group\npage body" || m.body != "link:member\npage body" {
		t.Fatalf("group got %q, member got %q; each must carry its own links", g.body, m.body)
	}
}

package typosquat

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

// cratesStub serves crates.io-shaped pages of 100 names ("crate-<n>") and
// fails page 2 with a transport error for the first failPage2 attempts.
type cratesStub struct {
	failPage1 bool
	page1Hits int
	failPage2 int
	page2Hits int
}

func (s *cratesStub) RoundTrip(req *http.Request) (*http.Response, error) {
	page := req.URL.Query().Get("page")
	if page == "1" {
		s.page1Hits++
		if s.failPage1 {
			return nil, errors.New("network unreachable")
		}
	}
	if page == "2" {
		s.page2Hits++
		if s.page2Hits <= s.failPage2 {
			// What crates.io did on 2026-10-05; upstreamhttp does not retry it.
			return nil, errors.New("remote end closed connection without response")
		}
	}
	var n int
	fmt.Sscanf(page, "%d", &n)
	names := make([]string, 100)
	for i := range names {
		names[i] = fmt.Sprintf(`{"name":"crate-%d"}`, (n-1)*100+i)
	}
	body := `{"crates":[` + strings.Join(names, ",") + `]}`
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
		Header:     http.Header{"Content-Type": {"application/json"}},
	}, nil
}

func stubFetcher(rt http.RoundTripper) *Fetcher {
	f := NewFetcher(nil, WithHTTPClient(&http.Client{Transport: rt}))
	f.pageRetryDelay = 0
	return f
}

// TestFetchCargoRefusesTruncatedCorpus is the regression for the 2026-10-05
// production quarantines of mime/sha1/libm/crc/cbc/rend/scc: a failure after
// page 1 used to return the first 100 crates as the whole corpus.
func TestFetchCargoRefusesTruncatedCorpus(t *testing.T) {
	stub := &cratesStub{failPage2: pageAttempts}
	pkgs, err := stubFetcher(stub).fetchCargo(context.Background(), 150)
	if !errors.Is(err, ErrTruncatedCorpus) {
		t.Fatalf("err = %v, want ErrTruncatedCorpus", err)
	}
	if pkgs != nil {
		t.Fatalf("returned %d packages with a truncated-corpus error; a partial corpus must never be handed to LoadEcosystem", len(pkgs))
	}
	if stub.page2Hits != pageAttempts {
		t.Errorf("page 2 tried %d times, want %d", stub.page2Hits, pageAttempts)
	}
}

func TestFetchCargoRetriesATransientPageFailure(t *testing.T) {
	stub := &cratesStub{failPage2: pageAttempts - 1}
	pkgs, err := stubFetcher(stub).fetchCargo(context.Background(), 150)
	if err != nil {
		t.Fatalf("err = %v, want success after retry", err)
	}
	if len(pkgs) != 150 || pkgs[149].Name != "crate-149" {
		t.Fatalf("got %d packages (last %+v), want the full 150", len(pkgs), pkgs[len(pkgs)-1])
	}
}

// TestFetchCargoFirstPageFailureFallsBackWithoutRetry pins the offline path:
// the install guard (guard_eval.go) relies on a failed first request reaching
// the embedded seed instantly. Retrying it cost ~6s per ecosystem.
func TestFetchCargoFirstPageFailureFallsBackWithoutRetry(t *testing.T) {
	stub := &cratesStub{failPage1: true}
	pkgs, err := stubFetcher(stub).fetchCargo(context.Background(), 150)
	if err != nil || len(pkgs) == 0 {
		t.Fatalf("got %d packages, err %v; want the embedded seed", len(pkgs), err)
	}
	if stub.page1Hits != 1 {
		t.Fatalf("page 1 tried %d times; a first-page failure must not be retried", stub.page1Hits)
	}
}

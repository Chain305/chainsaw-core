package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strconv"
	"testing"

	"github.com/chain305/chainsaw-core/storage"
)

// pypi.org/simple/ is ~46 MiB and npm packuments keep growing. Refusing an
// index above the old 50 MiB cap made it unservable: detection accuracy
// wins over bandwidth, so such a document is transformed and served.
func TestTransformBodyAboveOldCapIsTransformed(t *testing.T) {
	const size = 60 << 20
	chunk := bytes.Repeat([]byte("a"), 1<<20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(size))
		for i := 0; i < size/len(chunk); i++ {
			_, _ = w.Write(chunk)
		}
	}))
	t.Cleanup(srv.Close)
	base, _ := url.Parse(srv.URL + "/")
	store := &capturingStorage{}
	f := NewFacet(FacetConfig{RepoName: "r", Format: "npm", Storage: store, Rewrite: upperTransformer{},
		Remote: RemoteDefinition{BaseURL: base, Client: srv.Client()}, Logger: discardLogger()})

	if _, err := f.Get(context.Background(), &Request{LogicalPath: "huge", Method: http.MethodGet, Header: http.Header{}}); err != nil {
		t.Fatalf("a %d MiB index was refused: %v", size>>20, err)
	}
	if store.stored != size || !store.allUpper {
		t.Fatalf("stored %d bytes (all transformed: %v), want %d transformed bytes", store.stored, store.allUpper, size)
	}
}

// A body whose length is known is not grown past: append's grow-and-copy
// allocates several times the body over a read, and holds two copies at
// the peak, which at 256 MiB is the difference that matters. The first
// transformInitialAlloc bytes are read before the length is trusted.
func TestReadBodyWithEncodingAllocatesKnownLengthOnce(t *testing.T) {
	const n = 32 << 20
	body := bytes.Repeat([]byte("a"), n)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	got, release, err := readBodyWithEncoding(context.Background(), bytes.NewReader(body), "", n)
	runtime.ReadMemStats(&after)
	defer release()
	if err != nil || len(got) != n {
		t.Fatalf("read %d bytes, err %v", len(got), err)
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > n*3/2 {
		t.Fatalf("reading a %d-byte body of known length allocated %d bytes", n, alloc)
	}
}

type capturingStorage struct {
	freshStorage
	stored   int
	allUpper bool
}

func (s *capturingStorage) Put(ctx context.Context, logicalPath string, src io.Reader, meta storage.ContentMetadata) (*storage.CachedContent, error) {
	b, err := io.ReadAll(src)
	if err != nil {
		return nil, err
	}
	s.stored = len(b)
	s.allUpper = bytes.Count(b, []byte("A")) == len(b)
	return s.freshStorage.Put(ctx, logicalPath, nil, meta)
}

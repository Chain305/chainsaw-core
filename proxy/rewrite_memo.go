package proxy

import (
	"container/list"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/chain305/chainsaw-core/storage"
)

// rewriteMemo holds the result of transforming a cached response (npm
// packument, PyPI simple page, ...) for one request context. A warm hit used
// to re-read the stored body from the blob store, decode it, transform it,
// re-encode it, and, whenever the requester's host differed from the last
// one, write it back. On Contabo S3 that was 0.6-1.3 s of GETs and up to
// 3 s of PUT per hit before serving, plus a full JSON parse of a document
// that can be several MB.
//
// Keyed by everything the transform depends on: repository, org, logical
// path, the stored version (CachedAt, ETag, Size) and the request's base URL
// and org slug, so a new upstream copy or a different host misses. Bounded
// by bytes (CHAINSAW_PACKUMENT_MEMO_MB, default 128; 0 turns it off).
type rewriteMemoEntry struct {
	key       string
	meta      storage.ContentMetadata
	data      []byte
	unchanged bool // the transform was a no-op: serve the stored copy
}

type byteLRU struct {
	mu    sync.Mutex
	cap   int64
	size  int64
	ll    *list.List
	items map[string]*list.Element
}

const rewriteMemoEnv = "CHAINSAW_PACKUMENT_MEMO_MB"

var rewriteMemo = sync.OnceValue(func() *byteLRU {
	mb := int64(128)
	if v := strings.TrimSpace(os.Getenv(rewriteMemoEnv)); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
			mb = n
		}
	}
	return newByteLRU(mb << 20)
})

func newByteLRU(capBytes int64) *byteLRU {
	return &byteLRU{cap: capBytes, ll: list.New(), items: make(map[string]*list.Element)}
}

func (c *byteLRU) get(key string) (rewriteMemoEntry, bool) {
	if c == nil || c.cap <= 0 {
		return rewriteMemoEntry{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return rewriteMemoEntry{}, false
	}
	c.ll.MoveToFront(el)
	return el.Value.(rewriteMemoEntry), true
}

func (c *byteLRU) put(e rewriteMemoEntry) {
	if c == nil || c.cap <= 0 || int64(len(e.data)) > c.cap {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[e.key]; ok {
		c.size -= int64(len(el.Value.(rewriteMemoEntry).data))
		el.Value = e
		c.ll.MoveToFront(el)
	} else {
		c.items[e.key] = c.ll.PushFront(e)
	}
	c.size += int64(len(e.data))
	for c.size > c.cap {
		oldest := c.ll.Back()
		old := oldest.Value.(rewriteMemoEntry)
		c.ll.Remove(oldest)
		delete(c.items, old.key)
		c.size -= int64(len(old.data))
	}
}

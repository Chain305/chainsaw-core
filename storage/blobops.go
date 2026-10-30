package storage

import (
	"context"
	"strconv"
	"sync/atomic"
)

// BlobOps counts the blob-store operations one request caused, so a request
// log line can say how much object-store traffic it cost
// (docs/REPORTS.md#backend-perf-load-test-2026-10-29 J.2 A1). Disk-tier,
// spool and in-memory reads are not blob-store operations and are not
// counted.
type BlobOps struct {
	Gets, Puts atomic.Int64
}

type blobOpsKey struct{}

// WithBlobOps returns ctx carrying a fresh counter, and the counter.
func WithBlobOps(ctx context.Context) (context.Context, *BlobOps) {
	ops := &BlobOps{}
	return context.WithValue(ctx, blobOpsKey{}, ops), ops
}

func blobOpsFrom(ctx context.Context) *BlobOps {
	if ctx == nil {
		return nil
	}
	ops, _ := ctx.Value(blobOpsKey{}).(*BlobOps)
	return ops
}

// String is "gets/puts".
func (o *BlobOps) String() string {
	if o == nil {
		return "0/0"
	}
	return strconv.FormatInt(o.Gets.Load(), 10) + "/" + strconv.FormatInt(o.Puts.Load(), 10)
}

func (o *BlobOps) get() {
	if o != nil {
		o.Gets.Add(1)
	}
}

func (o *BlobOps) put() {
	if o != nil {
		o.Puts.Add(1)
	}
}

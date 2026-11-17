package storage

// Process-wide byte budget for temp-file spools (R2-G2).
//
// Each spool was capped on its own (the scan spool at the scanner's stream
// limit, 512 MiB by default; an upload's restore check at the 500 MiB upload
// limit), but nothing bounded them together. /tmp counts toward the pod's
// ephemeral-storage limit, so about eight concurrent large fills evicted the
// pod, and every request on it with them. Every spool now writes through a
// SpoolWriter that draws on one budget as bytes arrive; a write that would
// exceed it fails with ErrSpoolBudgetExhausted, and the caller answers 503
// with Retry-After. Fail closed: an artifact that cannot be spooled is not
// scanned, so it is neither stored nor served.
//
// Bytes are counted as written, not reserved up front, so small artifacts do
// not wait behind the worst case. A spool's bytes return to the budget only
// after its file is removed (Release).

import (
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	// SpoolBudgetEnv sets the budget in bytes explicitly.
	SpoolBudgetEnv = "CHAINSAW_SPOOL_BUDGET_BYTES"
	// EphemeralStorageLimitEnv is the container's ephemeral-storage limit
	// in bytes (the Helm chart sets it from the downward API). With no
	// explicit budget, a quarter of it is the budget: clamd writes its own
	// copy of every scanned stream to the same /tmp, and logs and the
	// writable layer count toward the same limit.
	EphemeralStorageLimitEnv = "CHAINSAW_EPHEMERAL_STORAGE_LIMIT_BYTES"
	// DefaultSpoolBudget applies when neither variable holds a positive
	// integer: four full-size scans at ClamAV's default stream limit.
	DefaultSpoolBudget int64 = 2 << 30
)

// ErrSpoolBudgetExhausted is returned by a SpoolWriter whose write would
// take the process's spooled bytes past the budget.
var ErrSpoolBudgetExhausted = errors.New("storage: temporary spool space for this process is exhausted; retry shortly")

var (
	spoolUsed       atomic.Int64
	spoolRejections atomic.Uint64
	// spoolBudget is read once; tests replace it.
	spoolBudget = sync.OnceValue(spoolBudgetFromEnv)
)

func spoolBudgetFromEnv() int64 {
	if n := positiveEnvInt(SpoolBudgetEnv); n > 0 {
		return n
	}
	if n := positiveEnvInt(EphemeralStorageLimitEnv); n >= 4 {
		return n / 4
	}
	return DefaultSpoolBudget
}

func positiveEnvInt(name string) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(os.Getenv(name)), 10, 64)
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

// SpoolBudget is the process-wide spool budget in bytes.
func SpoolBudget() int64 { return spoolBudget() }

// SpoolBytesInUse is the number of bytes currently held by spools.
func SpoolBytesInUse() int64 { return spoolUsed.Load() }

// SpoolBudgetRejections is the cumulative count of spool writes refused
// because the budget was exhausted (chainsaw_spool_budget_rejections_total).
func SpoolBudgetRejections() uint64 { return spoolRejections.Load() }

// SpoolWriter counts the bytes written through it against the process
// budget. Call Release once the spool file is gone.
type SpoolWriter struct {
	w    io.Writer
	held int64
}

// NewSpoolWriter wraps w, typically an *os.File created for a spool.
func NewSpoolWriter(w io.Writer) *SpoolWriter { return &SpoolWriter{w: w} }

func (s *SpoolWriter) Write(p []byte) (int, error) {
	n := int64(len(p))
	limit := spoolBudget()
	for {
		cur := spoolUsed.Load()
		if cur+n > limit {
			spoolRejections.Add(1)
			return 0, ErrSpoolBudgetExhausted
		}
		if spoolUsed.CompareAndSwap(cur, cur+n) {
			break
		}
	}
	s.held += n
	return s.w.Write(p)
}

// Release returns every byte this writer drew. Safe to call more than once.
func (s *SpoolWriter) Release() {
	spoolUsed.Add(-s.held)
	s.held = 0
}

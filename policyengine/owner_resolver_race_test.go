package policyengine_test

// Pain 4 P3 — race coverage for SetOwnerResolver.
//
// SetOwnerResolver is called from the admin reconfiguration path (an
// operator updates the team→destination mapping while requests are in
// flight); Decide() reads the resolver on every request. Without an
// atomic.Pointer behind the slot, `go test -race` flagged the unguarded
// publish. This test exercises the publish under concurrent read+write
// load and asserts there are no panics.
//
// Run with: `go test -race ./internal/policyengine -run TestSetOwnerResolverConcurrent`

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/policy"
	"github.com/chain305/chainsaw-core/policyengine"
)

// raceResolver is a fakeResolver-equivalent local to this file so this
// race test can be compiled and run independently. It records nothing —
// the test asserts only on the absence of panics + race-detector output.
type raceResolver struct{ tag string }

func (r *raceResolver) ResolveOwners(_ context.Context, _, _, _ string) (string, string, string, bool) {
	if r == nil {
		return "", "", "", false
	}
	return r.tag, "", "", r.tag != ""
}

// TestSetOwnerResolverConcurrent fires 100 goroutines doing a 50/50 mix
// of reads (Decide) and writes (SetOwnerResolver) for 100ms, asserting
// no panics. The race detector (go test -race) is what catches the
// underlying memory-model bug — this test exists to give it something
// to chew on. Without atomic.Pointer the previous unguarded slot would
// trip `WARNING: DATA RACE`.
func TestSetOwnerResolverConcurrent(t *testing.T) {
	t.Parallel()

	eng := policyengine.New(policyengine.Config{})

	// Seed a resolver so the very first read sees a non-nil value.
	eng.SetOwnerResolver(&raceResolver{tag: "init"})

	const goroutines = 100
	deadline := time.Now().Add(100 * time.Millisecond)

	var wg sync.WaitGroup
	wg.Add(goroutines)

	var panics atomic.Uint64
	ec := policy.EvaluationContext{
		PackageName:    "foo",
		PackageVersion: "1.0.0",
		Repository:     "acme/payments",
		OrgID:          "org-1",
	}

	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					panics.Add(1)
				}
			}()
			for time.Now().Before(deadline) {
				if i%2 == 0 {
					// Reader: Decide() exercises the resolver load
					// path inside emitOwnerRouting.
					_, _ = eng.Decide(context.Background(), policy.SurfaceProxy, ec)
				} else {
					// Writer: half the writers swap a fresh resolver,
					// the other quarter clear it via nil.
					if i%4 == 1 {
						eng.SetOwnerResolver(&raceResolver{tag: "rotated"})
					} else {
						eng.SetOwnerResolver(nil)
					}
				}
			}
		}()
	}
	wg.Wait()

	if got := panics.Load(); got != 0 {
		t.Fatalf("expected zero panics under concurrent reads/writes, got %d", got)
	}
}

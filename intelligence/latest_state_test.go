package intelligence

import (
	"context"
	"errors"
	"testing"
)

// TestLatestStateSeparatesNotFoundFromUnknown is the whole point of the Ex
// form, checked without touching the network.
//
// Every resolver used to collapse both a 404 and a connection failure into
// "". A caller cannot tell those apart, so anything built on the plain form
// that wanted to say "this package does not exist" was going to say it on a
// timeout too. That is the failure mode behind the withdrawn F-1 and F-3 in
// the socket.dev comparison, arriving by a different route.
func TestLatestStateSeparatesNotFoundFromUnknown(t *testing.T) {
	// An ecosystem with no resolver must be UNKNOWN. Not-found would mean
	// "we looked and it is not there", and we did not look.
	if v, st := ResolveLatestVersionEx(context.Background(), "cocoapods", "Alamofire"); st != LatestUnknown || v != "" {
		t.Errorf("no-resolver ecosystem gave state=%v version=%q, want LatestUnknown/\"\" — "+
			"reporting not_found here asserts absence from a registry we never queried", st, v)
	}
	if _, st := ResolveLatestVersionEx(context.Background(), "", ""); st != LatestUnknown {
		t.Errorf("empty coordinate gave state=%v, want LatestUnknown", st)
	}
}

// TestErrRegistryNotFoundIsASentinel — the 404 path has to be matchable
// with errors.Is. It used to be fmt.Errorf("not found"), which is only
// distinguishable by string comparison, i.e. not at all in practice.
func TestErrRegistryNotFoundIsASentinel(t *testing.T) {
	if ErrRegistryNotFound == nil {
		t.Fatal("ErrRegistryNotFound is nil")
	}
	wrapped := errors.Join(errors.New("context"), ErrRegistryNotFound)
	if !errors.Is(wrapped, ErrRegistryNotFound) {
		t.Error("ErrRegistryNotFound does not survive wrapping; callers cannot " +
			"distinguish a 404 from any other failure")
	}
}

// TestResolveLatestVersionDelegatesToEx keeps the two surfaces from
// drifting — the plain form must stay a thin wrapper so a fix to the
// resolvers reaches both, which is the property its own doc comment claims.
func TestResolveLatestVersionDelegatesToEx(t *testing.T) {
	ctx := context.Background()
	plain := ResolveLatestVersion(ctx, "cocoapods", "Alamofire")
	ex, _ := ResolveLatestVersionEx(ctx, "cocoapods", "Alamofire")
	if plain != ex {
		t.Errorf("ResolveLatestVersion=%q but ResolveLatestVersionEx=%q — the two "+
			"surfaces have diverged", plain, ex)
	}
}

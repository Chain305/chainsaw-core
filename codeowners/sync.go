package codeowners

import (
	"context"
	"errors"
	"fmt"
)

// ErrNotFound is returned by GHClient.GetFile when the requested file
// does not exist at the given path. Sync uses it to fall through to the
// next candidate location.
var ErrNotFound = errors.New("codeowners: file not found")

// GHClient is the minimal GitHub surface Sync needs. Tests inject a
// fake; production wires a thin net/http-based implementation. Keeping
// this interface narrow means we don't have to take on a github SDK
// dependency for a single endpoint.
type GHClient interface {
	// GetFile fetches the raw bytes of a file from a repository, where
	// repo is the "owner/name" GitHub slug. Implementations should
	// return ErrNotFound when the path does not exist (any 404), and a
	// wrapped error for any other failure.
	GetFile(ctx context.Context, repo, path string) ([]byte, error)
}

// Store is the persistence surface Sync writes through. Adapters in
// the cli/billy packages wrap *pgstore.Store to satisfy this
// interface; in-memory stores in tests implement it directly.
type Store interface {
	UpsertCodeowners(ctx context.Context, repoID string, mappings []Mapping) error
	GetCodeowners(ctx context.Context, repoID string) ([]Mapping, error)
}

// candidatePaths is the ordered list of repository-relative paths that
// GitHub recognises as a CODEOWNERS file. We try them in this order
// and stop at the first one that exists, mirroring GitHub's lookup
// order documented in the Code Owners reference.
var candidatePaths = []string{".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"}

// Sync fetches the CODEOWNERS file for repo from GitHub, parses it,
// and replaces the persisted mapping for the same repo. Idempotent:
// running Sync twice with no upstream changes leaves the store in the
// same state.
//
// repo is the GitHub slug ("owner/name") and is also used as the
// repoID written to the store, so callers can Lookup by the same key.
func Sync(ctx context.Context, gh GHClient, repo string, store Store) error {
	if gh == nil {
		return fmt.Errorf("codeowners: nil GHClient")
	}
	if store == nil {
		return fmt.Errorf("codeowners: nil Store")
	}
	if repo == "" {
		return fmt.Errorf("codeowners: empty repo")
	}

	var (
		body      []byte
		lastErr   error
		matchedAt string
	)
	for _, path := range candidatePaths {
		b, err := gh.GetFile(ctx, repo, path)
		if err == nil {
			body = b
			matchedAt = path
			break
		}
		if !errors.Is(err, ErrNotFound) {
			lastErr = err
		}
	}
	if body == nil {
		if lastErr != nil {
			return fmt.Errorf("fetch CODEOWNERS for %s: %w", repo, lastErr)
		}
		return fmt.Errorf("CODEOWNERS not found in %s (tried %v)", repo, candidatePaths)
	}

	mappings, err := Parse(body)
	if err != nil {
		return fmt.Errorf("parse CODEOWNERS at %s/%s: %w", repo, matchedAt, err)
	}
	if err := store.UpsertCodeowners(ctx, repo, mappings); err != nil {
		return fmt.Errorf("persist CODEOWNERS for %s: %w", repo, err)
	}
	return nil
}

// LookupOwners returns the owners that own path under repoID, using
// the most recently synced CODEOWNERS mapping. Returns (nil, nil) when
// the repo has been synced but no pattern matches; (nil, err) when the
// store call fails. A repo that has never been synced returns
// (nil, nil) — callers fall back to a repo-level default.
func LookupOwners(ctx context.Context, store Store, repoID, path string) ([]string, error) {
	if store == nil {
		return nil, fmt.Errorf("codeowners: nil Store")
	}
	mappings, err := store.GetCodeowners(ctx, repoID)
	if err != nil {
		return nil, err
	}
	if len(mappings) == 0 {
		return nil, nil
	}
	return Lookup(mappings, CleanPath(path)), nil
}

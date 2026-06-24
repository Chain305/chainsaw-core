// Package githubactions — scanner library.
//
// This file is the public surface for turning parsed ActionRefs into
// structured Findings. It is a pure library with no I/O of its own — it
// composes the existing Wave 4 detection layers (typosquat, malware feed)
// and a curated known-publisher allowlist into a single ordered output.
//
// The known-publisher allowlist is sourced from the same curated corpus
// that drives typosquat detection (internal/typosquat/github_actions.go),
// trimmed to OWNERS only (not full Action paths). This keeps the
// "is this a trusted publisher?" check aligned with the typosquat
// signal: an owner that publishes a popular Action is, by definition, a
// known publisher. The list is intentionally short — the goal is to
// surface "I've never heard of this org" as a low-severity nudge, not a
// hard gate.
package githubactions

import (
	"context"
	"sort"
	"strings"

	"github.com/chain305/chainsaw-core/malware"
	"github.com/chain305/chainsaw-core/typosquat"
)

// Signal name constants for Findings emitted by Scan. These mirror the
// Wave 4 signal IDs registered in the v2 risk engine so downstream
// consumers can switch on a single canonical string.
const (
	SignalActionUnpinnedRef      = "action.unpinned_ref"
	SignalActionTyposquat        = "action.typosquat"
	SignalActionUnknownPublisher = "action.unknown_publisher"
	SignalActionMalicious        = "action.malicious"
)

// Finding is one issue surfaced by Scan against an ActionRef.
type Finding struct {
	Ref      ActionRef
	Signal   string // "action.unpinned_ref" | "action.typosquat" | "action.unknown_publisher" | "action.malicious"
	Severity string // "high" | "medium" | "low"
	Message  string // human-readable; safe to print
	// Detail is signal-specific structured context. For typosquat: the
	// suggested known-good Action. For malicious: the feed reason. Empty
	// for unpinned/unknown_publisher.
	Detail string
}

// ScanDeps wires the existing Wave 4 detection layers into Scan. All
// fields are optional — a nil typosquat detector or nil malware feed
// just means that signal is skipped. KnownPublishers, when nil, falls
// back to DefaultKnownPublishers().
type ScanDeps struct {
	Typosquat       TyposquatLookup
	Malware         MalwareLookup
	KnownPublishers []string
}

// TyposquatLookup is the narrow interface Scan calls. The real
// implementation is internal/typosquat (whatever entry point that
// package exposes for the "github_actions" ecosystem). Tests pass a
// fake.
type TyposquatLookup interface {
	// Lookup reports whether owner/name resembles a known-good Action,
	// returning the suggested canonical name. Empty suggestion means
	// no typosquat match.
	Lookup(ctx context.Context, ownerSlashName string) (suggestion string, err error)
}

// MalwareLookup is the narrow interface for the malicious-Action feed.
type MalwareLookup interface {
	IsMalicious(ctx context.Context, owner, name, ref string) (bool, string, error)
}

// signalSeverityRank orders signals by severity for within-ref ordering:
// malicious → typosquat → unpinned → unknown_publisher.
func signalSeverityRank(signal string) int {
	switch signal {
	case SignalActionMalicious:
		return 0
	case SignalActionTyposquat:
		return 1
	case SignalActionUnpinnedRef:
		return 2
	case SignalActionUnknownPublisher:
		return 3
	default:
		return 4
	}
}

// Scan runs every applicable signal against every ref in refs. Returns
// findings ordered by SourceFile then SourceLine for stable output.
//
// Within a single ref, findings are ordered by severity rank so the
// most severe signal surfaces first — useful for CLI display
// truncation.
//
// Context cancellation: if ctx is cancelled mid-scan, Scan returns the
// partial findings collected so far together with ctx.Err().
func Scan(ctx context.Context, refs []ActionRef, deps ScanDeps) ([]Finding, error) {
	publishers := deps.KnownPublishers
	if publishers == nil {
		publishers = DefaultKnownPublishers()
	}
	publisherSet := make(map[string]struct{}, len(publishers))
	for _, p := range publishers {
		publisherSet[strings.ToLower(strings.TrimSpace(p))] = struct{}{}
	}

	var findings []Finding

	for _, ref := range refs {
		// Honor cancellation between refs so a long ref list doesn't
		// keep working after the caller gave up. Return whatever was
		// collected so far together with ctx.Err().
		if err := ctx.Err(); err != nil {
			return findings, err
		}

		// Only remote refs are in scope. Local ./path refs and
		// docker:// refs are different problems handled elsewhere.
		if ref.Kind != KindRemote {
			continue
		}

		var perRef []Finding

		// Unpinned check. Only fire when there *is* a Version but it's
		// not a SHA — a totally empty Version is a different problem
		// and the parser would mark such refs as unknown anyway.
		if ref.SHA == "" && ref.Version != "" {
			perRef = append(perRef, Finding{
				Ref:      ref,
				Signal:   SignalActionUnpinnedRef,
				Severity: "medium",
				Message:  "Action " + ref.Owner + "/" + ref.Name + " is not pinned to a commit SHA (using \"" + ref.Version + "\")",
			})
		}

		// Typosquat check. Strip composite-action sub-paths so
		// `actions/cache/save` is looked up as `actions/cache`.
		if deps.Typosquat != nil {
			lookupName := ref.Owner + "/" + stripSubPath(ref.Name)
			suggestion, err := deps.Typosquat.Lookup(ctx, lookupName)
			if err != nil {
				return findings, err
			}
			if suggestion != "" {
				perRef = append(perRef, Finding{
					Ref:      ref,
					Signal:   SignalActionTyposquat,
					Severity: "high",
					Message:  "Action " + ref.Owner + "/" + ref.Name + " resembles known-good Action " + suggestion,
					Detail:   suggestion,
				})
			}
		}

		// Malicious check.
		if deps.Malware != nil {
			bad, reason, err := deps.Malware.IsMalicious(ctx, ref.Owner, ref.Name, ref.Version)
			if err != nil {
				return findings, err
			}
			if bad {
				perRef = append(perRef, Finding{
					Ref:      ref,
					Signal:   SignalActionMalicious,
					Severity: "high",
					Message:  "Action " + ref.Owner + "/" + ref.Name + " is on the malicious-Action feed: " + reason,
					Detail:   reason,
				})
			}
		}

		// Unknown publisher check.
		if _, known := publisherSet[strings.ToLower(ref.Owner)]; !known {
			perRef = append(perRef, Finding{
				Ref:      ref,
				Signal:   SignalActionUnknownPublisher,
				Severity: "low",
				Message:  "Action publisher " + ref.Owner + " is not in the known-publisher allowlist",
			})
		}

		// Order signals within a ref by severity rank.
		sort.SliceStable(perRef, func(i, j int) bool {
			return signalSeverityRank(perRef[i].Signal) < signalSeverityRank(perRef[j].Signal)
		})

		findings = append(findings, perRef...)
	}

	// Final stable sort: (SourceFile, SourceLine) ascending, with
	// signal-rank as the within-line tiebreaker so the within-ref
	// ordering survives.
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Ref.SourceFile != findings[j].Ref.SourceFile {
			return findings[i].Ref.SourceFile < findings[j].Ref.SourceFile
		}
		if findings[i].Ref.SourceLine != findings[j].Ref.SourceLine {
			return findings[i].Ref.SourceLine < findings[j].Ref.SourceLine
		}
		return signalSeverityRank(findings[i].Signal) < signalSeverityRank(findings[j].Signal)
	})

	return findings, nil
}

// stripSubPath reduces a parsed Name like "aws-actions/configure-aws-credentials"
// (composite-action sub-path preserved by the parser) to the first path
// segment. The ParseUsesString contract is that Owner is always the first
// slug and Name is everything after — so for typosquat lookup we want
// just the repo name slug, not the sub-path.
func stripSubPath(name string) string {
	if i := strings.Index(name, "/"); i >= 0 {
		return name[:i]
	}
	return name
}

// DefaultKnownPublishers returns the curated owner-allowlist for the
// "is this a trusted publisher?" check. Sourced inside this package so
// Scan and the CLI agree.
//
// Derivation: extracted from the OWNER prefixes of
// typosquat.PopularGitHubActions(), deduped and lowercased. Trimming to
// owners (rather than the full owner/name corpus) keeps this list short
// and human-auditable while still tracking the popular-Actions corpus
// as it grows. The list is sorted alphabetically.
func DefaultKnownPublishers() []string {
	return []string{
		"actions",
		"aws-actions",
		"azure",
		"docker",
		"github",
		"golang",
		"golangci",
		"google-github-actions",
		"goreleaser",
		"hashicorp",
		"jetbrains",
		"microsoft",
		"peaceiris",
		"pre-commit",
		"softprops",
		"vercel",
	}
}

// --- Concrete adapters ---------------------------------------------------
//
// These thin wrappers let callers (CLI, API) plug the real Wave 4
// implementations into ScanDeps without needing to know the internal
// signatures of typosquat.Detector / malware.GitHubActionsFeed. Tests
// inside this package don't use the adapters — they pass fakes — but
// downstream packages prefer the adapters so the wiring lives here.

// typosquatAdapter wraps a *typosquat.Detector and exposes the
// TyposquatLookup interface. It calls Check against the
// "github_actions" ecosystem and returns the SimilarTo suggestion.
type typosquatAdapter struct {
	detector *typosquat.Detector
}

// NewTyposquatAdapter returns a TyposquatLookup that delegates to the
// given typosquat.Detector. The detector must already have the
// "github_actions" ecosystem loaded (typically via
// detector.LoadEcosystem("github_actions", typosquat.PopularGitHubActions())
// at startup). A nil detector returns nil.
func NewTyposquatAdapter(detector *typosquat.Detector) TyposquatLookup {
	if detector == nil {
		return nil
	}
	return &typosquatAdapter{detector: detector}
}

func (a *typosquatAdapter) Lookup(ctx context.Context, ownerSlashName string) (string, error) {
	if a == nil || a.detector == nil {
		return "", nil
	}
	res := a.detector.Check(ctx, "github_actions", ownerSlashName)
	if !res.IsSuspected {
		return "", nil
	}
	return res.SimilarTo, nil
}

// malwareAdapter wraps a *malware.GitHubActionsFeed.
type malwareAdapter struct {
	feed *malware.GitHubActionsFeed
}

// NewMalwareAdapter returns a MalwareLookup that delegates to the given
// malicious-Action feed. A nil feed returns nil.
func NewMalwareAdapter(feed *malware.GitHubActionsFeed) MalwareLookup {
	if feed == nil {
		return nil
	}
	return &malwareAdapter{feed: feed}
}

func (a *malwareAdapter) IsMalicious(ctx context.Context, owner, name, ref string) (bool, string, error) {
	if a == nil || a.feed == nil {
		return false, "", nil
	}
	return a.feed.IsMalicious(ctx, owner, name, ref)
}

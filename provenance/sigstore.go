package provenance

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/chain305/chainsaw-core/provenance/sigstoreverify"
)

// sigstoreEnv is a stripped-down view of a Sigstore bundle's JSON form
// that we walk to extract the DSSE envelope payload (an in-toto Statement)
// and any Rekor transparency-log entries.
type sigstoreEnv struct {
	DSSE struct {
		Payload     string `json:"payload"`
		PayloadType string `json:"payloadType"`
	} `json:"dsseEnvelope"`
	VerificationMaterial struct {
		TLogEntries []struct {
			LogIndex int64  `json:"logIndex"`
			LogID    string `json:"logId"`
		} `json:"tlogEntries"`
	} `json:"verificationMaterial"`
}

// inTotoStatement is the minimum subset of an in-toto v1 Statement we need
// to extract the artifact's claimed digest, the SLSA level, and the build
// materials (which carry the source commit).
type inTotoStatement struct {
	Type          string `json:"_type"`
	PredicateType string `json:"predicateType"`
	Subject       []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	Predicate map[string]any `json:"predicate"`
}

// extractInTotoStatement decodes the DSSE payload of a Sigstore bundle to
// the in-toto Statement it carries. Returns an error if the bundle isn't
// a DSSE-wrapped in-toto envelope.
func extractInTotoStatement(bundleJSON []byte) (*inTotoStatement, *sigstoreEnv, error) {
	var env sigstoreEnv
	if err := json.Unmarshal(bundleJSON, &env); err != nil {
		return nil, nil, fmt.Errorf("parse sigstore bundle: %w", err)
	}
	if env.DSSE.Payload == "" {
		return nil, &env, errors.New("bundle has no dsseEnvelope.payload")
	}
	raw, err := base64.StdEncoding.DecodeString(env.DSSE.Payload)
	if err != nil {
		return nil, &env, fmt.Errorf("decode dsse payload: %w", err)
	}
	var stmt inTotoStatement
	if err := json.Unmarshal(raw, &stmt); err != nil {
		return nil, &env, fmt.Errorf("parse in-toto statement: %w", err)
	}
	return &stmt, &env, nil
}

// subjectSHA256 returns the SHA-256 digest the in-toto statement claims
// for its (single) subject artifact, as raw bytes. Returns an error if
// the statement has no subject or no sha256 entry.
func subjectSHA256(stmt *inTotoStatement) ([]byte, error) {
	if stmt == nil || len(stmt.Subject) == 0 {
		return nil, errors.New("in-toto statement has no subject")
	}
	hexDigest, ok := stmt.Subject[0].Digest["sha256"]
	if !ok || hexDigest == "" {
		return nil, errors.New("subject has no sha256 digest")
	}
	return hex.DecodeString(hexDigest)
}

// slsaLevelFromPredicate inspects an SLSA provenance predicate and returns
// the build level it claims (1-4). Best-effort: returns 0 when the
// predicate doesn't carry explicit level information.
//
// SLSA v0.2 and v1.0 predicates differ in shape. We support both:
//   - v1.0 (https://slsa.dev/provenance/v1): builder.id + buildDefinition
//     paired with runDetails. We treat presence of buildDefinition + a
//     non-empty builder.id as L2; presence of a hosted-builder ID
//     (github.com/slsa-framework/slsa-github-generator) as L3.
//   - v0.2 (https://slsa.dev/provenance/v0.2): builder.id; v0.2 by
//     construction is at most L2.
//
// This is intentionally heuristic: the SLSA spec doesn't include an
// in-band "level" field, so verifiers must reason about builder identity
// and build-definition shape. Operators who want stricter bounds use the
// RequireBuilderID condition in policy.
func slsaLevelFromPredicate(predicateType string, predicate map[string]any) int {
	if predicate == nil {
		return 0
	}
	builderID := ""
	if b, ok := predicate["builder"].(map[string]any); ok {
		if id, ok := b["id"].(string); ok {
			builderID = id
		}
	}
	switch {
	case strings.Contains(predicateType, "slsa.dev/provenance/v1"):
		if strings.Contains(builderID, "slsa-github-generator") ||
			strings.Contains(builderID, "slsa-framework") {
			return 3
		}
		if _, ok := predicate["buildDefinition"]; ok && builderID != "" {
			return 2
		}
		return 1
	case strings.Contains(predicateType, "slsa.dev/provenance/v0.2"):
		if builderID != "" {
			return 2
		}
		return 1
	}
	return 0
}

// sourceCommitFromPredicate digs the source commit SHA out of an SLSA
// predicate. Looks at v1 buildDefinition.resolvedDependencies and v0.2
// materials. Returns "" when not present.
func sourceCommitFromPredicate(predicate map[string]any) string {
	if predicate == nil {
		return ""
	}
	if bd, ok := predicate["buildDefinition"].(map[string]any); ok {
		if deps, ok := bd["resolvedDependencies"].([]any); ok {
			for _, d := range deps {
				if dm, ok := d.(map[string]any); ok {
					if dig, ok := dm["digest"].(map[string]any); ok {
						if g, ok := dig["gitCommit"].(string); ok && g != "" {
							return g
						}
						if s, ok := dig["sha1"].(string); ok && s != "" {
							return s
						}
					}
				}
			}
		}
	}
	if mats, ok := predicate["materials"].([]any); ok {
		for _, m := range mats {
			if mm, ok := m.(map[string]any); ok {
				if dig, ok := mm["digest"].(map[string]any); ok {
					if g, ok := dig["gitCommit"].(string); ok && g != "" {
						return g
					}
					if s, ok := dig["sha1"].(string); ok && s != "" {
						return s
					}
				}
			}
		}
	}
	return ""
}

// transparencyLogURL formats the public Rekor entry URL for the first
// tlog entry in a Sigstore bundle. Empty when the bundle has no tlog
// entries (offline-signed bundles).
func transparencyLogURL(env *sigstoreEnv) string {
	if env == nil || len(env.VerificationMaterial.TLogEntries) == 0 {
		return ""
	}
	idx := env.VerificationMaterial.TLogEntries[0].LogIndex
	if idx <= 0 {
		return ""
	}
	return fmt.Sprintf("https://search.sigstore.dev/?logIndex=%d", idx)
}

// applySigstoreToResult fills the SLSA-related fields on a Result from a
// successful Sigstore verification. Mutates r in place; caller is
// responsible for setting Status.
func applySigstoreToResult(r *Result, vr *sigstoreverify.VerifyResult, bundleJSON []byte) {
	r.AttestationBundle = bundleJSON
	r.BundleFormat = "sigstore-bundle"
	r.VerifiedAt = vr.VerifiedAt
	r.CacheStale = vr.CacheStale
	r.AttestationType = "sigstore"

	if vr.Identity.SourceRepo != "" {
		r.SourceRepo = vr.Identity.SourceRepo
	}
	if vr.Identity.BuilderID != "" {
		r.BuilderID = vr.Identity.BuilderID
	}
	if vr.CacheStale {
		msg := "served from sigstore cache; live verification unavailable"
		if vr.LiveError != nil {
			msg = fmt.Sprintf("%s (%v)", msg, vr.LiveError)
		}
		r.Warnings = append(r.Warnings, msg)
	}

	stmt, env, err := extractInTotoStatement(bundleJSON)
	if err != nil {
		r.Warnings = append(r.Warnings, fmt.Sprintf("parse in-toto statement: %v", err))
		return
	}
	if env != nil {
		if u := transparencyLogURL(env); u != "" {
			r.TransparencyLogURL = u
		}
	}
	if stmt != nil {
		if len(stmt.Subject) > 0 {
			if sha, ok := stmt.Subject[0].Digest["sha256"]; ok && sha != "" {
				r.SubjectDigest = "sha256:" + sha
			}
		}
		if level := slsaLevelFromPredicate(stmt.PredicateType, stmt.Predicate); level > 0 {
			r.SLSALevel = level
		}
		if c := sourceCommitFromPredicate(stmt.Predicate); c != "" {
			r.SourceCommit = c
		}
	}
}

// noteUnverifiedBundle records that a Sigstore bundle was found but full
// verification could not run (no expected artifact digest, verifier
// disabled, or the live verifier and cache both missed). Best-effort
// identity extraction via InspectBundleIdentity is *not* a substitute for
// real verification, so callers using this path must leave Status =
// StatusUnverified.
func noteUnverifiedBundle(r *Result, bundleJSON []byte, reason string) {
	r.AttestationBundle = bundleJSON
	r.BundleFormat = "sigstore-bundle"
	r.AttestationType = "sigstore"
	r.VerifiedAt = time.Time{}
	if reason != "" {
		r.Warnings = append(r.Warnings, reason)
	}

	if id, err := sigstoreverify.InspectBundleIdentity(bundleJSON); err == nil && id != nil {
		if r.SourceRepo == "" && id.SourceRepo != "" {
			r.SourceRepo = id.SourceRepo
		}
		if r.BuilderID == "" && id.BuilderID != "" {
			r.BuilderID = id.BuilderID
		}
	}
	if stmt, env, err := extractInTotoStatement(bundleJSON); err == nil {
		if env != nil {
			if u := transparencyLogURL(env); u != "" {
				r.TransparencyLogURL = u
			}
		}
		if stmt != nil {
			if len(stmt.Subject) > 0 {
				if sha, ok := stmt.Subject[0].Digest["sha256"]; ok && sha != "" {
					r.SubjectDigest = "sha256:" + sha
				}
			}
			if level := slsaLevelFromPredicate(stmt.PredicateType, stmt.Predicate); level > 0 {
				r.SLSALevel = level
			}
			if c := sourceCommitFromPredicate(stmt.Predicate); c != "" {
				r.SourceCommit = c
			}
		}
	}
}

// runSigstoreVerify wraps the cached verifier path. It looks up the
// process-wide trusted-root verifier (which has its own short-TTL cache)
// and then runs VerifyWithCache against the per-bundle cache. The
// returned VerifyResult includes a CacheStale=true flag when Rekor/Fulcio
// were unreachable but a stale cache entry is being served.
func runSigstoreVerify(ctx context.Context, cache *sigstoreverify.BundleCache, bundleJSON, artifactSHA256 []byte) (*sigstoreverify.VerifyResult, error) {
	v, err := sigstoreverify.Default(ctx)
	if err != nil {
		// Trust root unreachable. Try the cache; if we have a stale entry
		// we can still serve a last-known-good answer.
		if cache != nil {
			if id, verifiedAt, _, ok := cache.Get(bundleJSON, artifactSHA256); ok {
				return &sigstoreverify.VerifyResult{
					Identity:   id,
					VerifiedAt: verifiedAt,
					CacheStale: true,
					LiveError:  err,
				}, nil
			}
		}
		return nil, fmt.Errorf("sigstore trust root: %w", err)
	}
	return v.VerifyWithCache(cache, bundleJSON, artifactSHA256)
}

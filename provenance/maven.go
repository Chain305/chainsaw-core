package provenance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/chain305/chainsaw-core/provenance/pgpverify"
	"github.com/chain305/chainsaw-core/provenance/sigstoreverify"
	"github.com/chain305/chainsaw-core/upstreamhttp"
)

// mavenChecker verifies Maven artifacts via either:
//  1. A .sigstore.json sidecar (Maven Central, opt-in since Jan 2025), or
//  2. A .asc GPG detached signature sidecar (mandatory on Maven Central).
//
// Package name is expected as "groupId:artifactId" (Gradle dependency
// notation). A single mavenChecker instance is registered per ecosystem
// ("maven", "gradle"); the actual upstream to probe for sidecars is
// determined per-call from the source URL passed to CheckWithSource, so
// that a "gradle" repo proxying Maven Central probes repo.maven.apache.org
// for sidecars instead of plugins.gradle.org. The baseURL field is the
// fallback used when the caller cannot supply a source URL.
type mavenChecker struct {
	client    *http.Client
	logger    *slog.Logger
	baseURL   string // fallback upstream, e.g. https://repo1.maven.org/maven2
	ecosystem string // "maven" or "gradle"
	pgp       *pgpverify.Verifier
}

func newMavenChecker(client *http.Client, logger *slog.Logger) *mavenChecker {
	return &mavenChecker{
		client:    client,
		logger:    logger,
		baseURL:   "https://repo1.maven.org/maven2",
		ecosystem: "maven",
		pgp:       pgpverify.NewVerifier(client, ""),
	}
}

func newGradleChecker(client *http.Client, logger *slog.Logger) *mavenChecker {
	// plugins.gradle.org answers every /m2 artifact with a 303 to
	// plugins-artifacts.gradle.org, and the SSRF-guarded client refuses all
	// redirects — 2,078 gradle attestations recorded "HTTP 303" as a
	// verification failure. Both the sidecar fetch and the PGP verifier need
	// the derived client; the signature and the artifact live behind the same
	// redirect. See registry_redirect.go.
	client = followRegistryRedirects(client, registryRedirectHosts)
	return &mavenChecker{
		client:    client,
		logger:    logger,
		baseURL:   "https://plugins.gradle.org/m2",
		ecosystem: "gradle",
		pgp:       pgpverify.NewVerifier(client, ""),
	}
}

func (c *mavenChecker) Ecosystem() string { return c.ecosystem }

func (c *mavenChecker) Check(ctx context.Context, packageName, version string) Result {
	return c.CheckWithSource(ctx, packageName, version, "")
}

// CheckWithSource probes the sidecar locations for the requested artifact.
// When sourceURL is non-empty it overrides the ecosystem-default baseURL,
// which is how a "gradle" repo proxying Maven Central or Google Maven ends
// up probing the correct upstream rather than plugins.gradle.org. Passing
// "" retains the historical per-ecosystem default and is used by callers
// that only know (ecosystem, name, version).
func (c *mavenChecker) CheckWithSource(ctx context.Context, packageName, version, sourceURL string) Result {
	group, artifact, ok := splitMavenCoords(packageName)
	if !ok {
		return Result{
			Status:    StatusFailed,
			Ecosystem: c.ecosystem,
			Error:     fmt.Sprintf("invalid maven coordinate %q (want groupId:artifactId)", packageName),
		}
	}
	groupPath := strings.ReplaceAll(group, ".", "/")
	base := mavenRepoBase(sourceURL, groupPath)
	if base == "" {
		base = c.baseURL
	}
	fileURL := func(ext string) string {
		return fmt.Sprintf("%s/%s/%s/%s/%s-%s.%s",
			base, groupPath, artifact, version, artifact, version, ext)
	}
	if isGoogleMavenBase(base) {
		// Google Maven publishes no sigstore bundles, and most of what it
		// hosts is an .aar: every androidx row probed `.jar.asc`, got a 404
		// and read as unsigned (232 rows on 2026-11-03), while
		// activity-1.9.0.aar.asc is there. Some of it is a .jar
		// (annotation-jvm, the Android Gradle plugin), so both are tried.
		for _, ext := range []string{"aar", "jar"} {
			if res := c.tryPGP(ctx, fileURL(ext)); res.Status != StatusMissing {
				return res
			}
		}
		return Result{Status: StatusMissing, Ecosystem: c.ecosystem}
	}
	jarURL := fileURL("jar")

	// Try Sigstore sidecar first — when present it's the richer signal.
	if res := c.trySigstore(ctx, jarURL); res.Status != StatusMissing {
		return res
	}
	// Fall back to PGP detached signature.
	return c.tryPGP(ctx, jarURL)
}

// GoogleMavenBase is Google's Maven repository, where androidx,
// com.android.*, com.google.android.* and Firebase are published instead of
// Central. maven.google.com 301s every file to this host.
const GoogleMavenBase = "https://dl.google.com/dl/android/maven2"

func isGoogleMavenBase(base string) bool {
	u, err := url.Parse(base)
	if err != nil {
		return false
	}
	h := strings.ToLower(u.Hostname())
	return h == "dl.google.com" || h == "maven.google.com"
}

// mavenRepoBase reduces a source URL to the repository root. Callers pass
// either a base (".../maven2") or the upstream URL of the file the proxy
// served (".../maven2/io/netty/netty-buffer/4.1.93.Final/netty-buffer-4.1.93.Final.pom"),
// and appending the coordinate to the second produced
// ".../netty-buffer-4.1.93.Final.pom/io/netty/..." on every such row. The root
// is everything before the coordinate's group path.
func mavenRepoBase(sourceURL, groupPath string) string {
	base := strings.TrimRight(sourceURL, "/")
	if i := strings.Index(base, "/"+groupPath+"/"); i > 0 {
		base = base[:i]
	}
	return base
}

// trySigstore fetches `.sigstore.json` and verifies the bundle.
// Returns StatusMissing if the sidecar is absent, letting the caller try
// the PGP fallback.
//
// KEPT DELIBERATELY, despite being a 404 on most coordinates. The ecosystem
// sweep flagged this as a guaranteed-404 per Maven coordinate per tick, and
// measured 2026-09-23 it is: commons-text, guava and slf4j-api all answer 404
// here and 200 on `.asc`. Removing it would still be wrong.
//
// Sidecar presence is per-ARTIFACT, not per-host: artifacts published through
// the new Central Portal do carry sigstore bundles, and there is no cheaper
// way to learn that than asking. Skipping the probe would silently downgrade
// those from a verified Sigstore bundle to PGP, or to nothing — trading a real
// provenance signal for one request.
//
// The cost is also no longer what the sweep measured. The refresh amplifier
// fixed in v0.22.8 meant every Maven row was rescanned hourly; it is now once
// per staleness window, so this is ~1 request per coordinate per 24h rather
// than per hour. If it needs reducing further, the answer is negative caching
// on the provenance client (it uses `c.client` directly and so has none),
// NOT dropping the probe.
func (c *mavenChecker) trySigstore(ctx context.Context, jarURL string) Result {
	sigURL := jarURL + ".sigstore.json"
	sigBytes, status, err := fetchBytes(ctx, c.client, sigURL, 1<<20)
	if err != nil {
		if isNotFound(status) {
			return Result{Status: StatusMissing, Ecosystem: c.ecosystem}
		}
		if res, ok := c.rateLimited("fetch sidecar", err); ok {
			return res
		}
		return Result{Status: StatusFailed, Ecosystem: c.ecosystem, Error: err.Error()}
	}

	// Compute artifact digest to feed into the Sigstore policy. Maven
	// Central publishes a .sha256 sidecar; prefer that (64 bytes vs a full
	// JAR) and fall back to streaming the JAR if the sidecar is absent or
	// unparseable.
	digest, err := c.artifactSHA256(ctx, jarURL)
	if err != nil {
		if res, ok := c.rateLimited("fetch jar for digest", err); ok {
			return res
		}
		return Result{Status: StatusFailed, Ecosystem: c.ecosystem, Error: fmt.Sprintf("fetch jar for digest: %v", err)}
	}

	verifier, err := sigstoreverify.Default(ctx)
	if err != nil {
		// Couldn't init trust root — attestation exists, just not verified.
		return Result{
			Status:          StatusUnverified,
			Ecosystem:       c.ecosystem,
			AttestationType: "sigstore",
			Error:           fmt.Sprintf("sigstore init: %v", err),
		}
	}

	id, err := verifier.Verify(sigBytes, digest[:])
	if err != nil {
		if c.logger != nil {
			c.logger.Debug(c.ecosystem+" sigstore verification failed",
				"url", sigURL, "error", err.Error())
		}
		return Result{
			Status:          StatusFailed,
			Ecosystem:       c.ecosystem,
			AttestationType: "sigstore",
			Error:           err.Error(),
		}
	}
	return Result{
		Status:          StatusVerified,
		Ecosystem:       c.ecosystem,
		AttestationType: "sigstore",
		SourceRepo:      id.SourceRepo,
		BuilderID:       id.BuilderID,
	}
}

// tryPGP fetches `.asc` and verifies the detached signature against the
// .jar contents.
//
// Status mapping:
//   - .asc missing (404)              → StatusMissing
//   - keyserver lookup failed (404 or
//     unparseable response)            → StatusUnavailable + warning
//   - signature mismatch / tampered    → StatusFailed
//   - all-good                         → StatusVerified
//
// Trust note: we do NOT validate that the issuer key is "trusted" by any
// authority. The key is whatever keys.openpgp.org returns for the issuer
// fingerprint embedded in the .asc. Operators who want a stronger root
// must enforce SignerID/BuilderID via downstream policy. We attach a
// Warning making this explicit on every successful verification.
//
// TODO(rubygems): RubyGems gem-cert (X.509 detached over data.tar.gz) is a
// separate verifier — see internal/provenance/x509rubygems.go (not yet
// created). It does NOT live here because the cert chain root is the
// gem-author's self-signed pubkey, not a PGP keyserver, and the failure
// modes (CA validity, gem unpack) don't share code with PGP detached.
func (c *mavenChecker) tryPGP(ctx context.Context, jarURL string) Result {
	ascURL := jarURL + ".asc"
	sigBytes, status, err := fetchBytes(ctx, c.client, ascURL, 1<<20)
	if err != nil {
		if isNotFound(status) {
			return Result{Status: StatusMissing, Ecosystem: c.ecosystem}
		}
		if res, ok := c.rateLimited("fetch sidecar", err); ok {
			return res
		}
		return Result{Status: StatusFailed, Ecosystem: c.ecosystem, Error: err.Error()}
	}

	// The scanner usually holds this artifact already, and the jar was the
	// heaviest Central request per gradle row (2026-11-03 trace). A signature
	// that verifies over the held bytes proves they are the jar; a signing
	// key that cannot be found is the same answer for any bytes. Any other
	// failure may only mean the held file is the .aar or .pom, so it falls
	// through to the jar itself.
	if held := artifactBytesFrom(ctx); len(held) > 0 {
		res := c.pgpResult(ctx, ascURL, bytes.NewReader(held), sigBytes)
		if res.Status == StatusVerified || res.Status == StatusUnavailable {
			return res
		}
	}

	jarStream, closeJar, err := fetchStream(ctx, c.client, jarURL)
	if err != nil {
		if res, ok := c.rateLimited("fetch jar", err); ok {
			return res
		}
		return Result{Status: StatusFailed, Ecosystem: c.ecosystem, Error: fmt.Sprintf("fetch jar: %v", err)}
	}
	defer closeJar()

	// Cap the body read at 256 MiB — larger than real Maven JARs but
	// bounded enough to fail fast on a pathological response.
	return c.pgpResult(ctx, ascURL, io.LimitReader(jarStream, 256<<20), sigBytes)
}

// pgpResult verifies sigBytes over artifact and maps the outcome. Only a
// missing signing key reads as StatusUnavailable.
func (c *mavenChecker) pgpResult(ctx context.Context, ascURL string, artifact io.Reader, sigBytes []byte) Result {
	uid, err := c.pgp.Verify(ctx, artifact, sigBytes)
	if err != nil {
		if c.logger != nil {
			c.logger.Debug(c.ecosystem+" pgp verification failed",
				"url", ascURL, "error", err.Error())
		}
		// "no candidate public keys found on keyserver" → key fetch
		// failed, not a tampered artifact. Map to StatusUnavailable so
		// the caller doesn't penalise the package for an outage.
		msg := err.Error()
		if strings.Contains(msg, "no candidate public keys") {
			return Result{
				Status:          StatusUnavailable,
				Ecosystem:       c.ecosystem,
				AttestationType: "pgp-detached",
				BundleFormat:    "gpg-detached",
				Warnings:        []string{"pgp signing key not found on keyserver " + c.pgp.Keyserver()},
				Error:           msg,
			}
		}
		return Result{
			Status:          StatusFailed,
			Ecosystem:       c.ecosystem,
			AttestationType: "pgp-detached",
			BundleFormat:    "gpg-detached",
			Error:           msg,
		}
	}
	builderID := uid.Email
	if builderID == "" {
		builderID = uid.Name
	}
	if builderID == "" {
		builderID = uid.Fingerprint
	}
	warnings := []string{
		"pgp key fetched from " + keyserverOf(uid, c.pgp) + "; trust not validated (no web-of-trust, no key registry)",
	}
	if uid.KeyExpired {
		warnings = append(warnings, "pgp signing key has expired since; the signature was made "+
			uid.SignedAt.UTC().Format("2006-01-02")+", while it was valid")
	}
	return Result{
		Status:          StatusVerified,
		Ecosystem:       c.ecosystem,
		AttestationType: "pgp-detached",
		BundleFormat:    "gpg-detached",
		BuilderID:       builderID,
		Warnings:        warnings,
	}
}

// rateLimited maps a fetch refused for rate to StatusUnavailable. StatusFailed
// is what a tampered artifact gets; a 429 from the repository, or our own
// limiter refusing to ask (which covers the Sonatype standoff and the paused
// background bucket), says nothing about the artifact. nuget.go already maps
// every non-404 fetch error this way. Measured 2026-11-03: after v0.22.139,
// 22 of the 28 "failed" gradle rows in a 34-row sample were exactly this.
func (c *mavenChecker) rateLimited(what string, err error) (Result, bool) {
	if !errors.Is(err, errHTTP429) &&
		!errors.Is(err, upstreamhttp.ErrRateLimitedLocally) &&
		!errors.Is(err, upstreamhttp.ErrBackgroundPaused) {
		return Result{}, false
	}
	return Result{
		Status:    StatusUnavailable,
		Ecosystem: c.ecosystem,
		Reason:    ReasonRateLimited,
		Error:     fmt.Sprintf("%s: %v", what, err),
	}, true
}

// errHTTP429 lets rateLimited recognise an upstream 429 by type rather than
// by message. Its text is the plain "HTTP 429" every other status produces.
var errHTTP429 = errors.New("HTTP 429")

func httpStatusError(code int) error {
	if code == http.StatusTooManyRequests {
		return errHTTP429
	}
	return fmt.Errorf("HTTP %d", code)
}

// splitMavenCoords parses "groupId:artifactId" into its two parts.
// Proxy traffic sometimes encodes this as "groupId/artifactId" too; accept
// both.
func splitMavenCoords(name string) (group, artifact string, ok bool) {
	if idx := strings.Index(name, ":"); idx > 0 && idx < len(name)-1 {
		return name[:idx], name[idx+1:], true
	}
	// Fall back to last-slash split for proxy-path-style coords.
	if idx := strings.LastIndex(name, "/"); idx > 0 && idx < len(name)-1 {
		return strings.ReplaceAll(name[:idx], "/", "."), name[idx+1:], true
	}
	return "", "", false
}

// fetchBytes GETs the URL and returns the body, the HTTP status (even on
// error, so callers can branch on 404), and any error.
// artifactSHA256 returns the SHA-256 of the Maven artifact at jarURL.
// Maven Central publishes a `{jar}.sha256` sidecar (plain text — 64 hex
// chars, optionally followed by whitespace + filename). We try that first
// to avoid downloading the full JAR just to hash it, falling back to
// streaming the jar on any failure.
func (c *mavenChecker) artifactSHA256(ctx context.Context, jarURL string) ([32]byte, error) {
	body, status, err := fetchBytes(ctx, c.client, jarURL+".sha256", 256)
	if err == nil && status == http.StatusOK {
		if d, ok := parseHexSHA256(body); ok {
			return d, nil
		}
	}
	return fetchSHA256(ctx, c.client, jarURL)
}

// parseHexSHA256 parses the body of a .sha256 sidecar: the first
// whitespace-delimited token should be the 64-char hex digest. Returns ok=false
// if the body is malformed.
func parseHexSHA256(body []byte) ([32]byte, bool) {
	var d [32]byte
	fields := strings.Fields(string(body))
	if len(fields) == 0 {
		return d, false
	}
	raw, err := hex.DecodeString(fields[0])
	if err != nil || len(raw) != 32 {
		return d, false
	}
	copy(d[:], raw)
	return d, true
}

// headContentTooLarge issues a HEAD request and returns true if the
// advertised Content-Length exceeds limit. Returns (false, nil) when the
// server doesn't advertise a length or the response isn't 200 — in those
// cases the caller falls through to the normal GET path.
func headContentTooLarge(ctx context.Context, client *http.Client, url string, limit int64) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, nil
	}
	return resp.ContentLength > limit, nil
}

// fetchStream starts an HTTP GET and returns the response body as a
// streaming io.Reader plus a close function. Prefer this over fetchBytes
// when the caller processes the body incrementally (hashing, PGP verify,
// zip extraction) instead of needing the whole buffer.
func fetchStream(ctx context.Context, client *http.Client, url string) (io.Reader, func(), error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, func() {}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, func() {}, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, func() {}, httpStatusError(resp.StatusCode)
	}
	return resp.Body, func() { _ = resp.Body.Close() }, nil
}

// isNotFound returns true only for HTTP 404 / 410 responses. Use this to
// distinguish a "definitively absent" signal from a "network error"
// (transient) when mapping fetchBytes errors to Result statuses.
func isNotFound(status int) bool {
	return status == http.StatusNotFound || status == http.StatusGone
}

func fetchBytes(ctx context.Context, client *http.Client, url string, limit int64) ([]byte, int, error) {
	return fetchBytesBearer(ctx, client, url, limit, "")
}

// fetchBytesBearer is fetchBytes with an optional bearer token.
func fetchBytesBearer(ctx context.Context, client *http.Client, url string, limit int64, bearer string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, httpStatusError(resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

// fetchBytesDetectTruncation is like fetchBytes but reports whether the body
// exceeded limit. io.LimitReader returns EOF (not an error) at the cap, so a
// plain fetchBytes silently truncates an oversize body — which, when the
// caller hashes the result, manufactures a false digest mismatch. This
// variant reads one byte past the limit: if that extra byte is present the
// body was larger than limit (truncated == true) and the caller must NOT
// treat a hash of the truncated prefix as authoritative.
func fetchBytesDetectTruncation(ctx context.Context, client *http.Client, url string, limit int64) (body []byte, status int, truncated bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, false, httpStatusError(resp.StatusCode)
	}
	// Read limit+1 so a full read of limit+1 bytes proves the body overflowed.
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, resp.StatusCode, false, err
	}
	if int64(len(b)) > limit {
		return b[:limit], resp.StatusCode, true, nil
	}
	return b, resp.StatusCode, false, nil
}

// fetchSHA256 streams the artifact and returns its SHA-256 digest without
// buffering the full body in memory.
func fetchSHA256(ctx context.Context, client *http.Client, url string) ([32]byte, error) {
	var zero [32]byte
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return zero, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return zero, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return zero, httpStatusError(resp.StatusCode)
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(resp.Body, 500<<20)); err != nil { // 500 MiB cap
		return zero, err
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

type artifactBytesKey struct{}

// WithArtifactBytes attaches the artifact bytes the caller already holds for
// the coordinate being checked, so a checker can verify a detached signature
// without downloading the artifact again. The bytes are a hint, not a claim:
// the caller may hold a different file of the same coordinate (an .aar or a
// .pom where the checker wants the .jar), so a checker must still verify
// against them and fall back when they do not match. Only the Maven/Gradle
// PGP path reads them today.
func WithArtifactBytes(ctx context.Context, b []byte) context.Context {
	if len(b) == 0 {
		return ctx
	}
	return context.WithValue(ctx, artifactBytesKey{}, b)
}

func artifactBytesFrom(ctx context.Context) []byte {
	b, _ := ctx.Value(artifactBytesKey{}).([]byte)
	return b
}

func keyserverOf(uid *pgpverify.SignerUID, v *pgpverify.Verifier) string {
	if uid.Keyserver != "" {
		return uid.Keyserver
	}
	return v.Keyserver()
}

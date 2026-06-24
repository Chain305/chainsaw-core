package swift

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// GitUpstream synthesizes SE-0292 registry responses from git remotes.
//
// SPM requests are translated into git operations:
//
//	GET /{scope}/{name}               → git ls-remote --tags <url>
//	GET /{scope}/{name}/{version}     → git ls-remote + shallow-clone tag (for publishedAt)
//	GET /{scope}/{name}/{version}.zip → git archive --format=zip <tag>
//	GET /{scope}/{name}/{version}/Package.swift → shallow clone, read file
//	GET /identifiers?url=<git-url>    → reverse lookup in IdentifierMap
//
// This upstream is intentionally conservative: it does NOT synthesize
// SE-0391 CMS signatures (there is no signer), and it does NOT attempt
// to populate `metadata.licenseURL` for license policies. Those fields
// appear only when a real SE-0292 registry is the upstream. The proxy
// continues to work for git-translated packages but `has_provenance`
// evaluates to false.
type GitUpstream struct {
	Map        *IdentifierMap
	GitBin     string        // defaults to "git" on $PATH
	Timeout    time.Duration // per-operation timeout; defaults to 60s
	CacheRoot  string        // working directory for clones; defaults to os.TempDir()
	HTTPClient *http.Client  // retained for future use; not wired yet
}

// NewGitUpstream constructs a GitUpstream with sane defaults.
func NewGitUpstream(m *IdentifierMap, cacheRoot string) *GitUpstream {
	if cacheRoot == "" {
		cacheRoot = filepath.Join(os.TempDir(), "chainsaw-swift-git")
	}
	return &GitUpstream{
		Map:       m,
		GitBin:    "git",
		Timeout:   60 * time.Second,
		CacheRoot: cacheRoot,
	}
}

// ReleasesResponse mirrors the SE-0292 §4.1 list-releases body.
type ReleasesResponse struct {
	Releases map[string]ReleaseEntry `json:"releases"`
}

// ReleaseEntry is a single entry inside ReleasesResponse.
type ReleaseEntry struct {
	URL     string   `json:"url"`
	Problem *Problem `json:"problem,omitempty"`
}

// Problem is an RFC 7807 Problem Details document.
type Problem struct {
	Status int    `json:"status"`
	Title  string `json:"title"`
}

// ReleaseMetadata mirrors the SE-0292 §4.2.2 release-metadata body.
type ReleaseMetadata struct {
	ID          string     `json:"id"`
	Version     string     `json:"version"`
	Resources   []Resource `json:"resources"`
	Metadata    Metadata   `json:"metadata"`
	PublishedAt string     `json:"publishedAt,omitempty"` // ISO 8601 / RFC 3339
}

// Resource is one downloadable artifact for a release.
type Resource struct {
	Name     string  `json:"name"`
	Type     string  `json:"type"`
	Checksum string  `json:"checksum"`
	Signing  *string `json:"signing,omitempty"` // nil for git-synthesized packages
}

// Metadata carries the optional author/license fields.
type Metadata struct {
	RepositoryURLs []string `json:"repositoryURLs,omitempty"`
}

// semVerTagRE matches tags like "1.2.3", "v1.2.3", "1.2.3-beta.1".
// Pre-release suffix is captured permissively — SPM's own SemVer parser
// handles the details.
var semVerTagRE = regexp.MustCompile(`^v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)$`)

// ListReleases synthesizes the SE-0292 list-releases response for an
// identifier. proxyPrefix is the path segment that should precede each
// release URL (e.g. "/repository/@acme/swift-proxy").
func (g *GitUpstream) ListReleases(ctx context.Context, identifier, proxyPrefix string) (*ReleasesResponse, error) {
	gitURL, ok := g.Map.Resolve(identifier)
	if !ok {
		return nil, errNotFound
	}
	tags, err := g.lsRemoteTags(ctx, gitURL)
	if err != nil {
		return nil, err
	}
	scope, name := SplitIdentifier(identifier)
	out := &ReleasesResponse{Releases: make(map[string]ReleaseEntry, len(tags))}
	for version := range tags {
		out.Releases[version] = ReleaseEntry{
			URL: fmt.Sprintf("%s/%s/%s/%s", strings.TrimSuffix(proxyPrefix, "/"), scope, name, version),
		}
	}
	return out, nil
}

// GetReleaseMetadata synthesizes the SE-0292 release-metadata response
// for a specific version.
func (g *GitUpstream) GetReleaseMetadata(ctx context.Context, identifier, version, proxyPrefix string) (*ReleaseMetadata, error) {
	gitURL, ok := g.Map.Resolve(identifier)
	if !ok {
		return nil, errNotFound
	}
	tags, err := g.lsRemoteTags(ctx, gitURL)
	if err != nil {
		return nil, err
	}
	commit, ok := tags[version]
	if !ok {
		return nil, errNotFound
	}
	publishedAt, _ := g.tagDate(ctx, gitURL, version, commit)

	scope, name := SplitIdentifier(identifier)
	meta := &ReleaseMetadata{
		ID:      identifier,
		Version: version,
		Resources: []Resource{{
			Name:     "source-archive",
			Type:     "application/zip",
			Checksum: "", // filled in by the caller when the zip is generated
		}},
		Metadata: Metadata{
			RepositoryURLs: []string{gitURL},
		},
	}
	if !publishedAt.IsZero() {
		meta.PublishedAt = publishedAt.UTC().Format(time.RFC3339)
	}
	_ = scope
	_ = name
	return meta, nil
}

// BuildArchive synthesizes a source archive zip for a tag. Returns the
// zip bytes and a base64-encoded SHA-256 digest suitable for the
// `Digest: sha-256=<digest>` response header.
func (g *GitUpstream) BuildArchive(ctx context.Context, identifier, version string) (zipBytes []byte, digest string, err error) {
	gitURL, ok := g.Map.Resolve(identifier)
	if !ok {
		return nil, "", errNotFound
	}
	tags, err := g.lsRemoteTags(ctx, gitURL)
	if err != nil {
		return nil, "", err
	}
	tagRef, ok := tags[version]
	if !ok {
		// Also try the raw version string, in case ls-remote gave us a
		// v-prefixed tag and the caller asked without the prefix.
		if c, alt := tags["v"+version]; alt {
			tagRef = c
			ok = true
		}
	}
	if !ok {
		return nil, "", errNotFound
	}

	_, name := SplitIdentifier(identifier)
	prefix := fmt.Sprintf("%s-%s/", name, version)

	repoDir, err := g.ensureRepo(ctx, identifier, gitURL)
	if err != nil {
		return nil, "", err
	}
	// Ensure the tag ref is present locally.
	if err := g.fetchTag(ctx, repoDir, version, tagRef); err != nil {
		return nil, "", err
	}
	zipBytes, err = g.gitArchive(ctx, repoDir, version, prefix)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(zipBytes)
	digest = base64.StdEncoding.EncodeToString(sum[:])
	return zipBytes, digest, nil
}

// FetchManifest returns the raw bytes of `Package.swift` (or a
// version-specific `Package@swift-X.Y.swift`) at the given tag.
// Returns errNotFound if the tag or manifest is absent.
func (g *GitUpstream) FetchManifest(ctx context.Context, identifier, version, swiftVersion string) ([]byte, error) {
	gitURL, ok := g.Map.Resolve(identifier)
	if !ok {
		return nil, errNotFound
	}
	tags, err := g.lsRemoteTags(ctx, gitURL)
	if err != nil {
		return nil, err
	}
	tagRef, ok := tags[version]
	if !ok {
		return nil, errNotFound
	}
	repoDir, err := g.ensureRepo(ctx, identifier, gitURL)
	if err != nil {
		return nil, err
	}
	if err := g.fetchTag(ctx, repoDir, version, tagRef); err != nil {
		return nil, err
	}
	file := "Package.swift"
	if swiftVersion = strings.TrimSpace(swiftVersion); swiftVersion != "" {
		file = fmt.Sprintf("Package@swift-%s.swift", swiftVersion)
	}
	return g.gitShow(ctx, repoDir, version, file)
}

// --- git CLI helpers ---

var errNotFound = errors.New("swift git upstream: not found")

// ErrNotFound is returned when a referenced package, version, or tag
// cannot be located via git.
var ErrNotFound = errNotFound

// validateGitArg rejects strings that git would parse as a flag. This
// is defense-in-depth against argument injection: even though we also
// insert a literal "--" separator on every subcommand's positional
// arguments (the structural fix), we additionally refuse any string
// beginning with "-" so that a malformed upstream config can't pass
// something like "--upload-pack=/tmp/evil" as a URL.
//
// Empty strings are allowed — git subcommands have their own handling
// for missing arguments, and we don't want to mask that behavior with
// a different error.
func validateGitArg(s string) error {
	if strings.HasPrefix(s, "-") {
		return fmt.Errorf("swift git upstream: refusing argument starting with '-': %q", s)
	}
	return nil
}

// lsRemoteTags returns a map of semver-parsed version string → commit
// SHA for every tag advertised by the upstream git remote.
func (g *GitUpstream) lsRemoteTags(ctx context.Context, gitURL string) (map[string]string, error) {
	if err := validateGitArg(gitURL); err != nil {
		return nil, err
	}
	stdout, err := g.runGit(ctx, "", "ls-remote", "--tags", "--", gitURL)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		sha, ref := fields[0], fields[1]
		const prefix = "refs/tags/"
		if !strings.HasPrefix(ref, prefix) {
			continue
		}
		tag := strings.TrimPrefix(ref, prefix)
		tag = strings.TrimSuffix(tag, "^{}")
		m := semVerTagRE.FindStringSubmatch(tag)
		if m == nil {
			continue
		}
		version := m[1]
		// Prefer the peeled ref (tag^{}) when both are present.
		if existing, had := out[version]; had && !strings.HasSuffix(ref, "^{}") && strings.HasSuffix(existing, "-peeled") {
			continue
		}
		out[version] = sha
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// tagDate returns the tagger date (annotated tag) or committer date of
// the referenced commit as a best-effort publishedAt source.
func (g *GitUpstream) tagDate(ctx context.Context, gitURL, version, commit string) (time.Time, error) {
	// Do a cheap single-tag fetch into a throwaway bare repo to read
	// the date — ls-remote doesn't return tag dates.
	repoDir, err := g.ensureRepo(ctx, "date-"+commit[:minInt(8, len(commit))], gitURL)
	if err != nil {
		return time.Time{}, err
	}
	if err := g.fetchTag(ctx, repoDir, version, commit); err != nil {
		return time.Time{}, err
	}
	// fetchTag already ran validateGitArg on version and commit.
	// Prefer annotated tag date ("for-each-ref %(taggerdate:iso-strict)"),
	// fall back to committer date. The version is embedded in a fully
	// qualified `refs/tags/` prefix so it cannot be confused with a flag.
	tagOut, err := g.runGit(ctx, repoDir, "for-each-ref", "--format=%(taggerdate:iso-strict)", "refs/tags/"+version)
	if err == nil {
		if t, perr := time.Parse(time.RFC3339, strings.TrimSpace(string(tagOut))); perr == nil {
			return t, nil
		}
	}
	// git show treats args after `--` as paths, not revisions, so we
	// can't use `--` to separate the commit. Rely on validateGitArg
	// above to reject anything starting with `-`.
	commitOut, err := g.runGit(ctx, repoDir, "show", "-s", "--format=%cI", commit)
	if err != nil {
		return time.Time{}, err
	}
	return time.Parse(time.RFC3339, strings.TrimSpace(string(commitOut)))
}

// ensureRepo returns the path to a bare repo (in g.CacheRoot) for
// `identifier`. Creates it if missing.
func (g *GitUpstream) ensureRepo(ctx context.Context, identifier, gitURL string) (string, error) {
	if err := validateGitArg(gitURL); err != nil {
		return "", err
	}
	safeID := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "*", "_", "?", "_", "\"", "_", "<", "_", ">", "_", "|", "_").Replace(identifier)
	dir := filepath.Join(g.CacheRoot, safeID+".git")
	if err := os.MkdirAll(g.CacheRoot, 0o750); err != nil {
		return "", err
	}
	if _, err := os.Stat(filepath.Join(dir, "HEAD")); err == nil {
		return dir, nil
	}
	// `dir` is a filepath.Join result rooted at g.CacheRoot, so it
	// starts with the configured cache prefix and cannot begin with
	// `-` unless CacheRoot itself does. Defend anyway.
	if err := validateGitArg(dir); err != nil {
		return "", err
	}
	if _, err := g.runGit(ctx, "", "init", "--bare", dir); err != nil {
		return "", err
	}
	// `git remote add` does not accept a `--` flag terminator, so we
	// rely on validateGitArg above to reject flag-like URLs.
	if _, err := g.runGit(ctx, dir, "remote", "add", "origin", gitURL); err != nil {
		// If remote already exists from a partial init, ignore.
		if !strings.Contains(err.Error(), "already exists") {
			return "", err
		}
	}
	return dir, nil
}

// fetchTag fetches a single tag into the bare repo.
func (g *GitUpstream) fetchTag(ctx context.Context, repoDir, version, commit string) error {
	if err := validateGitArg(version); err != nil {
		return err
	}
	if err := validateGitArg(commit); err != nil {
		return err
	}
	// Use fully-qualified refspecs so `version` is always positioned
	// where git expects a ref name rather than a flag. The validateGitArg
	// check above prevents a `-` prefix from sneaking through.
	_, err := g.runGit(ctx, repoDir, "fetch", "--depth=1", "origin", "refs/tags/"+version+":refs/tags/"+version)
	if err != nil {
		// Some repos ship lightweight tags that git fetch won't find by
		// name — fall back to fetching the commit directly.
		_, err2 := g.runGit(ctx, repoDir, "fetch", "--depth=1", "origin", commit)
		return err2
	}
	return nil
}

// gitArchive streams `git archive --format=zip --prefix=<prefix>
// <refspec>` to a buffer.
func (g *GitUpstream) gitArchive(ctx context.Context, repoDir, refspec, prefix string) ([]byte, error) {
	if err := validateGitArg(refspec); err != nil {
		return nil, err
	}
	// `git archive` does not consistently honour `--` as an options
	// terminator across versions (it routes remaining args to paths
	// inside the tree), so we defend solely with validateGitArg.
	args := []string{"archive", "--format=zip", "--prefix=" + prefix, refspec}
	return g.runGit(ctx, repoDir, args...)
}

// gitShow returns the contents of a file at a given revision.
func (g *GitUpstream) gitShow(ctx context.Context, repoDir, rev, path string) ([]byte, error) {
	if err := validateGitArg(rev); err != nil {
		return nil, err
	}
	// The positional argument is `<rev>:<path>`; since rev has no `-`
	// prefix the combined string cannot be parsed as a flag.
	return g.runGit(ctx, repoDir, "show", rev+":"+path)
}

// runGit executes the git binary with the given args in workDir,
// returning stdout. Stderr is included in the error when git exits
// non-zero.
func (g *GitUpstream) runGit(ctx context.Context, workDir string, args ...string) ([]byte, error) {
	bin := g.GitBin
	if bin == "" {
		bin = "git"
	}
	timeout := g.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...)
	if workDir != "" {
		cmd.Dir = workDir
	}
	// Don't let SSH or credential helpers block on stdin.
	cmd.Stdin = strings.NewReader("")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, truncate(stderr.String(), 256))
	}
	return out, nil
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// --- ResponseBuilder helpers that turn the above into HTTP responses ---

// SynthesizeReleasesBody builds a JSON body + headers for a list-releases
// request. proxyPrefix is passed through to URL synthesis.
func SynthesizeReleasesBody(body *ReleasesResponse) (bytes []byte, contentType string, err error) {
	out, err := json.Marshal(body)
	if err != nil {
		return nil, "", err
	}
	return out, "application/vnd.swift.registry.v1+json", nil
}

// SynthesizeReleaseMetadataBody renders a release-metadata body.
func SynthesizeReleaseMetadataBody(meta *ReleaseMetadata) ([]byte, string, error) {
	out, err := json.Marshal(meta)
	if err != nil {
		return nil, "", err
	}
	return out, "application/vnd.swift.registry.v1+json", nil
}

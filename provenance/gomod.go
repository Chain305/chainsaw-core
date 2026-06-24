package provenance

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb/note"
)

// sumdbVKey is the well-known verifier key for sum.golang.org. Public and
// stable; baking it in lets us verify sumdb notes offline once fetched.
// See https://go.dev/blog/module-mirror-launch.
const sumdbVKey = "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ggk+ez7SUGOVmbro"

// gomodChecker verifies Go modules against the sum.golang.org transparency
// log. This is a weaker provenance signal than Sigstore (it binds
// (module, version) → hash but not to a publisher identity), so we
// surface AttestationType: "sumdb" distinctly.
type gomodChecker struct {
	client *http.Client
	logger *slog.Logger
}

func newGomodChecker(client *http.Client, logger *slog.Logger) *gomodChecker {
	return &gomodChecker{client: client, logger: logger}
}

func (c *gomodChecker) Ecosystem() string { return "go" }

func (c *gomodChecker) Check(ctx context.Context, packageName, version string) Result {
	// Go module paths and versions use a specific escaping for sumdb URLs:
	// uppercase letters map to '!' + lowercase, and the '+build' metadata
	// separator in versions (e.g. v1.0.0+incompatible) is left intact —
	// url.PathEscape would incorrectly percent-encode the '+'.
	escModule, err := module.EscapePath(packageName)
	if err != nil {
		return Result{Status: StatusFailed, Ecosystem: "go", Error: fmt.Sprintf("escape module: %v", err)}
	}
	escVersion, err := module.EscapeVersion(version)
	if err != nil {
		return Result{Status: StatusFailed, Ecosystem: "go", Error: fmt.Sprintf("escape version: %v", err)}
	}
	reqURL := fmt.Sprintf("https://sum.golang.org/lookup/%s@%s", escModule, escVersion)

	body, status, err := fetchBytes(ctx, c.client, reqURL, 1<<20)
	if err != nil {
		if isNotFound(status) {
			return Result{Status: StatusMissing, Ecosystem: "go"}
		}
		return Result{Status: StatusFailed, Ecosystem: "go", Error: err.Error()}
	}

	// The response is three lines (module@version h1: digest, tree size
	// and root hash line) followed by a blank line and a signed note
	// covering the tree head. The h1: block is appended above the note.
	// Split into the human-readable prefix (lookup output) and the note.
	lookup, signedNote, ok := splitSumdbLookup(body)
	if !ok {
		return Result{Status: StatusFailed, Ecosystem: "go", Error: "malformed sumdb response"}
	}
	_ = lookup // retained in case future logic wants the h1 hash

	verifier, err := note.NewVerifier(sumdbVKey)
	if err != nil {
		return Result{Status: StatusFailed, Ecosystem: "go", Error: fmt.Sprintf("sumdb key: %v", err)}
	}
	verifiers := note.VerifierList(verifier)
	if _, err := note.Open(signedNote, verifiers); err != nil {
		if c.logger != nil {
			c.logger.Debug("go sumdb note verification failed",
				"package", packageName, "version", version, "url", reqURL, "error", err.Error())
		}
		return Result{
			Status:          StatusFailed,
			Ecosystem:       "go",
			AttestationType: "sumdb",
			Error:           err.Error(),
		}
	}

	return Result{
		Status:          StatusVerified,
		Ecosystem:       "go",
		AttestationType: "sumdb",
		BuilderID:       "sum.golang.org",
		SourceRepo:      inferGoSourceRepo(packageName),
	}
}

// splitSumdbLookup splits the /lookup response. The format is:
//
//	<module>@<version> h1:<hash>\n
//	<module>@<version>/go.mod h1:<hash>\n
//	\n
//	<signed note ...>
//
// Returns the prefix and the note body. We locate the split by scanning
// for the first blank line.
func splitSumdbLookup(body []byte) (prefix, signedNote []byte, ok bool) {
	idx := strings.Index(string(body), "\n\n")
	if idx < 0 {
		return nil, nil, false
	}
	return body[:idx+1], body[idx+2:], true
}

// inferGoSourceRepo guesses the source repo URL for known VCS hosts
// encoded in the Go module path. Returns empty for module paths that
// don't map cleanly.
func inferGoSourceRepo(module string) string {
	switch {
	case strings.HasPrefix(module, "github.com/"),
		strings.HasPrefix(module, "gitlab.com/"),
		strings.HasPrefix(module, "bitbucket.org/"):
		parts := strings.SplitN(module, "/", 4)
		if len(parts) >= 3 {
			return "https://" + parts[0] + "/" + parts[1] + "/" + parts[2]
		}
	}
	return ""
}

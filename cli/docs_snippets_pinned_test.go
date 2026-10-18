package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/githubactions"
)

// Since v0.22.114 pr-scan blocks every action referenced by tag or branch
// except Chain305's own Guard Action, and since v0.22.115 every action whose
// publisher is not on the known-publisher list. The workflows our docs and
// templates tell customers to copy must therefore pin by commit SHA and use
// known publishers, or the PR that adds them fails the guard they install.
func TestCustomerWorkflowSnippetsArePinned(t *testing.T) {
	root := filepath.Join("..", "..")
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Skip("monorepo docs not present (open-core export)")
	}
	paths := []string{
		"how-tos-site/content", "internal/server/howtos/tutorials", "docs/enforcement",
		"docs/ONBOARDING.md", "core/README.md",
		"enforcement/github-actions/workflow-example.yml", "enforcement/github-actions/marketplace/LISTING.md",
	}
	usesRE := regexp.MustCompile(`uses:\s*["']?([A-Za-z0-9_.-]+)/[A-Za-z0-9_./-]+@([A-Za-z0-9_.-]+)`)
	shaRE := regexp.MustCompile(`^[0-9a-f]{40}$`)
	known := map[string]bool{}
	for _, o := range githubactions.DefaultKnownPublishers() {
		known[o] = true
	}
	var bad []string
	for _, p := range paths {
		_ = filepath.Walk(filepath.Join(root, p), func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if ext := filepath.Ext(path); ext != ".md" && ext != ".yml" && ext != ".yaml" {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			for i, line := range strings.Split(string(b), "\n") {
				for _, m := range usesRE.FindAllStringSubmatch(line, -1) {
					owner := strings.ToLower(m[1])
					pinned := owner == "chain305" || shaRE.MatchString(m[2])
					if pinned && known[owner] {
						continue
					}
					rel, _ := filepath.Rel(root, path)
					bad = append(bad, rel+":"+itoa(i+1)+": "+strings.TrimSpace(line))
				}
			}
			return nil
		})
	}
	if len(bad) > 0 {
		t.Fatalf("customer-facing workflow snippets that pr-scan would block (pin by commit SHA; known publishers only):\n  %s", strings.Join(bad, "\n  "))
	}
}

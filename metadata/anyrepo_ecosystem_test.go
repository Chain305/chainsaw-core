package metadata

import (
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/tenancy"
)

// TestGetVulnerabilityMetadataAnyRepoScopesByEcosystem is the Wave I (I-1)
// guard. The federated overlay reads an org's Trivy rows with no repository
// name; before I-1 that read ignored the ecosystem, so an org whose pip
// foo@1.0.0 carried CVEs had them overlaid onto npm foo@1.0.0.
//
// Reverting GetVulnerabilityMetadataAnyRepo to the ecosystem-blind query
// fails the first assertion: the newer pip row wins "latest" and answers the
// npm lookup.
func TestGetVulnerabilityMetadataAnyRepoScopesByEcosystem(t *testing.T) {
	s := openTestStore(t)
	db := s.sql.DB()
	org := tenancy.NormalizeOrgID(tenancy.DefaultOrgID)
	stamp := strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	pkg := "wavei-anyrepo-" + stamp
	pipRepo, npmRepo, orphanRepo := "wavei-pip-"+stamp, "wavei-npm-"+stamp, "wavei-gone-"+stamp

	for _, r := range []struct{ name, format string }{{pipRepo, "pip"}, {npmRepo, "npm"}} {
		if _, err := db.Exec(`INSERT INTO repositories(org_id, name, format, type, remote_url) VALUES(?,?,?,?,?)`,
			org, r.name, r.format, "proxy", "https://example.invalid"); err != nil {
			t.Fatalf("insert repository %s: %v", r.name, err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM vulnerability_metadata WHERE org_id=? AND package=?`, org, pkg)
		_, _ = db.Exec(`DELETE FROM repositories WHERE org_id=? AND name IN (?,?)`, org, pipRepo, npmRepo)
	})

	now := time.Now().UTC().Truncate(time.Second)
	set := func(repo string, scanned time.Time, cve string) {
		t.Helper()
		if err := s.SetVulnerabilityMetadata(VulnerabilityMetadata{
			Repository: repo, Package: pkg, Version: "1.0.0",
			IsVulnerable: true, CVEs: []string{cve}, ScannedAt: scanned,
		}); err != nil {
			t.Fatalf("SetVulnerabilityMetadata(%s): %v", repo, err)
		}
	}

	// Only a pip row, and it is the newest thing there is.
	set(pipRepo, now, "CVE-PIP-ONLY")
	if got, err := s.GetVulnerabilityMetadataAnyRepo(pkg, "1.0.0", "npm"); err != ErrNotFound {
		t.Fatalf("npm lookup answered by a pip row: got %+v err=%v, want ErrNotFound", got, err)
	}
	if got, err := s.GetVulnerabilityMetadataAnyRepo(pkg, "1.0.0", "pypi"); err != nil || got.Repository != pipRepo {
		t.Fatalf("pypi lookup must still find the pip row: got %+v err=%v", got, err)
	}

	// An older npm row: the npm lookup must pick it even though the pip row
	// is newer, i.e. "latest" is applied AFTER the ecosystem filter.
	set(npmRepo, now.Add(-time.Hour), "CVE-NPM")
	if got, err := s.GetVulnerabilityMetadataAnyRepo(pkg, "1.0.0", "npm"); err != nil || got.Repository != npmRepo {
		t.Fatalf("npm lookup: got %+v err=%v, want the npm row", got, err)
	}

	// An orphan row (repository deleted, no repositories row) is newest and
	// must still answer: an unresolvable format is not proof of a different
	// ecosystem, so it is disclosed rather than hidden.
	set(orphanRepo, now.Add(time.Hour), "CVE-ORPHAN")
	if got, err := s.GetVulnerabilityMetadataAnyRepo(pkg, "1.0.0", "npm"); err != nil || got.Repository != orphanRepo {
		t.Fatalf("orphan row must still satisfy the npm lookup: got %+v err=%v", got, err)
	}

	// No ecosystem: historical behaviour, newest row regardless.
	if got, err := s.GetVulnerabilityMetadataAnyRepo(pkg, "1.0.0", ""); err != nil || got.Repository != orphanRepo {
		t.Fatalf("ecosystem-less lookup: got %+v err=%v, want the newest row", got, err)
	}
}

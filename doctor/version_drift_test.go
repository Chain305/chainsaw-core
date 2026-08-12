package doctor

// Regression tests for D1: `doctor --upgrade-check --docker-compose-path`
// printed the Postgres password out of the compose file as the
// "compose-pinned version".
//
// The old matcher was strings.Index(text, "chainsaw:") over the whole file,
// which on this repo's OWN dockerized/docker-compose.ha.yml first matched
// inside CHAINSAW_DATABASE_URL and echoed everything after the username
// colon — starting with the password — to stdout and into --json.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// composeHA mirrors the shape of the repo's real docker-compose.ha.yml: a
// digest-pinned chainsaw image and a DSN carrying a password, in that order.
const composeHA = `services:
  postgres:
    image: postgres@sha256:c7526c0f6c3f30260a563d7bcf8ad778effac59a44f8ffa86678c35418338609
  proxy:
    image: chain305/chainsaw-firewall@sha256:3d05ffa9955f348fd917fc82e659d00fa46df9e1dd76933270e8384a4b53c00c  # chain305
    environment:
      CHAINSAW_DATABASE_URL: "postgres://chainsaw:sup3rs3cr3t@postgres:5432/chainsaw?sslmode=disable"
`

func writeCompose(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "docker-compose.yml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("seed compose: %v", err)
	}
	return p
}

// TestCheckVersionDrift_NeverPrintsComposeSecrets is the D1 regression guard.
// Before the fix this produced:
//
//	binary version "0.19.4" differs from compose-pinned
//	"sup3rs3cr3t@postgres:5432/chainsaw?sslmode=disable"
func TestCheckVersionDrift_NeverPrintsComposeSecrets(t *testing.T) {
	p := writeCompose(t, composeHA)
	for _, f := range checkVersionDrift("0.19.4", p) {
		for _, field := range []string{f.Message, f.Remediation} {
			if strings.Contains(field, "sup3rs3cr3t") {
				t.Fatalf("compose password leaked into a finding: %q", field)
			}
			if strings.Contains(field, "postgres://") {
				t.Fatalf("compose DSN leaked into a finding: %q", field)
			}
		}
	}
}

// TestCheckVersionDrift_DigestPinIsOKNotWarn: a sha256 digest is the
// strongest pin there is. It carries no comparable version, which is "not
// measurable" — warning about it told the most tightly pinned operators to
// loosen their pin.
func TestCheckVersionDrift_DigestPinIsOKNotWarn(t *testing.T) {
	p := writeCompose(t, composeHA)
	findings := checkVersionDrift("0.19.4", p)
	if len(findings) != 1 {
		t.Fatalf("want exactly one finding, got %+v", findings)
	}
	if findings[0].Severity != SeverityOK {
		t.Fatalf("digest pin should be SeverityOK, got %v (%q)", findings[0].Severity, findings[0].Message)
	}
	if !strings.Contains(findings[0].Message, "digest") {
		t.Errorf("message should name the digest pin, got %q", findings[0].Message)
	}
}

// TestCheckVersionDrift_IgnoresNonImageLines proves the anchor: a compose
// file whose ONLY "chainsaw:" occurrences are a service key and an env var
// must report "no chainsaw image line", not invent a pinned version out of
// whichever line happened to come first.
func TestCheckVersionDrift_IgnoresNonImageLines(t *testing.T) {
	p := writeCompose(t, `services:
  chainsaw-proxy:
    image: some-other/thing:1.2.3
    environment:
      CHAINSAW_DATABASE_URL: "postgres://chainsaw:hunter2@db:5432/chainsaw"
`)
	findings := checkVersionDrift("0.19.4", p)
	if len(findings) != 1 || findings[0].Severity != SeverityOK {
		t.Fatalf("want a single OK finding, got %+v", findings)
	}
	if !strings.Contains(findings[0].Message, "no chainsaw image line") {
		t.Fatalf("want the no-image-line verdict, got %q", findings[0].Message)
	}
}

// TestCheckVersionDrift_MatchesRealImageLine keeps the check USEFUL: the
// anchoring must not make it blind to the case it exists for.
func TestCheckVersionDrift_MatchesRealImageLine(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		binary   string
		severity Severity
	}{
		{
			name:     "matching tag",
			body:     "services:\n  proxy:\n    image: chain305/chainsaw-firewall:0.19.4\n",
			binary:   "0.19.4",
			severity: SeverityOK,
		},
		{
			name:     "drifted tag",
			body:     "services:\n  proxy:\n    image: chain305/chainsaw-firewall:0.19.3\n",
			binary:   "0.19.4",
			severity: SeverityWarn,
		},
		{
			name:     "quoted with trailing comment",
			body:     "    image: \"chain305/chainsaw-firewall:0.19.4\"  # pinned\n",
			binary:   "0.19.4",
			severity: SeverityOK,
		},
		{
			name:     "registry port is not a tag",
			body:     "    image: registry.internal:5000/chainsaw-firewall\n",
			binary:   "0.19.4",
			severity: SeverityWarn, // untagged → no drift measurable
		},
		{
			name:     "latest is not measurable",
			body:     "    image: chain305/chainsaw-firewall:latest\n",
			binary:   "0.19.4",
			severity: SeverityWarn,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			findings := checkVersionDrift(c.binary, writeCompose(t, c.body))
			if len(findings) != 1 {
				t.Fatalf("want one finding, got %+v", findings)
			}
			if findings[0].Severity != c.severity {
				t.Fatalf("severity = %v, want %v (%q)", findings[0].Severity, c.severity, findings[0].Message)
			}
		})
	}
}

// TestRun_RedactsEveryFindingString covers the belt-and-braces choke point:
// even a check that is careless with a credential cannot leak one, because
// doctor.Run sweeps every Message/Remediation on the way out.
//
// We drive it through the real Run() using the compose path, which is the
// one Options field that reads an operator-supplied file wholesale.
func TestRun_RedactsEveryFindingString(t *testing.T) {
	p := writeCompose(t, composeHA)
	report := Run(context.Background(), Options{
		Version:           "0.19.4",
		DockerComposePath: p,
		SkipNetwork:       true,
		Env:               func(string) string { return "" },
	})
	for _, f := range report.Findings {
		if strings.Contains(f.Message+f.Remediation, "sup3rs3cr3t") {
			t.Fatalf("credential survived the report-wide redaction sweep: %+v", f)
		}
	}
}

// TestRedactFindings_MasksCredentialShapes exercises the sweep directly, so
// the guarantee is pinned even if no shipped check currently produces such a
// string. The username survives on purpose — an operator diagnosing a DSN
// needs to know WHICH user is wired.
func TestRedactFindings_MasksCredentialShapes(t *testing.T) {
	findings := []Finding{{
		Check:       "synthetic",
		Message:     `cannot dial postgres://chainsaw:hunter2@db:5432/chainsaw`,
		Remediation: "check CHAINSAW_TOKEN=abc123secret",
	}}
	redactFindings(findings)
	if strings.Contains(findings[0].Message, "hunter2") {
		t.Errorf("DSN password not redacted: %q", findings[0].Message)
	}
	if !strings.Contains(findings[0].Message, "chainsaw:") {
		t.Errorf("username should survive redaction: %q", findings[0].Message)
	}
	if strings.Contains(findings[0].Remediation, "abc123secret") {
		t.Errorf("token not redacted: %q", findings[0].Remediation)
	}
	// Idempotent: a second sweep must not mangle the already-masked text.
	before := findings[0].Message
	redactFindings(findings)
	if findings[0].Message != before {
		t.Errorf("redaction is not idempotent: %q -> %q", before, findings[0].Message)
	}
}

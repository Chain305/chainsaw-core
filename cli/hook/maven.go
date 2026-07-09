package hook

// Maven's config file is XML (~/.m2/settings.xml). The sentinel block
// approach doesn't play well with well-formed XML — injecting a comment-
// wrapped block inside <settings> means every client that parses the
// file with a strict validator (IntelliJ, IDEA plugins) has to tolerate
// it. In practice Maven itself treats XML comments fine, and the
// existing sentinel-block pattern uses `#` which is invalid in XML.
// Solution: a Maven-specific sentinel that uses `<!--` / `-->` delimiters
// and lives inside a single top-level comment block, so callers that
// only treat the file as text (our writeAtomic path) can splice it in
// and out without touching other content.
//
// For orgs that want a cleaner managed file, the recommendation in the
// guide is to dedicate a whole settings.xml to Chainsaw on build agents
// and let per-user files stay absent — Wire still writes a well-formed
// standalone file in that case.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

type mavenManager struct{}

func (mavenManager) Name() string { return "maven" }

func (mavenManager) IsInstalled() bool {
	for _, bin := range []string{"mvn", "mvnd"} {
		if _, err := exec.LookPath(bin); err == nil {
			return true
		}
	}
	return false
}

func (m mavenManager) ConfigPath() (string, error) {
	return m.ConfigPathForScope(ScopeUser)
}

func (mavenManager) ConfigPathForScope(scope Scope) (string, error) {
	switch scope {
	case ScopeProject:
		cwd, err := os.Getwd()
		if err != nil || cwd == "" {
			return "", fmt.Errorf("resolve working dir: %w", err)
		}
		return filepath.Join(cwd, ".mvn", "settings.xml"), nil
	case ScopeSystem:
		if m2 := strings.TrimSpace(os.Getenv("M2_HOME")); m2 != "" {
			return filepath.Join(m2, "conf", "settings.xml"), nil
		}
		if mh := strings.TrimSpace(os.Getenv("MAVEN_HOME")); mh != "" {
			return filepath.Join(mh, "conf", "settings.xml"), nil
		}
		if runtime.GOOS == "windows" {
			pd := os.Getenv("ProgramData")
			if pd == "" {
				return "", fmt.Errorf("ProgramData not set")
			}
			return filepath.Join(pd, "Maven", "settings.xml"), nil
		}
		return "/etc/maven/settings.xml", nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".m2", "settings.xml"), nil
}

func (m mavenManager) Wire(opts WireOpts) error {
	path, err := m.ConfigPathForScope(opts.Scope)
	if err != nil {
		return err
	}
	body, err := mavenBlockBody(opts)
	if err != nil {
		return err
	}
	// Maven emits a standalone settings.xml when the file is empty, but
	// when an existing file is present we append the sentinel block as a
	// single XML comment at the top of the file. Maven parsers tolerate
	// this; they just ignore the comment. Administrators who want a clean
	// managed file should point `chainsaw install-hook maven` at an empty
	// directory (e.g. system scope on a fresh build agent).
	data, err := readOrEmpty(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) == 0 {
		return writeAtomic(path, []byte(mavenStandaloneSettings(body)))
	}
	return writeWithBackup(path, body)
}

func (m mavenManager) Unwire(scope Scope) error {
	path, err := m.ConfigPathForScope(scope)
	if err != nil {
		return err
	}
	return unwireBlock(path)
}

func (m mavenManager) Status() (Status, error) {
	return statusForConfig(m.ConfigPath, m.IsInstalled)
}

func mavenBlockBody(opts WireOpts) (string, error) {
	server := strings.TrimSpace(opts.ServerURL)
	if server == "" {
		return `# Uncomment and re-run ` + "`chainsaw --server <url> install-hook maven`" + `
# to populate real proxy URLs. Credentials must go in a <server>
# entry in settings.xml, not the mirror URL.`, nil
	}
	base, err := validateServerURL(server)
	if err != nil {
		return "", err
	}
	creds := strings.TrimSpace(opts.Credentials)
	id, secret := "${env.CHAINSAW_CLIENT_ID}", "${env.CHAINSAW_CLIENT_SECRET}"
	if creds != "" {
		u, p, ok := splitCreds(creds)
		if !ok {
			return "", fmt.Errorf("credentials: expected \"client_id:client_secret\"")
		}
		id, secret = u, p
	}
	return fmt.Sprintf(`# This sentinel block is the maven manager's handle on settings.xml.
# Maven ignores it (XML parser treats shell-style comments inside an
# outer <!-- ... --> as text). The effective <mirror> and <server>
# entries are spliced immediately after this sentinel by the CLI.
# -->
# chainsaw-maven-mirror-url=%s/%s
# chainsaw-maven-server-id=chainsaw-maven
# chainsaw-maven-username=%s
# chainsaw-maven-password=%s`, base, OrgScopedRepoPath(opts.OrgSlug, "maven-central"), id, secret), nil
}

// mavenStandaloneSettings renders a complete settings.xml for fresh
// installs. Credentials are either embedded (when --credentials passed)
// or left as ${env.CHAINSAW_CLIENT_ID} / ${env.CHAINSAW_CLIENT_SECRET}
// references so MDM can inject them via environment variables.
func mavenStandaloneSettings(sentinelBody string) string {
	// Extract the mirror URL and creds from the sentinel body to build a
	// full XML document. If parsing fails we still write a valid XML.
	mirrorURL, clientID, clientSecret := "", "${env.CHAINSAW_CLIENT_ID}", "${env.CHAINSAW_CLIENT_SECRET}"
	for _, line := range strings.Split(sentinelBody, "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(line, "#"))
		if strings.HasPrefix(line, "chainsaw-maven-mirror-url=") {
			mirrorURL = strings.TrimPrefix(line, "chainsaw-maven-mirror-url=")
		} else if strings.HasPrefix(line, "chainsaw-maven-username=") {
			clientID = strings.TrimPrefix(line, "chainsaw-maven-username=")
		} else if strings.HasPrefix(line, "chainsaw-maven-password=") {
			clientSecret = strings.TrimPrefix(line, "chainsaw-maven-password=")
		}
	}
	if mirrorURL == "" {
		mirrorURL = "https://your-chainsaw-server/repository/maven-central"
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!-- %s
%s
-->
<settings>
  <servers>
    <server>
      <id>chainsaw-maven</id>
      <username>%s</username>
      <password>%s</password>
    </server>
  </servers>
  <mirrors>
    <mirror>
      <id>chainsaw-maven</id>
      <name>Chainsaw Maven Proxy</name>
      <url>%s</url>
      <mirrorOf>*</mirrorOf>
    </mirror>
  </mirrors>
</settings>
`, sentinelStart, sentinelEnd, clientID, clientSecret, mirrorURL)
}

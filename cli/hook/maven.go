package hook

// Maven's config file is XML (~/.m2/settings.xml), and the shared sentinel
// machinery emits "#" line comments — which are character data in XML, not
// comments. Wiring therefore has exactly two outcomes:
//
//   - The file is absent, or chainsaw wrote it: emit a complete, well-formed
//     standalone settings.xml with the sentinel markers inside one top-level
//     <!-- --> comment (each marker on its OWN line so the matcher can find
//     them again — H2).
//
//   - The file exists and is somebody else's: REFUSE, and print the exact
//     <server>/<mirror> fragment to merge by hand (H1).
//
// The old second branch appended "# ..." lines after </settings>, producing
// `[FATAL] Non-parseable settings` on every mvn invocation (verified against
// Maven 3.9.9) and leaking the plaintext client secret into the file. A
// smarter splicer is not the answer either: Go's encoding/xml cannot
// round-trip a document losslessly, so it would silently reformat a
// hand-maintained settings.xml.
//
// For orgs that want a cleaner managed file, the recommendation in the guide
// is to dedicate a whole settings.xml to Chainsaw on build agents and let
// per-user files stay absent.

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
	fields, err := mavenRenderFields(opts)
	if err != nil {
		return err
	}
	data, err := readOrEmpty(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	switch {
	case len(data) == 0:
		// Fresh install: we own the whole document.
	case xmlHasSentinel(data):
		// A chainsaw-written file (including one carrying the legacy
		// same-line markers). Re-rendering it keeps install idempotent and
		// upgrades the marker spelling in place. Deliberately NOT backed
		// up: the content is entirely ours and regenerated, and a backup
		// of a chainsaw document would poison xmlUnwire's restore source.
	default:
		return xmlRefuseError("maven", path, mavenMergeFragment(fields))
	}
	return writeConfigFile(path, []byte(mavenStandaloneSettings(fields)), opts)
}

func (m mavenManager) Unwire(scope Scope) error {
	path, err := m.ConfigPathForScope(scope)
	if err != nil {
		return err
	}
	// NOT removeSentinel: stripping the marker lines would delete the
	// comment and leave <mirrorOf>*</mirrorOf> live while reporting
	// success. See xmlsentinel.go.
	return xmlUnwire(path)
}

func (m mavenManager) Status() (Status, error) {
	return xmlStatus(m.ConfigPath, m.IsInstalled)
}

// mavenFields carries the values spliced into the generated settings.xml.
// Every string is raw (unescaped); the renderers escape at the point of use.
type mavenFields struct {
	MirrorURL    string
	ClientID     string
	ClientSecret string
	// Placeholder is true when no --server was supplied, so the rendered
	// file points at an obviously-broken host and fails loud on first use.
	Placeholder bool
}

func mavenRenderFields(opts WireOpts) (mavenFields, error) {
	f := mavenFields{
		ClientID:     "${env.CHAINSAW_CLIENT_ID}",
		ClientSecret: "${env.CHAINSAW_CLIENT_SECRET}",
	}
	repoPath, err := orgScopedRepoPath(opts.OrgSlug, "maven-central")
	if err != nil {
		return mavenFields{}, err
	}
	server := strings.TrimSpace(opts.ServerURL)
	if server == "" {
		f.Placeholder = true
		f.MirrorURL = "https://your-chainsaw-server/" + repoPath
	} else {
		base, err := validateServerURL(server)
		if err != nil {
			return mavenFields{}, err
		}
		f.MirrorURL = base + "/" + repoPath
	}
	if creds := strings.TrimSpace(opts.Credentials); creds != "" {
		id, secret, err := parseCreds(creds)
		if err != nil {
			return mavenFields{}, err
		}
		f.ClientID, f.ClientSecret = id, secret
	}
	return f, nil
}

// mavenMergeFragment is the XML an operator must paste into their own
// settings.xml when chainsaw refuses to edit it (H1).
func mavenMergeFragment(f mavenFields) string {
	return fmt.Sprintf(`  <!-- inside <settings><servers> -->
    <server>
      <id>chainsaw-maven</id>
      <username>%s</username>
      <password>%s</password>
    </server>

  <!-- inside <settings><mirrors> -->
    <mirror>
      <id>chainsaw-maven</id>
      <name>Chainsaw Maven Proxy</name>
      <url>%s</url>
      <mirrorOf>*</mirrorOf>
    </mirror>
`, xmlEscape(f.ClientID), xmlEscape(f.ClientSecret), xmlEscape(f.MirrorURL))
}

// mavenStandaloneSettings renders a complete settings.xml. Credentials are
// either embedded (when --credentials was passed) or left as
// ${env.CHAINSAW_CLIENT_ID} / ${env.CHAINSAW_CLIENT_SECRET} references so MDM
// can inject them via environment variables.
//
// H2: each sentinel marker gets its OWN line inside the comment. The previous
// `<!-- # >>> chainsaw-managed >>>` spelling was invisible to the matcher, so
// Status lied and Unwire could never remove the mirror.
//
// H4: every interpolated value goes through xmlEscape. A client secret
// containing & or < previously produced `<password>a&b<c</password>`, which
// breaks every mvn run.
func mavenStandaloneSettings(f mavenFields) string {
	// NB: an XML comment may not contain the two-hyphen sequence, so no
	// text placed inside this block may spell a long CLI flag.
	note := ""
	if f.Placeholder {
		note = "\n     No server was configured, so the mirror URL below is a placeholder\n     and will fail loudly on first use. Re-run install-hook once a server\n     is set (chainsaw auth login, or the CHAINSAW_SERVER env var)."
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!--
%s
     This file is managed by chainsaw. Remove it with
     `+"`chainsaw uninstall-hook maven`"+` rather than editing it by hand:
     chainsaw refuses to modify a settings.xml it did not write.%s
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
`, sentinelStart, note, sentinelEnd,
		xmlEscape(f.ClientID), xmlEscape(f.ClientSecret), xmlEscape(f.MirrorURL))
}

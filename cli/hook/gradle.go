package hook

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

type gradleManager struct{}

func (gradleManager) Name() string { return "gradle" }

func (gradleManager) IsInstalled() bool {
	_, err := exec.LookPath("gradle")
	return err == nil
}

func (m gradleManager) ConfigPath() (string, error) {
	return m.ConfigPathForScope(ScopeUser)
}

// ConfigPathForScope targets init.gradle.kts, which Gradle loads on every
// invocation. User scope is ~/.gradle/init.d/chainsaw.gradle.kts; system
// scope writes to the Gradle install dir's init.d (GRADLE_HOME required)
// so every invocation on the agent picks it up.
func (gradleManager) ConfigPathForScope(scope Scope) (string, error) {
	switch scope {
	case ScopeProject:
		cwd, err := os.Getwd()
		if err != nil || cwd == "" {
			return "", fmt.Errorf("resolve working dir: %w", err)
		}
		return filepath.Join(cwd, "gradle", "chainsaw.init.gradle.kts"), nil
	case ScopeSystem:
		if gh := strings.TrimSpace(os.Getenv("GRADLE_USER_HOME")); gh != "" {
			return filepath.Join(gh, "init.d", "chainsaw.gradle.kts"), nil
		}
		if gh := strings.TrimSpace(os.Getenv("GRADLE_HOME")); gh != "" {
			return filepath.Join(gh, "init.d", "chainsaw.gradle.kts"), nil
		}
		if runtime.GOOS == "windows" {
			pd := os.Getenv("ProgramData")
			if pd == "" {
				return "", fmt.Errorf("ProgramData not set")
			}
			return filepath.Join(pd, "gradle", "init.d", "chainsaw.gradle.kts"), nil
		}
		return "/etc/gradle/init.d/chainsaw.gradle.kts", nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".gradle", "init.d", "chainsaw.gradle.kts"), nil
}

// gradleMarker accepts the Kotlin "//" markers gradle emits now and the "#"
// markers earlier releases wrote, so an existing (broken) install is still
// found, replaced and removable. See H14.
var gradleMarker = commentPrefixMarker("//", "#")

func (m gradleManager) Wire(opts WireOpts) error {
	path, err := m.ConfigPathForScope(opts.Scope)
	if err != nil {
		return err
	}
	body, err := gradleBlockBody(opts)
	if err != nil {
		return err
	}
	// H14: buildBlock's default "#" prefix is a syntax error in Kotlin — it
	// has no "#" line comment — and Gradle loads EVERY script in init.d and
	// fails the build when one will not compile. So `install-hook gradle`
	// (or --all on a box with gradle on PATH) broke every Gradle build for
	// that user. Emit "//" instead.
	return writeWithBackupPrefix(m.Name(), path, body, opts, "//", gradleMarker)
}

func (m gradleManager) Unwire(scope Scope) error {
	path, err := m.ConfigPathForScope(scope)
	if err != nil {
		return err
	}
	// chainsaw.gradle.kts is a file we own outright, so removing our block
	// leaves nothing worth keeping — drop the file rather than leaving an
	// empty script in init.d.
	return unwireBlockWith(path, gradleMarker, true)
}

func (m gradleManager) Status() (Status, error) {
	return statusForConfigWith(m.ConfigPath, m.IsInstalled, gradleMarker)
}

func gradleBlockBody(opts WireOpts) (string, error) {
	server := strings.TrimSpace(opts.ServerURL)
	if server == "" {
		return `// Re-run ` + "`chainsaw --server <url> install-hook gradle`" + ` to
// populate real proxy URLs. Credentials read from gradle.properties
// keys chainsawUser / chainsawPass.`, nil
	}
	base, err := validateServerURL(server)
	if err != nil {
		return "", err
	}
	// BUG-A6: org-scoped paths required for every maven repo URL.
	pluginsPath, err := orgScopedRepoPath(opts.OrgSlug, "gradle-plugins")
	if err != nil {
		return "", err
	}
	centralPath, err := orgScopedRepoPath(opts.OrgSlug, "gradle-central")
	if err != nil {
		return "", err
	}
	googlePath, err := orgScopedRepoPath(opts.OrgSlug, "google-maven")
	if err != nil {
		return "", err
	}
	// H4: these land inside Kotlin double-quoted string literals that Gradle
	// compiles on every build, so escape for that grammar. The slug is
	// already constrained by orgScopedRepoPath and the base by
	// validateServerURL; this is the belt to those braces.
	base = kotlinEscape(base)
	pluginsPath = kotlinEscape(pluginsPath)
	centralPath = kotlinEscape(centralPath)
	googlePath = kotlinEscape(googlePath)
	return fmt.Sprintf(`// Added by chainsaw install-hook gradle — routes every project through
// the Chainsaw proxy regardless of what the project's settings.gradle(.kts)
// NOTE: the credential providers use .getOrElse("") rather than .get().
// .get() is EAGER — Gradle resolves it while configuring every project, so an
// unset CHAINSAW_CLIENT_ID made every build fail at configuration time with
// "Cannot query the value of this provider because it has no value available",
// on projects that have nothing to do with Chainsaw. Verified against Gradle
// 8.14: exit 1 on a trivial project that never mentions Chainsaw — the same
// blast radius as the hash-comment defect this file already carries a fix for.
// Deferring to an empty string lets the build configure and fails at fetch
// time against the proxy instead, where the error names the real problem.
// declares. Credentials live in gradle.properties (chainsawUser /
// chainsawPass) so they stay out of URLs and build logs.
allprojects {
    buildscript {
        repositories {
            maven {
                url = uri("%[1]s/%[2]s/")
                credentials {
                    username = (providers.gradleProperty("chainsawUser")
                        .orElse(providers.environmentVariable("CHAINSAW_CLIENT_ID"))).getOrElse("")
                    password = (providers.gradleProperty("chainsawPass")
                        .orElse(providers.environmentVariable("CHAINSAW_CLIENT_SECRET"))).getOrElse("")
                }
            }
        }
    }
    repositories {
        maven {
            url = uri("%[1]s/%[3]s/")
            credentials {
                username = (providers.gradleProperty("chainsawUser")
                    .orElse(providers.environmentVariable("CHAINSAW_CLIENT_ID"))).getOrElse("")
                password = (providers.gradleProperty("chainsawPass")
                    .orElse(providers.environmentVariable("CHAINSAW_CLIENT_SECRET"))).getOrElse("")
            }
        }
        maven {
            url = uri("%[1]s/%[4]s/")
            credentials {
                username = (providers.gradleProperty("chainsawUser")
                    .orElse(providers.environmentVariable("CHAINSAW_CLIENT_ID"))).getOrElse("")
                password = (providers.gradleProperty("chainsawPass")
                    .orElse(providers.environmentVariable("CHAINSAW_CLIENT_SECRET"))).getOrElse("")
            }
        }
    }
}`, base, pluginsPath, centralPath, googlePath), nil
}

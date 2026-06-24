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

func (m gradleManager) Wire(opts WireOpts) error {
	path, err := m.ConfigPathForScope(opts.Scope)
	if err != nil {
		return err
	}
	body, err := gradleBlockBody(opts)
	if err != nil {
		return err
	}
	return writeWithBackup(path, body)
}

func (m gradleManager) Unwire(scope Scope) error {
	path, err := m.ConfigPathForScope(scope)
	if err != nil {
		return err
	}
	return unwireBlock(path)
}

func (m gradleManager) Status() (Status, error) {
	return statusForConfig(m.ConfigPath, m.IsInstalled)
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
	pluginsPath := OrgScopedRepoPath(opts.OrgSlug, "gradle-plugins")
	centralPath := OrgScopedRepoPath(opts.OrgSlug, "gradle-central")
	googlePath := OrgScopedRepoPath(opts.OrgSlug, "google-maven")
	return fmt.Sprintf(`// Added by chainsaw install-hook gradle — routes every project through
// the Chainsaw proxy regardless of what the project's settings.gradle(.kts)
// declares. Credentials live in gradle.properties (chainsawUser /
// chainsawPass) so they stay out of URLs and build logs.
allprojects {
    buildscript {
        repositories {
            maven {
                url = uri("%[1]s/%[2]s/")
                credentials {
                    username = (providers.gradleProperty("chainsawUser")
                        .orElse(providers.environmentVariable("CHAINSAW_CLIENT_ID"))).get()
                    password = (providers.gradleProperty("chainsawPass")
                        .orElse(providers.environmentVariable("CHAINSAW_CLIENT_SECRET"))).get()
                }
            }
        }
    }
    repositories {
        maven {
            url = uri("%[1]s/%[3]s/")
            credentials {
                username = (providers.gradleProperty("chainsawUser")
                    .orElse(providers.environmentVariable("CHAINSAW_CLIENT_ID"))).get()
                password = (providers.gradleProperty("chainsawPass")
                    .orElse(providers.environmentVariable("CHAINSAW_CLIENT_SECRET"))).get()
            }
        }
        maven {
            url = uri("%[1]s/%[4]s/")
            credentials {
                username = (providers.gradleProperty("chainsawUser")
                    .orElse(providers.environmentVariable("CHAINSAW_CLIENT_ID"))).get()
                password = (providers.gradleProperty("chainsawPass")
                    .orElse(providers.environmentVariable("CHAINSAW_CLIENT_SECRET"))).get()
            }
        }
    }
}`, base, pluginsPath, centralPath, googlePath), nil
}

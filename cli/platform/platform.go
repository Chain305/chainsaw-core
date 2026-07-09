// Package platform resolves platform-appropriate locations for chainsaw
// configuration. Conventions differ per OS and we also honor a universal
// CHAINSAW_CONFIG_HOME override for CI, nix, and portable installs.
package platform

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	// EnvConfigHome is the universal override for the config directory.
	EnvConfigHome = "CHAINSAW_CONFIG_HOME"
	// EnvXDGConfigHome is the XDG Base Directory spec variable consulted on Linux.
	EnvXDGConfigHome = "XDG_CONFIG_HOME"

	dirName       = "chainsaw"
	dirNameWindow = "Chainsaw"
	legacyDirName = ".chainsaw"
)

// ConfigHome returns the directory where chainsaw config lives. Precedence:
//  1. $CHAINSAW_CONFIG_HOME (with leading ~ expansion)
//  2. Linux:   $XDG_CONFIG_HOME/chainsaw, fallback $HOME/.config/chainsaw
//  3. Windows: os.UserConfigDir()/Chainsaw (typically %APPDATA%\Chainsaw)
//  4. macOS:   $HOME/.chainsaw (legacy — kept for familiarity)
//  5. Other:   $HOME/.chainsaw
//
// If $HOME is unavailable for any reason the returned path may be empty or
// relative; callers should tolerate that.
func ConfigHome() string {
	if override := os.Getenv(EnvConfigHome); override != "" {
		return expandTilde(override)
	}

	switch runtime.GOOS {
	case "linux":
		if xdg := os.Getenv(EnvXDGConfigHome); xdg != "" {
			return filepath.Join(xdg, dirName)
		}
		home := homeDir()
		if home == "" {
			return filepath.Join(".config", dirName)
		}
		return filepath.Join(home, ".config", dirName)
	case "windows":
		if cfg, err := os.UserConfigDir(); err == nil && cfg != "" {
			return filepath.Join(cfg, dirNameWindow)
		}
		home := homeDir()
		if home == "" {
			return legacyDirName
		}
		return filepath.Join(home, legacyDirName)
	default:
		home := homeDir()
		if home == "" {
			return legacyDirName
		}
		return filepath.Join(home, legacyDirName)
	}
}

// LegacyConfigHome is the pre-refactor location ($HOME/.chainsaw). Used by
// the silent-migration path so older configs move to their new home.
func LegacyConfigHome() string {
	home := homeDir()
	if home == "" {
		return legacyDirName
	}
	return filepath.Join(home, legacyDirName)
}

func homeDir() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return h
}

func expandTilde(p string) string {
	if p == "~" {
		if home := homeDir(); home != "" {
			return home
		}
		return p
	}
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		home := homeDir()
		if home == "" {
			return p
		}
		return filepath.Join(home, p[2:])
	}
	return p
}

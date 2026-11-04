package homebrew

import (
	"encoding/json"
	"net/url"
	"strings"
)

// Cask is the subset of formulae.brew.sh/api/cask/<token>.json Chainsaw reads.
type Cask struct {
	Token             string   `json:"token"`
	FullToken         string   `json:"full_token"`
	Tap               string   `json:"tap"`
	Name              []string `json:"name"`
	Desc              string   `json:"desc"`
	Homepage          string   `json:"homepage"`
	URL               string   `json:"url"`
	Version           string   `json:"version"`
	SHA256            string   `json:"sha256"`
	AutoUpdates       bool     `json:"auto_updates"`
	Deprecated        bool     `json:"deprecated"`
	DeprecationReason string   `json:"deprecation_reason"`
	Disabled          bool     `json:"disabled"`
	DisableReason     string   `json:"disable_reason"`
	// Artifacts is a list of single-key objects ({"app": [...]},
	// {"pkg": [...]}, {"installer": [...]}, {"preflight": ...}). Kept raw:
	// only the keys matter for risk flags.
	Artifacts []map[string]json.RawMessage `json:"artifacts"`
}

// CaskFlags are the install-risk facts a cask's metadata states. They are
// not verdicts: each maps to a guard/policy decision documented in
// docs/PLANS_INTELLIGENCE.md#plan-homebrew-ecosystem §3.
type CaskFlags struct {
	// NoChecksum: `sha256 :no_check` — the download is not pinned, so the
	// bytes brew installs are whatever the vendor serves today.
	NoChecksum bool `json:"no_checksum"`
	// AutoUpdates: the app replaces itself outside Homebrew.
	AutoUpdates bool `json:"auto_updates"`
	// RunsInstaller: a .pkg or installer-script artifact, which runs
	// outside brew's sandbox and usually with elevated privileges.
	RunsInstaller bool `json:"runs_installer"`
	// HasHooks: preflight/postflight/uninstall_preflight/... Ruby hooks.
	HasHooks bool `json:"has_hooks"`
	// DownloadHostMismatch: the download host shares no registrable suffix
	// with the homepage host (heuristic; vendor CDNs are common).
	DownloadHostMismatch bool `json:"download_host_mismatch"`
	// Deprecated / Disabled mirror the cask's lifecycle flags. Official casks
	// failing Gatekeeper are disabled.
	Deprecated bool   `json:"deprecated"`
	Disabled   bool   `json:"disabled"`
	Reason     string `json:"reason,omitempty"`
	// ThirdPartyTap: not from homebrew/cask.
	ThirdPartyTap bool `json:"third_party_tap"`
}

// Flags derives the install-risk facts from the cask metadata.
func (c *Cask) Flags() CaskFlags {
	if c == nil {
		return CaskFlags{}
	}
	f := CaskFlags{
		NoChecksum:  strings.EqualFold(strings.TrimSpace(c.SHA256), "no_check") || strings.TrimSpace(c.SHA256) == "",
		AutoUpdates: c.AutoUpdates,
		Deprecated:  c.Deprecated,
		Disabled:    c.Disabled,
	}
	if c.Disabled {
		f.Reason = c.DisableReason
	} else if c.Deprecated {
		f.Reason = c.DeprecationReason
	}
	tap := strings.ToLower(strings.TrimSpace(c.Tap))
	f.ThirdPartyTap = tap != "" && tap != "homebrew/cask"
	for _, a := range c.Artifacts {
		for k := range a {
			switch k {
			case "pkg", "installer":
				f.RunsInstaller = true
			case "preflight", "postflight", "uninstall_preflight", "uninstall_postflight":
				f.HasHooks = true
			}
		}
	}
	f.DownloadHostMismatch = hostMismatch(c.URL, c.Homepage)
	return f
}

// hostMismatch reports whether two URLs share no registrable-domain suffix.
// It compares the last two DNS labels, which is a heuristic (it treats
// example.co.uk as co.uk) and is labelled as one wherever it surfaces.
func hostMismatch(download, homepage string) bool {
	d := lastLabels(download)
	h := lastLabels(homepage)
	if d == "" || h == "" {
		return false
	}
	return d != h
}

func lastLabels(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" {
		return ""
	}
	parts := strings.Split(strings.ToLower(u.Hostname()), ".")
	if len(parts) < 2 {
		return strings.Join(parts, ".")
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

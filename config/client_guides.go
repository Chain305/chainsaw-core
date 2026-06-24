package config

import (
	"net/url"
	"os"
	"regexp"
	"strings"
)

var optionHeadingRegex = regexp.MustCompile(`(?im)^\s*(?:>\s*)?(?:[-*]\s+)?(?:#{1,6}\s*)?(?:\*\*|__)?Option\s+\d+.*$`)

const cacheAdviceHeading = "## Cache cleanup before configuring"

type ClientGuideRenderer struct {
	baseURL string
	host    string
}

func NewClientGuideRenderer() ClientGuideRenderer {
	baseURL, host := resolveClientGuideBaseURL()
	return ClientGuideRenderer{baseURL: baseURL, host: host}
}

func (r ClientGuideRenderer) Render(guide string) string {
	return r.RenderWithOverride(guide, "")
}

// RenderWithOverride renders the guide but prefers publicBaseURL over the
// server-wide base when it's non-empty. Use this when a repository has a
// public hostname distinct from the dashboard host (e.g. dashboard on
// `internal.corp`, proxy on `artifacts.corp`).
func (r ClientGuideRenderer) RenderWithOverride(guide, publicBaseURL string) string {
	if guide == "" {
		return guide
	}
	rendered := guide
	effective := strings.TrimSpace(publicBaseURL)
	if effective == "" {
		effective = r.baseURL
	}
	if effective != "" {
		base := strings.TrimRight(effective, "/")
		rendered = strings.ReplaceAll(rendered, "${CHAINSAW_REPO_BASE_URL}", base)

		parsed, err := url.Parse(base)
		if err == nil && parsed.Scheme != "" && parsed.Host != "" {
			basePath := strings.TrimRight(parsed.Path, "/")
			for _, oldHost := range []string{"your-chainsaw-server:8787", "localhost:8787"} {
				// Replace full URLs including optional embedded credentials
				// (e.g. http://user:pass@old-host/path → https://user:pass@new-host/basePath/path)
				pattern := regexp.MustCompile(`https?://([^@\s]*@)?` + regexp.QuoteMeta(oldHost))
				rendered = pattern.ReplaceAllStringFunc(rendered, func(match string) string {
					creds := ""
					if atIdx := strings.Index(match, "@"); atIdx != -1 {
						schemeEnd := strings.Index(match, "://") + 3
						creds = match[schemeEnd : atIdx+1]
					}
					return parsed.Scheme + "://" + creds + parsed.Host + basePath
				})
				// Replace remaining bare host references (e.g. trusted-host directives)
				rendered = strings.ReplaceAll(rendered, oldHost, parsed.Host)
			}
		} else {
			rendered = strings.ReplaceAll(rendered, "http://your-chainsaw-server:8787", base)
			rendered = strings.ReplaceAll(rendered, "https://your-chainsaw-server:8787", base)
			rendered = strings.ReplaceAll(rendered, "http://localhost:8787", base)
			rendered = strings.ReplaceAll(rendered, "https://localhost:8787", base)
			// When an override is in play, prefer its host for bare-host
			// substitutions; otherwise fall back to the renderer's default.
			hostForBare := r.host
			if publicBaseURL != "" {
				if h := hostFromURL(effective); h != "" {
					hostForBare = h
				}
			}
			if hostForBare != "" {
				rendered = strings.ReplaceAll(rendered, "your-chainsaw-server:8787", hostForBare)
				rendered = strings.ReplaceAll(rendered, "localhost:8787", hostForBare)
			}
		}
	}
	rendered = insertCacheAdvice(rendered)
	return rendered
}

func resolveClientGuideBaseURL() (string, string) {
	repoBase := firstEnv(
		"CHAINSAW_REPO_BASE_URL",
		"NEXT_PUBLIC_CHAINSAW_REPO_BASE_URL",
	)
	if repoBase != "" {
		repoBase = strings.TrimRight(repoBase, "/")
		return repoBase, hostFromURL(repoBase)
	}

	apiBase := firstEnv(
		"CHAINSAW_API_BASE_URL",
		"NEXT_PUBLIC_CHAINSAW_API_BASE_URL",
	)
	basePath := normalizeBasePath(firstEnv(
		"CHAINSAW_API_BASEPATH",
		"NEXT_PUBLIC_CHAINSAW_API_BASEPATH",
	))

	if apiBase != "" {
		if parsed, err := url.Parse(apiBase); err == nil && parsed.Scheme != "" && parsed.Host != "" {
			origin := parsed.Scheme + "://" + parsed.Host
			if basePath == "" {
				basePath = stripApiSuffix(parsed.Path)
			}
			repoBase = strings.TrimRight(origin+basePath, "/")
			return repoBase, parsed.Host
		}
	}

	origin := firstEnv(
		"CHAINSAW_API_ORIGIN",
		"NEXT_PUBLIC_CHAINSAW_API_ORIGIN",
	)
	if origin != "" {
		repoBase = strings.TrimRight(origin+basePath, "/")
		return repoBase, hostFromURL(repoBase)
	}

	return "", ""
}

func normalizeBasePath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || value == "/" {
		return ""
	}
	if !strings.HasPrefix(value, "/") {
		value = "/" + value
	}
	return strings.TrimRight(value, "/")
}

func stripApiSuffix(value string) string {
	normalized := normalizeBasePath(value)
	if normalized == "" {
		return ""
	}
	if normalized == "/api" || normalized == "/api/v1" {
		return ""
	}
	if strings.HasSuffix(normalized, "/api/v1") {
		return strings.TrimSuffix(normalized, "/api/v1")
	}
	if strings.HasSuffix(normalized, "/api") {
		return strings.TrimSuffix(normalized, "/api")
	}
	return normalized
}

func firstEnv(keys ...string) string {
	for _, key := range keys {
		value := strings.TrimSpace(os.Getenv(key))
		if value != "" {
			return value
		}
	}
	return ""
}

func hostFromURL(value string) string {
	if value == "" {
		return ""
	}
	parsed, err := url.Parse(value)
	if err == nil && parsed.Host != "" {
		return parsed.Host
	}
	parsed, err = url.Parse("http://" + value)
	if err == nil {
		return parsed.Host
	}
	return ""
}

func insertCacheAdvice(guide string) string {
	if guide == "" || !optionHeadingRegex.MatchString(guide) {
		return guide
	}
	if strings.Contains(guide, cacheAdviceHeading) {
		return guide
	}
	format := inferGuideFormat(guide)
	advice := cacheAdviceForFormat(format)
	if advice == "" {
		return guide
	}
	loc := optionHeadingRegex.FindStringIndex(guide)
	if loc == nil {
		return guide
	}
	prefix := strings.TrimRight(guide[:loc[0]], "\n")
	suffix := strings.TrimLeft(guide[loc[0]:], "\n")
	return prefix + "\n\n" + advice + "\n\n" + suffix
}

func inferGuideFormat(guide string) string {
	for _, line := range strings.Split(guide, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			title := strings.TrimSpace(strings.TrimLeft(trimmed, "#"))
			lower := strings.ToLower(title)
			switch {
			case strings.Contains(lower, "npm"):
				return "npm"
			case strings.Contains(lower, "yarn"):
				return "yarn"
			case strings.Contains(lower, "pip") || strings.Contains(lower, "pypi"):
				return "pip"
			case strings.Contains(lower, "maven"):
				return "maven"
			case strings.Contains(lower, "nuget"):
				return "nuget"
			case strings.Contains(lower, "composer"):
				return "composer"
			case strings.Contains(lower, "cargo"):
				return "cargo"
			case strings.Contains(lower, "go modules") || strings.Contains(lower, "gomod"):
				return "go"
			case strings.Contains(lower, "apt"):
				return "apt"
			case strings.Contains(lower, "yum"):
				return "yum"
			case strings.Contains(lower, "dnf"):
				return "dnf"
			case strings.Contains(lower, "docker"):
				return "docker"
			case strings.Contains(lower, "gradle"):
				return "gradle"
			case strings.Contains(lower, "cocoapods"):
				return "cocoapods"
			case strings.Contains(lower, "swift") || strings.Contains(lower, "spm"):
				return "swift"
			}
			return ""
		}
	}
	return ""
}

func cacheAdviceForFormat(format string) string {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "npm":
		return cacheAdviceHeading + "\nClear the npm cache before switching registries:\n\n```bash\nnpm cache clean --force\n```\n"
	case "yarn":
		return cacheAdviceHeading + "\nClear the Yarn cache before switching registries:\n\n```bash\nyarn cache clean\n```\n"
	case "pip":
		return cacheAdviceHeading + "\nClear the pip cache before switching indexes:\n\n```bash\npip cache purge\n```\n"
	case "maven":
		return cacheAdviceHeading + "\nClear the local Maven repository cache to avoid stale metadata:\n\n```bash\nmvn dependency:purge-local-repository\n```\n"
	case "nuget":
		return cacheAdviceHeading + "\nClear NuGet caches before switching sources:\n\n```bash\ndotnet nuget locals all --clear\n```\n"
	case "composer":
		return cacheAdviceHeading + "\nClear the Composer cache before switching registries:\n\n```bash\ncomposer clear-cache\n```\n"
	case "go":
		return cacheAdviceHeading + "\nClear the Go module download cache:\n\n```bash\ngo clean -modcache\n```\n"
	case "apt":
		return cacheAdviceHeading + "\nClear local apt metadata before switching mirrors:\n\n```bash\nsudo apt-get clean\n```\n"
	case "yum":
		return cacheAdviceHeading + "\nClear Yum metadata before switching mirrors:\n\n```bash\nsudo yum clean all\n```\n"
	case "dnf":
		return cacheAdviceHeading + "\nClear DNF metadata before switching mirrors:\n\n```bash\nsudo dnf clean all\n```\n"
	case "docker":
		return cacheAdviceHeading + "\nPrune local Docker image cache before pulling through the proxy:\n\n```bash\ndocker system prune --force\n```\n"
	case "gradle":
		return cacheAdviceHeading + "\nClear the Gradle dependency cache before switching repositories:\n\n```bash\nrm -rf ~/.gradle/caches\n```\n"
	case "cocoapods":
		return cacheAdviceHeading + "\nClear the CocoaPods cache before switching sources:\n\n```bash\npod cache clean --all\n```\n"
	case "swift":
		return cacheAdviceHeading + "\nRemove SPM's package resolution state before switching registries:\n\n```bash\nrm -rf .build ~/Library/Caches/org.swift.swiftpm\n```\n"
	default:
		return ""
	}
}

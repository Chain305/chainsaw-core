package intelligence

// installScriptsProvider wraps the pure installscripts.* parsers. It is a
// Tier-2 provider: it needs the raw artifact bytes so it can pick the
// ecosystem-specific manifest file(s) out of the archive before handing
// them to installscripts.NPM / Pip / RubyGems / Cargo / Composer.
//
// As of Wave 0a the archive walk is consolidated through
// ArtifactHandle.SharedArtifactMap so Tier-2 siblings (hidden unicode
// and the 9 scanners landing in Wave 3) share one decompression pass.
// The legacy per-provider walker lives as a fallback in
// artifact_fallback.go and runs only when SharedArtifactMap returns an
// empty result (impossible in the Service pipeline — reserved for
// narrow unit-test paths).

import (
	"context"
	"encoding/json"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/chain305/chainsaw-core/featureflags"
	"github.com/chain305/chainsaw-core/installscripts"
	"github.com/chain305/chainsaw-core/intelligence/artifactmap"
)

// installscriptAstEnabled gates the AST-mode upgrade for the npm
// (package.json) and pip (pyproject.toml) detectors. Default OFF — when
// the flag is off the legacy regex-based installscripts.NPM /
// installscripts.Pip functions run unchanged.
//
// Resolution (handled by featureflags.Eval):
//
//  1. CHAINSAW_FF_INSTALLSCRIPT_AST env override (kill switch for ops)
//  2. `installscript_ast` PostHog flag, per-org via the scan's
//     req.OrgID (rolls out to specific customers without redeploy)
//  3. default false
//
// The hot-path concern that originally motivated an env-var-only check
// is now satisfied by the PostHog SDK's local evaluation mode (enabled
// in featureflags.New when POSTHOG_PERSONAL_API_KEY is set): IsEnabled
// becomes an in-memory map lookup, no HTTP per scan.
func installscriptAstEnabled(ctx context.Context, orgID string) bool {
	return featureflags.Default().Eval(ctx, "installscript_ast", "", orgID, false)
}

// installScriptsProvider holds no state — the detector functions are pure.
type installScriptsProvider struct{}

func newInstallScriptsProvider() *installScriptsProvider {
	return &installScriptsProvider{}
}

func (p *installScriptsProvider) Name() string { return "installscripts" }

func (p *installScriptsProvider) Signal() SignalMask { return SignalInstallScripts }

// Tier: needs the artifact bytes.
func (p *installScriptsProvider) Tier() int { return 2 }

// NeedsArtifact: true — we have nothing to do without bytes.
func (p *installScriptsProvider) NeedsArtifact() bool { return true }

// supportedInstallScriptEcosystems is the explicit whitelist of ecosystems
// for which the installscripts package has a parser. Aliases (yarn, bun,
// pypi) collapse to the canonical npm / pip paths.
var supportedInstallScriptEcosystems = map[string]struct{}{
	"npm":      {},
	"yarn":     {},
	"bun":      {},
	"pip":      {},
	"pypi":     {},
	"rubygems": {},
	"cargo":    {},
	"composer": {},
	"nuget":    {},
}

// Supports checks the ecosystem against the explicit coverage list.
func (p *installScriptsProvider) Supports(ecosystem string) bool {
	_, ok := supportedInstallScriptEcosystems[strings.ToLower(strings.TrimSpace(ecosystem))]
	return ok
}

// Run extracts the per-ecosystem manifest file(s) from the artifact bytes
// and hands them to the appropriate installscripts.* parser.
func (p *installScriptsProvider) Run(ctx context.Context, req Request, prior *Report) (PartialReport, error) {
	if req.Artifact == nil || len(req.Artifact.Bytes) == 0 {
		return PartialReport{}, nil
	}
	ecosystem := strings.ToLower(strings.TrimSpace(req.Key.Ecosystem))

	files := ManifestsFor(req.Artifact)

	var (
		result      installscripts.Result
		extraSeen   []string
		extraScript bool
		extraFetch  bool
		extraMutate bool
	)

	astEnabled := installscriptAstEnabled(ctx, req.OrgID)
	switch ecosystem {
	case "npm", "yarn", "bun":
		if len(files) == 0 {
			return PartialReport{}, nil
		}
		manifest := FirstMatch(files, "package.json")
		if astEnabled {
			result = installscripts.NPMAST(manifest)
		} else {
			result = installscripts.NPM(manifest)
		}
	case "pip", "pypi":
		setupPy := FirstMatch(files, "setup.py")
		pyproject := FirstMatch(files, "pyproject.toml")
		// setup.cfg fallback — not in the shared manifest filter, walk
		// the archive ourselves. When setup.py is empty or a stub
		// (`from setuptools import setup; setup()`) the install logic
		// lives in setup.cfg.
		setupCfg := walkForFile(req.Artifact, "setup.cfg")
		if len(setupPy) == 0 && len(pyproject) == 0 && len(setupCfg) == 0 && len(files) == 0 {
			return PartialReport{}, nil
		}
		if astEnabled {
			result = installscripts.PipAST(setupPy, pyproject)
		} else {
			result = installscripts.Pip(setupPy, pyproject)
		}
		if len(setupCfg) > 0 {
			extraSeen = append(extraSeen, "setup.cfg")
			if cfgHas, cfgFetch := scanSetupCfg(setupCfg); cfgHas {
				extraScript = true
				if cfgFetch {
					extraFetch = true
				}
			}
		}
	case "rubygems":
		if len(files) == 0 {
			return PartialReport{}, nil
		}
		gemspec := firstGemspec(files)
		result = installscripts.RubyGems(gemspec)
		// Surface explicit extconf.rb / extension declarations from
		// `s.extensions = [...]`.
		if exts := parseGemspecExtensions(gemspec); len(exts) > 0 {
			extraScript = true
			for _, e := range exts {
				extraSeen = append(extraSeen, "gemspec:extension:"+e)
			}
		}
	case "cargo":
		if len(files) == 0 {
			return PartialReport{}, nil
		}
		buildRs := FirstMatch(files, "build.rs")
		result = installscripts.Cargo(
			FirstMatch(files, "Cargo.toml"),
			buildRs,
		)
		if len(buildRs) > 0 {
			if hits := scanBuildRs(buildRs); len(hits) > 0 {
				extraScript = true
				for _, h := range hits {
					extraSeen = append(extraSeen, "build.rs:"+h)
				}
				if hasNetworkOrShell(hits) {
					extraFetch = true
				}
			}
		}
	case "composer":
		if len(files) == 0 {
			return PartialReport{}, nil
		}
		composerJSON := FirstMatch(files, "composer.json")
		result = installscripts.Composer(composerJSON)
		// Parse the `bin` field — declares executables installed into
		// vendor/bin/ and can ship attacker scripts.
		if bins := parseComposerBin(composerJSON); len(bins) > 0 {
			extraScript = true
			for _, b := range bins {
				extraSeen = append(extraSeen, "composer.json:bin:"+b)
			}
		}
	case "nuget":
		hooks := walkNuGetHooks(req.Artifact)
		if len(hooks) == 0 {
			return PartialReport{}, nil
		}
		result.Ecosystem = "nuget"
		// Concatenate all hook bodies and run the same fetches_remote
		// classification used by the installscripts parsers.
		var body strings.Builder
		for name, b := range hooks {
			extraSeen = append(extraSeen, name)
			body.Write(b)
			body.WriteString("\n")
		}
		extraScript = true
		result.HasInstallScript = true
		result.Kind = installscripts.KindPresent
		if fetchesRemoteRE.MatchString(body.String()) {
			extraFetch = true
			result.Kind = installscripts.KindFetchesRemote
		}
	default:
		return PartialReport{}, nil
	}

	// Bundled-install-script body scan (Shai-Hulud / "bun" loader wave).
	//
	// When an install hook invokes a LOCAL bundled script
	// (`preinstall: node setup_bun.js`), the manifest string only shows the
	// reference — the payload lives in that file's body. Resolve each
	// referenced script from the artifact and run the same fetch/exec/exfil
	// classifier on its body. Escalate to fetches_remote ONLY when a body
	// exhibits the fetch+exec / obfuscated-loader pattern or mutates a sibling
	// dependency under node_modules. The latter stays warning-grade; it never
	// sets InstallScriptFetches.
	if result.HasInstallScript && result.ScriptBody != "" {
		refHits := scanReferencedScripts(req.Artifact, result.ScriptBody)
		for _, h := range refHits {
			extraScript = true
			extraSeen = append(extraSeen, "ref:"+h.path+":"+string(h.kind))
			if h.kind == installscripts.KindFetchesRemote {
				extraFetch = true
			}
			if h.kind == installscripts.KindMutatesDependency {
				extraMutate = true
			}
		}
	}

	hasInstall := result.HasInstallScript || extraScript
	fetches := result.Kind == installscripts.KindFetchesRemote || extraFetch

	kind := string(result.Kind)
	if extraScript && !result.HasInstallScript {
		if extraFetch {
			kind = string(installscripts.KindFetchesRemote)
		} else {
			kind = string(installscripts.KindPresent)
		}
	} else if extraFetch && result.Kind != installscripts.KindFetchesRemote {
		kind = string(installscripts.KindFetchesRemote)
	} else if extraMutate && result.Kind == installscripts.KindPresent {
		kind = string(installscripts.KindMutatesDependency)
	}

	scan := &ArtifactScanSection{
		Performed:            true,
		InstallScriptKind:    kind,
		HasInstallScript:     hasInstall,
		InstallScriptFetches: fetches,
	}
	seen := make([]string, 0, len(files)+len(extraSeen))
	for name := range files {
		seen = append(seen, name)
	}
	seen = append(seen, extraSeen...)
	scan.ManifestFilesSeen = seen

	return PartialReport{Scan: scan}, nil
}

var _ Provider = (*installScriptsProvider)(nil)

// refScriptHit is one resolved bundled-script body scan result.
type refScriptHit struct {
	path string
	kind installscripts.Kind
}

// scanReferencedScripts parses install-hook commands out of scriptBody,
// resolves each referenced LOCAL script against the artifact's source files,
// and classifies each body with the shared fetch/exec/exfil heuristics. Only
// scripts that are actually present in the artifact AND classify above
// KindPresent are returned — a referenced file that is absent, or whose body
// is benign, contributes nothing (no signal, no false positive).
func scanReferencedScripts(h *ArtifactHandle, scriptBody string) []refScriptHit {
	refs := installscripts.ReferencedScripts(scriptBody)
	if len(refs) == 0 {
		return nil
	}
	srcFiles := sourceFilesFor(h)
	if len(srcFiles) == 0 {
		return nil
	}
	var out []refScriptHit
	seen := map[string]struct{}{}
	// Bound total resolved-file work: a first hop per hook plus one staged
	// second hop. maxResolve caps pathological fan-out from a body that names
	// dozens of .js literals.
	const maxResolve = 16
	resolved := 0

	// scanOne resolves a ref to ALL its candidate files and scans each. If ANY
	// candidate is malware-shaped it returns that hit immediately (closing the
	// decoy-shadow bypass). Otherwise it returns the shallowest present body so
	// the caller can follow a clean loader's next hop. Returns ("","") only when
	// the ref resolves to nothing bundled.
	scanOne := func(ref string) (installscripts.Kind, string, string) {
		var firstPath, firstBody string
		for _, rs := range resolveBundledScripts(srcFiles, ref) {
			if resolved >= maxResolve {
				break
			}
			if _, dup := seen[rs.path]; dup {
				continue
			}
			seen[rs.path] = struct{}{}
			resolved++
			bs := string(rs.body)
			if k := installscripts.ScanReferencedBody(bs); k == installscripts.KindFetchesRemote || k == installscripts.KindEvalEncoded || k == installscripts.KindMutatesDependency {
				return k, rs.path, bs
			}
			if firstPath == "" {
				firstPath, firstBody = rs.path, bs
			}
		}
		if firstPath == "" {
			return installscripts.KindNone, "", ""
		}
		return installscripts.KindPresent, firstPath, firstBody
	}

	for _, ref := range refs {
		if resolved >= maxResolve {
			break
		}
		kind, matchedPath, body := scanOne(ref)
		if matchedPath == "" {
			continue
		}
		// Only surface a hit when the body classifies above plain present.
		// KindPresent means a benign local build script (no fetch-and-exec and
		// no sibling dependency mutation), which must not add any signal.
		if kind == installscripts.KindFetchesRemote || kind == installscripts.KindEvalEncoded || kind == installscripts.KindMutatesDependency {
			out = append(out, refScriptHit{path: matchedPath, kind: kind})
			continue
		}
		// Staged-payload second hop: a clean-looking first-hop loader
		// (setup_bun.js) that spawns a sibling bundled script
		// (bun_environment.js) named as a string literal. Resolve and scan
		// each named next-hop file. The payload blob lives there, not in the
		// loader. Bounded to a single extra hop.
		if body == "" {
			continue
		}
		for _, hop := range installscripts.NextHopScripts(body) {
			if resolved >= maxResolve {
				break
			}
			hk, hopPath, _ := scanOne(hop)
			if hopPath == "" {
				continue
			}
			if hk == installscripts.KindFetchesRemote || hk == installscripts.KindEvalEncoded || hk == installscripts.KindMutatesDependency {
				out = append(out, refScriptHit{path: hopPath, kind: hk})
			}
		}
	}
	return out
}

// resolvedScript is one bundled file matching an install-hook reference.
type resolvedScript struct {
	body []byte
	path string
}

// resolveBundledScripts looks up a package-root-relative reference in the
// artifact's source-file map and returns ALL matches, ranked shallowest-first,
// bounded. npm tarballs prefix entries with "package/" and pip sdists with
// "<name>-<version>/"; the reference is root-relative, so we match on the path
// SUFFIX (after any single leading archive-prefix segment) as well as the exact
// basename.
//
// SECURITY — return EVERY match, not just the shallowest: an attacker fully
// controls the tarball layout and can plant a benign decoy at the root
// (package/index.js) while burying the real payload one dir down
// (package/lib/index.js). Resolving only the shallowest candidate would scan
// the decoy and never see the payload (reviewer-confirmed shadow bypass). So
// the caller scans every candidate; the shallowest-first ordering is only for
// determinism and for picking the next-hop loader body.
func resolveBundledScripts(srcFiles map[string][]byte, ref string) []resolvedScript {
	lowerRef := strings.ToLower(ref)
	var names []string
	for name := range srcFiles {
		ln := strings.ToLower(name)
		if ln == lowerRef || strings.HasSuffix(ln, "/"+lowerRef) {
			names = append(names, name)
		}
	}
	// Basename-only fallback for a bare-filename ref (no directory component)
	// when the suffix match missed entirely. Restricted to slash-free refs so a
	// `scripts/x.js` ref never matches an unrelated top-level `x.js`.
	if len(names) == 0 && !strings.Contains(ref, "/") {
		base := strings.ToLower(path.Base(ref))
		for name := range srcFiles {
			if strings.ToLower(path.Base(name)) == base {
				names = append(names, name)
			}
		}
	}
	// Shallowest-first (fewest path segments), ties broken by path for
	// determinism (map iteration is non-deterministic).
	sort.Slice(names, func(i, j int) bool {
		si, sj := strings.Count(names[i], "/"), strings.Count(names[j], "/")
		if si != sj {
			return si < sj
		}
		return names[i] < names[j]
	})
	// Cap candidates per ref so a tarball stuffed with same-basename files can't
	// blow up the scan (maxResolve in the caller bounds total work too).
	const maxCandidatesPerRef = 8
	if len(names) > maxCandidatesPerRef {
		names = names[:maxCandidatesPerRef]
	}
	out := make([]resolvedScript, 0, len(names))
	for _, name := range names {
		out = append(out, resolvedScript{body: srcFiles[name], path: name})
	}
	return out
}

// sourceFilesFor returns the source/text file bodies from the shared artifact
// map — the bundled scripts an install hook can invoke (.js/.ts/.py/.sh and
// friends). Keyed by lower-cased archive path. Bodies are already bounded by
// artifactmap.PerFileCap (2 MiB), so a minified loader blob is captured whole
// up to the cap without risking OOM.
func sourceFilesFor(h *ArtifactHandle) map[string][]byte {
	res := h.SharedArtifactMap()
	if len(res.Files) == 0 {
		return legacyWalkArtifact(h, wantsBundledScript)
	}
	return res.Files.SelectLower(wantsBundledScript)
}

// wantsBundledScript matches the extensions an install hook can invoke as a
// bundled script body. A superset of artifactmap.WantsSourceCode for the shell
// scripts (.sh/.bash) install hooks commonly call.
func wantsBundledScript(name string) bool {
	ext := strings.ToLower(path.Ext(strings.TrimSpace(name)))
	switch ext {
	case ".js", ".cjs", ".mjs", ".ts", ".tsx", ".jsx",
		".py", ".sh", ".bash":
		return true
	}
	return false
}

// ManifestsFor returns the installscripts manifest subset of the shared
// artifact map, keyed by lower-case path (so callers can do
// case-insensitive base-name lookups via FirstMatch/firstGemspec).
// Falls back to the legacy per-provider walker if the shared map came
// back empty AND the handle has bytes — this preserves behavioural
// parity with narrow tests that construct a provider directly.
//
// Exported as part of the open-core seam: the premium aiartifact provider
// (internal/intelligence/premium) reuses this manifest accessor.
func ManifestsFor(h *ArtifactHandle) map[string][]byte {
	res := h.SharedArtifactMap()
	if len(res.Files) == 0 {
		return legacyWalkManifests(h)
	}
	return res.Files.SelectLower(artifactmap.WantsInstallManifest)
}

// FirstMatch returns the body of the first entry whose basename matches
// `basename` (case-insensitive). npm tarballs ship their manifest under
// "package/package.json"; we don't want the caller to guess the prefix.
//
// Exported as part of the open-core seam: the premium aiartifact provider
// (internal/intelligence/premium) reuses this manifest lookup.
func FirstMatch(files map[string][]byte, basename string) []byte {
	lower := strings.ToLower(basename)
	for name, body := range files {
		if strings.ToLower(path.Base(name)) == lower {
			return body
		}
	}
	return nil
}

// firstGemspec returns the body of the first *.gemspec entry in the map.
func firstGemspec(files map[string][]byte) []byte {
	for name, body := range files {
		if strings.HasSuffix(strings.ToLower(path.Base(name)), ".gemspec") {
			return body
		}
	}
	return nil
}

// walkForFile collects the body of the first archive entry whose
// basename matches `basename` (case-insensitive). Used for files that
// the shared manifest filter doesn't cover (e.g. setup.cfg).
func walkForFile(h *ArtifactHandle, basename string) []byte {
	lower := strings.ToLower(basename)
	matches := legacyWalkArtifact(h, func(name string) bool {
		return strings.ToLower(path.Base(name)) == lower
	})
	for _, body := range matches {
		return body
	}
	return nil
}

// walkNuGetHooks collects PowerShell hook scripts from a .nupkg (zip).
// install.ps1 / uninstall.ps1 / init.ps1 living under tools/ run when
// the package is installed into a project.
func walkNuGetHooks(h *ArtifactHandle) map[string][]byte {
	want := func(name string) bool {
		clean := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(name), "\\", "/"))
		base := path.Base(clean)
		switch base {
		case "install.ps1", "uninstall.ps1", "init.ps1":
		default:
			return false
		}
		// Accept tools/install.ps1, tools/net45/install.ps1, etc.
		return strings.Contains(clean, "tools/") || strings.HasPrefix(clean, "tools/")
	}
	out := legacyWalkArtifact(h, want)
	if len(out) == 0 {
		return nil
	}
	return out
}

// fetchesRemoteRE mirrors the installscripts package's classifier so we
// can apply the same remote-fetch test to file bodies the shared parser
// doesn't yet cover (e.g. NuGet hook scripts).
var fetchesRemoteRE = regexp.MustCompile(
	`curl\b|wget\b|\bfetch\s*\(|https\.get\b|urllib\b|requests\.get\b|subprocess\b|child_process\.exec\b|os\.system\b|\beval\s*\(|\bFunction\s*\(|Invoke-WebRequest|Invoke-Expression|Net\.WebClient|DownloadString|DownloadFile|Start-Process`,
)

// gemspecExtensionsRE captures values inside `s.extensions = [ ... ]`
// (or `spec.extensions = [...]`). We accept either array or `<<` push
// syntax; the inner value is read leniently as everything up to the
// closing bracket / EOL.
var gemspecExtensionsRE = regexp.MustCompile(
	`(?m)\b(?:s|spec|gem|gemspec)\.extensions\s*(?:=|<<)\s*(.+)$`,
)

// gemspecExtensionItemRE pulls quoted filenames out of a captured
// `s.extensions = ...` value.
var gemspecExtensionItemRE = regexp.MustCompile(`["']([^"']+)["']`)

// parseGemspecExtensions returns the file paths declared in the
// gemspec's `s.extensions = [...]` field. Empty if none are declared.
func parseGemspecExtensions(gemspec []byte) []string {
	if len(gemspec) == 0 {
		return nil
	}
	var out []string
	for _, m := range gemspecExtensionsRE.FindAllSubmatch(gemspec, -1) {
		if len(m) < 2 {
			continue
		}
		for _, item := range gemspecExtensionItemRE.FindAllSubmatch(m[1], -1) {
			if len(item) >= 2 {
				out = append(out, string(item[1]))
			}
		}
	}
	return out
}

// parseComposerBin returns the executables declared in composer.json's
// `bin` field. The field is either a string or an array of strings;
// missing / malformed values yield an empty slice.
func parseComposerBin(composerJSON []byte) []string {
	if len(composerJSON) == 0 {
		return nil
	}
	var manifest struct {
		Bin json.RawMessage `json:"bin"`
	}
	if err := json.Unmarshal(composerJSON, &manifest); err != nil {
		return nil
	}
	if len(manifest.Bin) == 0 {
		return nil
	}
	var single string
	if err := json.Unmarshal(manifest.Bin, &single); err == nil {
		if strings.TrimSpace(single) == "" {
			return nil
		}
		return []string{single}
	}
	var arr []string
	if err := json.Unmarshal(manifest.Bin, &arr); err == nil {
		out := make([]string, 0, len(arr))
		for _, s := range arr {
			if strings.TrimSpace(s) != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// scanSetupCfg reports whether a setup.cfg body declares install-time
// hooks, and whether the body references a remote-fetch primitive. The
// scan is a tiny manual pass — we only look for `[options]` markers
// (entry_points, scripts, install_requires, cmdclass) and for
// fetches_remote markers in the raw text.
func scanSetupCfg(body []byte) (hasScript, fetches bool) {
	if len(body) == 0 {
		return false, false
	}
	text := string(body)
	lower := strings.ToLower(text)
	markers := []string{
		"entry_points", "scripts", "cmdclass",
		"install_requires", "[options.entry_points]",
		"setup_requires",
	}
	for _, m := range markers {
		if strings.Contains(lower, m) {
			hasScript = true
			break
		}
	}
	if fetchesRemoteRE.MatchString(text) {
		hasScript = true
		fetches = true
	}
	return hasScript, fetches
}

// buildRsScanRE matches a small set of shell exec / network primitives
// commonly abused inside Cargo build.rs scripts. Best-effort regex —
// false positives are tolerable, false negatives are the failure mode
// we care about.
var buildRsScanRE = regexp.MustCompile(
	`Command::new\b|process::Command\b|std::process\b|reqwest\b|hyper\b|ureq\b|curl\b|wget\b|/bin/sh\b|/bin/bash\b|powershell\b|net::TcpStream\b|TcpStream::connect\b`,
)

// scanBuildRs returns the distinct primitive names matched in a
// build.rs body. Empty when the body is benign.
func scanBuildRs(body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	hits := buildRsScanRE.FindAll(body, -1)
	if len(hits) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(hits))
	out := make([]string, 0, len(hits))
	for _, h := range hits {
		s := string(h)
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// hasNetworkOrShell reports whether any build.rs hit corresponds to a
// network or shell-exec primitive (as opposed to a benign process
// reference). Used to decide whether to escalate Kind to fetches_remote.
func hasNetworkOrShell(hits []string) bool {
	for _, h := range hits {
		switch h {
		case "reqwest", "hyper", "ureq", "curl", "wget",
			"net::TcpStream", "TcpStream::connect",
			"/bin/sh", "/bin/bash", "powershell":
			return true
		}
	}
	return false
}

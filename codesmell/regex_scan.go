package codesmell

import "bytes"

// runRules applies a signalRules set to a file map and returns a Result.
// This is the shared driver for UsesEval / NetworkAccess / ShellAccess /
// FilesystemAccess / EnvVarAccess — all five are "first N matches of a
// per-language regex list" detectors.
//
// Each rule is run with FindIndex (first-match only) rather than
// FindAllIndex. The five consumers that read this result only care
// about the Fired bit; the Matches slice is a nice-to-have for UI
// findings but does not need to be exhaustive. A first-match-per-rule
// strategy keeps the total regex work linear in (files × rules) rather
// than quadratic in file size, which is what lets the 9-scanner
// fan-out stay inside the 3s DefaultProviderTimeout on a 10MB archive.
func runRules(files map[string][]byte, rules *signalRules) Result {
	var res Result
	if len(files) == 0 {
		return res
	}
	iterFiles(files, func(name string, body []byte, lang Language) bool {
		combined := rules.Combined[lang]
		if combined == nil {
			return true
		}
		// Anchor prefilter — a linear bytes.Contains sweep over the
		// per-rule literal anchors. Skips the regex engine entirely
		// on the vast majority of files (clean source doesn't carry
		// "eval(" / "fetch(" / "child_process" etc.).
		if anchors := rules.Anchors[lang]; anchors != nil {
			hit := false
			for _, a := range anchors {
				if bytes.Contains(body, a) {
					hit = true
					break
				}
			}
			if !hit {
				return true
			}
		}
		// Regex pass — one combined-alternation engine call.
		loc := combined.FindIndex(body)
		if loc == nil {
			return true
		}
		// Hit path — identify the specific rule for the Kind tag.
		// This costs O(rules) but only on files with a confirmed hit,
		// which is a small minority in practice.
		kind := ""
		for _, pat := range rules.ByLang[lang] {
			if pat.Re.MatchString(string(body[loc[0]:loc[1]])) {
				kind = pat.Tag
				break
			}
		}
		res.addMatch(Match{
			Path:    name,
			Line:    lineOf(body, loc[0]),
			Snippet: snippetAt(body, loc[0]),
			Kind:    kind,
		})
		return true
	})
	return res
}

// ScanEval looks for dynamic-code-evaluation primitives.
func ScanEval(files map[string][]byte) Result { return runRules(files, &evalRules) }

// ScanNetwork looks for network-access primitives (http, fetch, raw sockets).
func ScanNetwork(files map[string][]byte) Result { return runRules(files, &networkRules) }

// ScanShell looks for shell / subprocess execution primitives.
func ScanShell(files map[string][]byte) Result { return runRules(files, &shellRules) }

// ScanFilesystem looks for direct filesystem access (open / read / write / unlink).
func ScanFilesystem(files map[string][]byte) Result { return runRules(files, &filesystemRules) }

// ScanEnvVars looks for environment-variable access.
func ScanEnvVars(files map[string][]byte) Result { return runRules(files, &envVarRules) }

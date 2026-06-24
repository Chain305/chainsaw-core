// Package capability statically analyses a package's source tree and emits
// capability flags — what a package *can do* at runtime (open sockets,
// shell out, read env, etc.). This is the "permission grading" surface
// that Socket.dev surfaces prominently; Chainsaw v1 covers npm only.
//
// # Design
//
// The analyser uses simple regex/substring scanning rather than a full AST.
// Socket.dev itself does not ship a type-checked AST analyser — speed and
// broad coverage matter more than zero false positives for this signal class.
// Capability flags are informational by default (severity "info"); policy
// rules can upgrade specific combinations to warn/block.
//
// # Extending to other ecosystems
//
// Add a new package under internal/capability/<ecosystem>/ that implements
// the same scan logic (walk source files, match patterns, return Evidence).
// Register the ecosystem string in Analyze() below.
//
// TODO(capability): pip — scan for socket/subprocess/os imports in *.py
// TODO(capability): rubygems — scan for Net::HTTP, Open3, etc. in *.rb
// TODO(capability): cargo — scan for std::net, std::process in *.rs
package capability

// Capability is a named runtime permission/capability that a package may
// exhibit. The string form is used as the signal ID in the risk registry
// (prefix "cap.").
type Capability string

const (
	// CapNetwork — package can open TCP/UDP sockets or make HTTP requests.
	// Patterns: require('net'), require('http'), require('https'),
	// require('dgram'), require('tls'), fetch(, XMLHttpRequest.
	CapNetwork Capability = "cap.network"

	// CapShell — package can execute shell commands / subprocesses.
	// Patterns: require('child_process'), exec(, execSync(, spawn(, spawnSync(.
	CapShell Capability = "cap.shell"

	// CapFilesystemWrite — package can write, delete or rename files.
	// Patterns: fs.writeFile, fs.writeFileSync, fs.appendFile,
	// fs.createWriteStream, fs.unlink, fs.rename.
	CapFilesystemWrite Capability = "cap.filesystem_write"

	// CapFilesystemRead — package can read files or directories.
	// Patterns: fs.readFile, fs.readFileSync, fs.createReadStream, fs.readdir.
	CapFilesystemRead Capability = "cap.filesystem_read"

	// CapEnvAccess — package reads process environment variables.
	// Pattern: process.env.
	CapEnvAccess Capability = "cap.env_access"

	// CapNativeCode — package uses native (C/C++) bindings or ships .node files.
	// Patterns: .node files present, bindings(, node-gyp in devDependencies,
	// binding.gyp present.
	CapNativeCode Capability = "cap.native_code"

	// CapDynamicEval — package executes dynamically-constructed code.
	// Patterns: eval(, Function(, vm.runInThisContext, vm.runInNewContext.
	// This is rarely benign in shipped libraries.
	CapDynamicEval Capability = "cap.dynamic_eval"

	// CapMinifiedOrBundled is set instead of scanning when a file exceeds
	// MaxFileScanBytes. Minified/vendored bundles cannot be reliably scanned
	// with substring matching; callers should note that the bundle *may*
	// contain any capability.
	CapMinifiedOrBundled Capability = "cap.minified_or_bundled"
)

// AllCapabilities is the ordered list of capability constants for stable
// iteration (useful for docs generation and tests).
var AllCapabilities = []Capability{
	CapNetwork,
	CapShell,
	CapFilesystemWrite,
	CapFilesystemRead,
	CapEnvAccess,
	CapNativeCode,
	CapDynamicEval,
	CapMinifiedOrBundled,
}

// Evidence is one concrete location in the source tree that triggered a
// capability detection. Up to MaxEvidencePerCap entries are recorded per
// capability — beyond that the scanner stops collecting (but continues
// reporting the capability itself).
type Evidence struct {
	// File is the path relative to the package root.
	File string `json:"file"`
	// Line is the 1-based line number. 0 means "not line-located" (used
	// for file-level detections such as .node binaries).
	Line int `json:"line,omitempty"`
	// Snippet is the matched text, truncated to MaxSnippetLen chars.
	Snippet string `json:"snippet,omitempty"`
}

// MaxEvidencePerCap is the maximum number of Evidence entries stored per
// capability. Capping prevents very large reports from repetitive patterns.
const MaxEvidencePerCap = 3

// MaxSnippetLen is the maximum byte length of an Evidence.Snippet.
const MaxSnippetLen = 120

// MaxFileScanBytes is the maximum size of a source file that will be
// scanned. Files larger than this are likely minified/vendored bundles;
// CapMinifiedOrBundled is recorded for them instead.
const MaxFileScanBytes = 5 * 1024 * 1024 // 5 MB

// Report is the output of a capability scan run.
type Report struct {
	// Ecosystem that was scanned.
	Ecosystem string `json:"ecosystem"`
	// Unsupported is true when the ecosystem has no capability scanner yet.
	// No capabilities are populated in this case; callers should not treat
	// absence-of-capabilities as "clean".
	Unsupported bool `json:"unsupported,omitempty"`
	// Capabilities maps each detected capability to its evidence list.
	// Absent key means the capability was not detected (not that it was
	// ruled out — the scanner is conservative, not exhaustive).
	Capabilities map[Capability][]Evidence `json:"capabilities,omitempty"`
}

// Has reports whether the Report detected a given capability.
func (r *Report) Has(c Capability) bool {
	if r == nil {
		return false
	}
	_, ok := r.Capabilities[c]
	return ok
}

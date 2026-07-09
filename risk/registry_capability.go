package risk

// Capability signal IDs. These map to the Capability constants in
// internal/capability/types.go — the "cap." prefix ties them together.
//
// Capability flags are informational by default (severity=info, weight=0)
// so that existing policies are not affected. Operators or higher-level
// policy rules can combine capability signals with supply-chain signals
// to produce meaningful blocks (e.g. "new dep with cap.shell + cap.network
// on first-time-collaborator publish → block").
//
// Cap.dynamic_eval is the sole exception: eval() is rarely benign in
// shipped libraries, so it defaults to severity=warn.
const (
	SignalCapNetwork         = "cap.network"
	SignalCapShell           = "cap.shell"
	SignalCapFilesystemWrite = "cap.filesystem_write"
	SignalCapFilesystemRead  = "cap.filesystem_read"
	SignalCapEnvAccess       = "cap.env_access"
	SignalCapNativeCode      = "cap.native_code"
	SignalCapDynamicEval     = "cap.dynamic_eval"
)

func init() {
	register(Signal{
		ID:          SignalCapNetwork,
		Category:    CategorySupplyChain,
		Severity:    SevInfo,
		Weight:      0,
		Title:       "Package can open network connections",
		Description: "Source code imports net/http/https/dgram/tls or uses fetch()/XMLHttpRequest — the package can make outbound network calls at runtime.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.CapNetwork {
				return false, "", nil
			}
			return true, "Package source imports network primitives (net/http/https/dgram/tls/fetch).",
				capEvidence(in.CapNetworkEvidence)
		},
	})

	register(Signal{
		ID:          SignalCapShell,
		Category:    CategorySupplyChain,
		Severity:    SevInfo,
		Weight:      0,
		Title:       "Package can execute shell commands",
		Description: "Source code imports child_process or calls exec/spawn — the package can run arbitrary commands at runtime.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.CapShell {
				return false, "", nil
			}
			return true, "Package source imports child_process or calls exec/spawn.",
				capEvidence(in.CapShellEvidence)
		},
	})

	register(Signal{
		ID:          SignalCapFilesystemWrite,
		Category:    CategorySupplyChain,
		Severity:    SevInfo,
		Weight:      0,
		Title:       "Package can write to the filesystem",
		Description: "Source code calls fs.writeFile/writeFileSync/appendFile/createWriteStream/unlink/rename.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.CapFilesystemWrite {
				return false, "", nil
			}
			return true, "Package source calls filesystem write APIs.",
				capEvidence(in.CapFilesystemWriteEvidence)
		},
	})

	register(Signal{
		ID:          SignalCapFilesystemRead,
		Category:    CategorySupplyChain,
		Severity:    SevInfo,
		Weight:      0,
		Title:       "Package can read from the filesystem",
		Description: "Source code calls fs.readFile/readFileSync/createReadStream/readdir — many packages legitimately read config files.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.CapFilesystemRead {
				return false, "", nil
			}
			return true, "Package source calls filesystem read APIs.",
				capEvidence(in.CapFilesystemReadEvidence)
		},
	})

	register(Signal{
		ID:          SignalCapEnvAccess,
		Category:    CategorySupplyChain,
		Severity:    SevInfo,
		Weight:      0,
		Title:       "Package reads environment variables",
		Description: "Source code references process.env — common and often benign, but combined with network access can exfiltrate secrets.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.CapEnvAccess {
				return false, "", nil
			}
			return true, "Package source reads process.env.",
				capEvidence(in.CapEnvAccessEvidence)
		},
	})

	register(Signal{
		ID:          SignalCapNativeCode,
		Category:    CategorySupplyChain,
		Severity:    SevInfo,
		Weight:      0,
		Title:       "Package uses native (C/C++) bindings",
		Description: "Package ships a .node file, binding.gyp, or references node-gyp — native addons bypass the V8 sandbox entirely.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.CapNativeCode {
				return false, "", nil
			}
			return true, "Package ships native addon or build descriptor.",
				capEvidence(in.CapNativeCodeEvidence)
		},
	})

	// cap.dynamic_eval is warn-severity: eval() is almost never needed in
	// shipped library code and is a common obfuscation entry point.
	register(Signal{
		ID:          SignalCapDynamicEval,
		Category:    CategorySupplyChain,
		Severity:    SevLow,
		Weight:      -3,
		Title:       "Package uses dynamic code evaluation",
		Description: "Source code calls eval(), Function(), or vm.runIn*Context() — dynamic eval is rarely benign in production libraries and is a common obfuscation vector.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.CapDynamicEval {
				return false, "", nil
			}
			return true, "Package source uses eval() or dynamic code construction.",
				capEvidence(in.CapDynamicEvalEvidence)
		},
	})
}

// capEvidence converts a slice of capability evidence structs to a
// map[string]any for the FiredSignal.Evidence field. Returns nil when
// there is no evidence to report.
func capEvidence(ev []CapEvidenceEntry) map[string]any {
	if len(ev) == 0 {
		return nil
	}
	entries := make([]map[string]any, 0, len(ev))
	for _, e := range ev {
		entry := map[string]any{"file": e.File}
		if e.Line > 0 {
			entry["line"] = e.Line
		}
		if e.Snippet != "" {
			entry["snippet"] = e.Snippet
		}
		entries = append(entries, entry)
	}
	return map[string]any{"locations": entries}
}

// CapEvidenceEntry is the risk-package-internal representation of a
// capability evidence item. It mirrors capability.Evidence but lives here
// to avoid a circular import between internal/risk and internal/capability.
// The projection from capability.Evidence to CapEvidenceEntry is done in
// the intelligence layer.
type CapEvidenceEntry struct {
	File    string
	Line    int
	Snippet string
}

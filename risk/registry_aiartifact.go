package risk

// AI-artifact signal IDs. These cover HuggingFace models / datasets /
// spaces and the cross-ecosystem agent-tool / MCP-server / prompt-template
// surface (npm and pypi packages that ship MCP servers).
//
// Routing into existing categories rather than introducing a new one keeps
// CategoryWeights summing to 1.0 (enforced by TestCategoryWeightsSumToOne)
// and lets these signals participate in the supply-chain rollup that the
// product already weights highest.
const (
	SignalAIDangerousPickle         = "ai.dangerous_pickle_opcode"
	SignalAISuspiciousPickle        = "ai.suspicious_pickle_opcode"
	SignalAIUnsafeSerialization     = "ai.unsafe_serialization_format"
	SignalAIPrefersSafetensors      = "ai.prefers_safetensors"
	SignalAIModelCardInjection      = "ai.model_card_injection"
	SignalAIAgentToolDangerous      = "ai.agent_tool_dangerous_capability"
	SignalAIAgentToolDeclared       = "ai.agent_tool_declared"
	SignalAIMCPServerUnverified     = "ai.mcp_server_unverified"
	SignalAIPromptTemplateInjection = "ai.prompt_template_injection"
)

func init() {
	// MaxImpact tier: CRITICAL (0-20). Pickle deserialization grants
	// arbitrary code execution on load — same severity class as malware.
	register(Signal{
		ID:          SignalAIDangerousPickle,
		Category:    CategorySupplyChain,
		Severity:    SevCritical,
		Weight:      -100,
		MaxImpact:   15,
		Title:       "Dangerous pickle opcode in model weights",
		Description: "A serialized weight file references a module with no legitimate place in a model checkpoint (os, subprocess, builtins.eval, …). Loading the file executes arbitrary code.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.DangerousPickleOpcode {
				return false, "", nil
			}
			return true,
				"Pickle deserialization grants the publisher arbitrary code execution.",
				map[string]any{
					"files":   in.DangerousPickleFiles,
					"summary": in.DangerousPickleSummary,
				}
		},
	})

	register(Signal{
		ID:          SignalAISuspiciousPickle,
		Category:    CategorySupplyChain,
		Severity:    SevMedium,
		Weight:      -15,
		Title:       "Pickle imports uncommon for model weights",
		Description: "Pickle stream references modules (ctypes, torch.distributed, …) that are unusual for serialized weights.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.SuspiciousPickleOpcode || in.DangerousPickleOpcode {
				return false, "", nil
			}
			return true,
				"Pickle imports modules not typically seen in checkpoints — review.",
				nil
		},
	})

	register(Signal{
		ID:          SignalAIUnsafeSerialization,
		Category:    CategorySupplyChain,
		Severity:    SevLow,
		Weight:      -10,
		Title:       "Unsafe serialization format (pickle without safetensors)",
		Description: "Artifact ships pickle weights and does not provide a safetensors alternative. Even without a malicious payload, pickle is a code-execution surface.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.UnsafeSerializationFormat {
				return false, "", nil
			}
			return true,
				"No safetensors alternative — consumers must trust pickle deserialization.",
				nil
		},
	})

	register(Signal{
		ID:          SignalAIPrefersSafetensors,
		Category:    CategorySupplyChain,
		Severity:    SevInfo,
		Weight:      +5,
		Title:       "Safetensors weights available",
		Description: "Artifact ships a safetensors copy of the weights — consumers can opt out of pickle deserialization.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.PrefersSafetensorsAvailable {
				return false, "", nil
			}
			return true,
				"Safetensors alternative is published — pin to it where possible.",
				nil
		},
	})

	register(Signal{
		ID:          SignalAIModelCardInjection,
		Category:    CategorySupplyChain,
		Severity:    SevMedium,
		Weight:      -20,
		Title:       "Model card contains injection markers",
		Description: "Card contains hidden unicode, classic prompt-injection phrasing, embedded <script>, or large base64 in frontmatter — tampering surface for downstream agents that ingest cards verbatim.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.ModelCardInjection {
				return false, "", nil
			}
			return true,
				"Model card contains tampering markers that can mislead downstream agents.",
				map[string]any{"kinds": in.ModelCardKinds}
		},
	})

	// MaxImpact tier: HIGH-confidence harmful (30-40). Declared dangerous
	// capability (filesystem write / subprocess / arbitrary egress) on a
	// tool the model can call.
	register(Signal{
		ID:          SignalAIAgentToolDangerous,
		Category:    CategorySupplyChain,
		Severity:    SevHigh,
		Weight:      -30,
		MaxImpact:   40,
		Title:       "Agent tool declares dangerous capability",
		Description: "Declared MCP server / agent tool exposes filesystem write, subprocess execution, or arbitrary network egress to the model.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.AgentToolDangerousCapability {
				return false, "", nil
			}
			return true,
				"Tool schema reveals data-exfiltration or RCE capabilities.",
				map[string]any{"capabilities": in.AgentToolCapabilities}
		},
	})

	register(Signal{
		ID:          SignalAIAgentToolDeclared,
		Category:    CategoryQuality,
		Severity:    SevInfo,
		Weight:      0,
		Title:       "Package declares an MCP server / agent tool",
		Description: "Inventory signal — package self-declares an MCP server or agent tool entry point. Use for visibility, not for blocking.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.AgentToolDeclared {
				return false, "", nil
			}
			return true,
				"Package self-declares an MCP server / agent tool.",
				nil
		},
	})

	register(Signal{
		ID:          SignalAIMCPServerUnverified,
		Category:    CategoryQuality,
		Severity:    SevLow,
		Weight:      -8,
		Title:       "MCP server lacks verified provenance",
		Description: "Package declares an MCP server but lacks sigstore/SLSA provenance or a verified source repository link.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.MCPServerUnverified {
				return false, "", nil
			}
			return true,
				"MCP server cannot be tied to a verified build or source repo.",
				nil
		},
	})

	register(Signal{
		ID:          SignalAIPromptTemplateInjection,
		Category:    CategorySupplyChain,
		Severity:    SevMedium,
		Weight:      -20,
		Title:       "Prompt template contains injection markers",
		Description: "Prompt-template artifact contains jailbreak phrasing, hidden unicode, or other tampering markers.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.PromptTemplateInjection {
				return false, "", nil
			}
			return true,
				"Prompt template contains injection markers.",
				nil
		},
	})
}

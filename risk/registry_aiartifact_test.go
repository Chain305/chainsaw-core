package risk

import "testing"

func TestAIArtifactSignalsRegistered(t *testing.T) {
	expected := []string{
		SignalAIDangerousPickle,
		SignalAISuspiciousPickle,
		SignalAIUnsafeSerialization,
		SignalAIPrefersSafetensors,
		SignalAIModelCardInjection,
		SignalAIAgentToolDangerous,
		SignalAIAgentToolDeclared,
		SignalAIMCPServerUnverified,
		SignalAIPromptTemplateInjection,
	}
	for _, id := range expected {
		if _, ok := Registry[id]; !ok {
			t.Fatalf("signal %q missing from Registry", id)
		}
	}
}

func TestAIArtifactSignalsFire(t *testing.T) {
	tests := []struct {
		id    string
		input Input
		want  bool
	}{
		{
			id:    SignalAIDangerousPickle,
			input: Input{DangerousPickleOpcode: true, DangerousPickleFiles: []string{"pytorch_model.bin"}},
			want:  true,
		},
		{
			id:    SignalAIDangerousPickle,
			input: Input{},
			want:  false,
		},
		{
			id:    SignalAISuspiciousPickle,
			input: Input{SuspiciousPickleOpcode: true},
			want:  true,
		},
		{
			// Suspicious must NOT fire when dangerous is also true (we
			// don't want both findings on the same artifact).
			id:    SignalAISuspiciousPickle,
			input: Input{SuspiciousPickleOpcode: true, DangerousPickleOpcode: true},
			want:  false,
		},
		{
			id:    SignalAIUnsafeSerialization,
			input: Input{UnsafeSerializationFormat: true},
			want:  true,
		},
		{
			id:    SignalAIPrefersSafetensors,
			input: Input{PrefersSafetensorsAvailable: true},
			want:  true,
		},
		{
			id:    SignalAIModelCardInjection,
			input: Input{ModelCardInjection: true, ModelCardKinds: []string{"hidden_unicode"}},
			want:  true,
		},
		{
			id:    SignalAIAgentToolDangerous,
			input: Input{AgentToolDangerousCapability: true, AgentToolCapabilities: []string{"filesystem-write"}},
			want:  true,
		},
		{
			id:    SignalAIAgentToolDeclared,
			input: Input{AgentToolDeclared: true},
			want:  true,
		},
		{
			id:    SignalAIMCPServerUnverified,
			input: Input{MCPServerUnverified: true},
			want:  true,
		},
		{
			id:    SignalAIPromptTemplateInjection,
			input: Input{PromptTemplateInjection: true},
			want:  true,
		},
	}
	for _, tt := range tests {
		s, ok := Registry[tt.id]
		if !ok {
			t.Fatalf("signal %q missing from registry", tt.id)
		}
		fired, _, _ := s.Fires(tt.input)
		if fired != tt.want {
			t.Fatalf("%s.Fires(%+v) = %v, want %v", tt.id, tt.input, fired, tt.want)
		}
	}
}

func TestAIArtifactSignalsHaveCategoriesInWeights(t *testing.T) {
	// Defensive: every signal must route to a category in CategoryWeights.
	// If a future change adds a new category for AI signals without updating
	// CategoryWeights this test will fail loudly.
	for _, id := range []string{
		SignalAIDangerousPickle,
		SignalAISuspiciousPickle,
		SignalAIUnsafeSerialization,
		SignalAIPrefersSafetensors,
		SignalAIModelCardInjection,
		SignalAIAgentToolDangerous,
		SignalAIAgentToolDeclared,
		SignalAIMCPServerUnverified,
		SignalAIPromptTemplateInjection,
	} {
		s := Registry[id]
		if _, ok := CategoryWeights[s.Category]; !ok {
			t.Fatalf("signal %q in category %q which is not in CategoryWeights", id, s.Category)
		}
	}
}

package risk

// cap.debug_access and cap.telemetry are socket.dev's debugAccess and
// telemetry alerts, reached from the package bytes by
// core/codesmell/debug_telemetry.go. Weight 0, like every codesmell-fed
// cap.* signal: an observation earns a verdict by being priced against the
// labelled corpus, and neither has been.
const (
	SignalCapDebugAccess = "cap.debug_access"
	SignalCapTelemetry   = "cap.telemetry"
	// SignalCapDynamicRequire is socket.dev's dynamicRequire: require()
	// with a non-literal argument, and Python's computed __import__ /
	// import_module. Not eval — that is cap.dynamic_eval*.
	SignalCapDynamicRequire = "cap.dynamic_require"
)

func init() {
	register(Signal{
		ID:          SignalCapDebugAccess,
		Category:    CategorySupplyChain,
		Severity:    SevInfo,
		Weight:      0,
		Title:       "Package uses runtime debug or introspection modules",
		Description: "JavaScript source imports node's vm, inspector or v8 module, or reaches internal bindings through process.binding — code that compiles, inspects or reaches under the runtime.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.CapDebugAccess {
				return false, "", nil
			}
			return true, "Package source imports vm, inspector or v8, or calls process.binding.",
				capEvidence(in.CapDebugAccessEvidence, 0)
		},
	})

	register(Signal{
		ID:          SignalCapTelemetry,
		Category:    CategorySupplyChain,
		Severity:    SevInfo,
		Weight:      0,
		Title:       "Package contains telemetry",
		Description: "Source code names a telemetry endpoint (a telemetry.* host, or Scarf) or reads a telemetry switch such as NEXT_TELEMETRY_DISABLED or DO_NOT_TRACK — the package likely reports on its own use.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.CapTelemetry {
				return false, "", nil
			}
			return true, "Package source names a telemetry endpoint or reads a telemetry switch.",
				capEvidence(in.CapTelemetryEvidence, 0)
		},
	})

	register(Signal{
		ID:          SignalCapDynamicRequire,
		Category:    CategorySupplyChain,
		Severity:    SevInfo,
		Weight:      0,
		Title:       "Package loads modules by computed name",
		Description: "JavaScript source calls require() with a non-literal argument (a variable, a path.join, a template with ${}), or Python source calls __import__() or importlib.import_module() with one, so which module is loaded is decided at run time.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.CapDynamicRequire {
				return false, "", nil
			}
			return true, "Package source loads a module by a computed name (require, __import__ or import_module).",
				capEvidence(in.CapDynamicRequireEvidence, 0)
		},
	})
}

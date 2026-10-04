package codesmell

// debug_telemetry.go holds the two scanners added for socket.dev's
// `debugAccess` and `telemetry` alerts. Both are OBSERVATIONS: the signals
// they feed (cap.debug_access, cap.telemetry) are weight 0.

var (
	debugAccessRules signalRules
	telemetryRules   signalRules
)

func init() {
	// --- DebugAccess -----------------------------------------------------
	//
	// Socket's alert reads "uses debug, reflection and dynamic code
	// execution features", and its worked example is the node `vm` module.
	// Checked against the bytes of every corpus-v1 package that fired it
	// and is still on npm (vm2 3.10.5 / 3.11.0, ys-coffee 1.7.2,
	// ys-coffee-script 1.6.3, seekcode 0.4.4): each one imports `vm`.
	//
	// eval()/Function() are NOT here: Socket reports those as usesEval,
	// a separate alert, and so do we (cap.dynamic_eval*).
	// ponytail: module imports plus process.binding only. `debugger`
	// statements and Reflect.* are left out — the first is a keyword the
	// coffee-script lexer ships as a string, the second is in every Babel and
	// TypeScript class helper. Add them only with an FP measurement.
	debugAccessRules.ByLang[LangJS] = compilePatterns([][2]string{
		{`\brequire\s*\(\s*["'](?:node:)?(?:vm|inspector|inspector/promises|v8)["']\s*\)`, "require(vm|inspector|v8)"},
		{`\bfrom\s+["'](?:node:)?(?:vm|inspector|inspector/promises|v8)["']`, "import vm|inspector|v8"},
		{`\bimport\s*\(\s*["'](?:node:)?(?:vm|inspector|inspector/promises|v8)["']\s*\)`, "import(vm|inspector|v8)"},
		{`\bprocess\.(?:binding|_linkedBinding)\s*\(`, "process.binding"},
	})

	// --- Telemetry -------------------------------------------------------
	//
	// Socket: "This package contains telemetry which tracks how it is used."
	// We claim less: the package names a telemetry endpoint or reads a
	// telemetry switch. Two shapes, both language-agnostic:
	//
	//  - an environment read whose variable name contains TELEMETRY, or is
	//    DO_NOT_TRACK. Packages that phone home ship the opt-out next to it:
	//    dagster's `os.getenv("DAGSTER_TELEMETRY_URL", ...)`, next.js's
	//    `process.env.NEXT_TELEMETRY_DISABLED`.
	//  - a URL whose host starts with a `telemetry.` label
	//    (http://telemetry.dagster.io/actions), or Scarf, the npm
	//    install-analytics service.
	//
	// Bare TELEMETRY identifiers are deliberately NOT matched: OpenTelemetry's
	// semantic-convention constants (ATTR_TELEMETRY_SDK_NAME) would fire on
	// every package that bundles an OTel SDK, which instruments the host
	// application rather than reporting on itself.
	const envRead = `(?:process\.env(?:\.|\[\s*["'])|environ(?:\.get)?\s*[\(\[]\s*["']|getenv\s*\(\s*["']|Getenv\s*\(\s*"|env::var\s*\(\s*"|ENV\s*\[\s*["']|GetEnvironmentVariable\s*\(\s*")`
	telemetryEnv := envRead + `[A-Z0-9_]*(?:TELEMETRY|DO_NOT_TRACK)[A-Z0-9_]*`
	telemetryHost := `https?://(?:telemetry\.[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}|(?:[a-z0-9-]+\.)*scarf\.sh)\b`
	for _, lang := range []Language{LangJS, LangPython, LangRuby, LangGo, LangRust, LangPHP, LangJava, LangCSharp} {
		telemetryRules.ByLang[lang] = compilePatterns([][2]string{
			{telemetryEnv, "telemetry env switch"},
			{telemetryHost, "telemetry endpoint"},
		})
	}

	finalizeRules(&debugAccessRules, &telemetryRules)
}

// ScanDebugAccess looks for the node debug/introspection modules (vm,
// inspector, v8) and internal-binding access. JavaScript only.
func ScanDebugAccess(files map[string][]byte) Result { return runRules(files, &debugAccessRules) }

// ScanTelemetry looks for a telemetry endpoint or telemetry switch.
func ScanTelemetry(files map[string][]byte) Result { return runRules(files, &telemetryRules) }

package codesmell

import "testing"

// Every positive case goes through ScanDebugAccess / ScanTelemetry, so through
// runRules and its anchor prefilter, not just the regex. There is at least one
// case per pattern BRANCH (require, import-from, dynamic import, binding; each
// env-read form; each host form), because a prefilter anchor taken from inside
// one branch skips files that match through another.
//
// The positive lines are copied from the published bytes of packages
// socket.dev raised the alert on in corpus v1 (docs/socket-comparison-2026-09-15-corpus-v1).
// The negative lines are the near misses each pattern was shaped to avoid.

func TestScanDebugAccess(t *testing.T) {
	for _, tc := range []struct {
		name, file, body string
		want             bool
	}{
		{"vm2 3.11.0 lib/script.js", "lib/script.js", "const {Script} = require('vm');\n", true},
		{"ys-coffee 1.7.2 coffee-script.js", "lib/coffee-script/coffee-script.js", "  vm = require('vm');\n", true},
		{"seekcode 0.4.4 dist chunk", "dist/chunk-6U42R724.js", "import { createRequire } from \"module\";\nimport vm from \"vm\";\n", true},
		{"node: specifier, inspector", "src/a.mjs", "import { Session } from 'node:inspector/promises'\n", true},
		{"v8 heap snapshot", "src/a.js", "const v8 = require(\"v8\")\n", true},
		{"internal binding", "lib/builtin.js", "const b = process.binding('natives');\n", true},
		{"dynamic import", "src/lazy.mjs", "const vm = await import('node:vm');\n", true},

		{"v8-compile-cache is a package, not the module", "index.js", "require('v8-compile-cache');\n", false},
		{"vm2 is a package, not the module", "index.js", "const { NodeVM } = require('vm2');\n", false},
		{"coffee-script lexer keyword list", "lib/coffee-script/lexer.js", "JS_KEYWORDS = ['true', 'false', 'debugger', 'yield'];\n", false},
		{"Babel class helper", "lib/helpers.js", "return Reflect.construct(Super, arguments, NewTarget);\n", false},
		{"not JavaScript", "setup.py", "import vm\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ScanDebugAccess(map[string][]byte{tc.file: []byte(tc.body)})
			if got.Fired != tc.want {
				t.Errorf("ScanDebugAccess(%q) fired=%v, want %v (matches %+v)", tc.body, got.Fired, tc.want, got.Matches)
			}
		})
	}
}

func TestScanTelemetry(t *testing.T) {
	for _, tc := range []struct {
		name, file, body string
		want             bool
	}{
		// dagster 1.10.16 dagster/_core/telemetry_upload.py, line 12 verbatim.
		{"dagster upload endpoint", "dagster/_core/telemetry_upload.py",
			`    return os.getenv("DAGSTER_TELEMETRY_URL", default="http://telemetry.dagster.io/actions")` + "\n", true},
		{"next.js opt-out", "dist/telemetry/storage.js", "this.NEXT_TELEMETRY_DISABLED = !!process.env.NEXT_TELEMETRY_DISABLED;\n", true},
		{"huggingface_hub opt-out", "huggingface_hub/constants.py", `HF_HUB_DISABLE_TELEMETRY = _is_true(os.environ.get("HF_HUB_DISABLE_TELEMETRY"))` + "\n", true},
		{"DO_NOT_TRACK in Go", "internal/track.go", "if os.Getenv(\"DO_NOT_TRACK\") != \"\" {\n", true},
		{"Rust env::var", "src/telemetry.rs", "if std::env::var(\"CARGO_TOOL_TELEMETRY_OPT_OUT\").is_ok() {\n", true},
		{"Ruby ENV[]", "lib/gem/usage.rb", "return if ENV['GEMTOOL_DISABLE_TELEMETRY']\n", true},
		{"Java System.getenv", "src/main/java/Usage.java", "String off = System.getenv(\"APP_TELEMETRY_DISABLED\");\n", true},
		{"C# GetEnvironmentVariable", "src/Usage.cs", "var off = Environment.GetEnvironmentVariable(\"DOTNET_CLI_TELEMETRY_OPTOUT\");\n", true},
		{"PHP getenv", "src/Usage.php", "if (getenv('COMPOSER_TOOL_TELEMETRY') === '0') {\n", true},
		{"process.env bracket form", "lib/t.js", "if (process.env['GATSBY_TELEMETRY_DISABLED']) return\n", true},
		{"bare telemetry host", "lib/report.js", "fetch('https://telemetry.example-cli.dev/v1/event', opts)\n", true},
		{"Scarf install analytics", "report.js", "https.get('https://static.scarf.sh/a.png?x-pxid=1')\n", true},

		{"OpenTelemetry semconv constant", "build/semconv.js", "export const ATTR_TELEMETRY_SDK_NAME = 'telemetry.sdk.name';\n", false},
		{"OTel env var", "sdk/env.js", "if (process.env.OTEL_SDK_DISABLED) return;\n", false},
		{"opentelemetry docs link", "README.js", "// see https://opentelemetry.io/docs/\nconst u = 'https://opentelemetry.io/docs/';\n", false},
		{"telemetry in a path, not a host", "src/docs.ts", "const u = 'https://docs.example.com/telemetry';\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ScanTelemetry(map[string][]byte{tc.file: []byte(tc.body)})
			if got.Fired != tc.want {
				t.Errorf("ScanTelemetry(%q) fired=%v, want %v (matches %+v)", tc.body, got.Fired, tc.want, got.Matches)
			}
		})
	}
}

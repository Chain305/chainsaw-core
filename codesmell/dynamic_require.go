package codesmell

// DynamicRequire is socket.dev's dynamicRequire alert: require() called with
// something other than a string literal, so the module loaded is decided at
// run time. JavaScript, and Python's __import__ / importlib.import_module.
// It feeds the weight-0 cap.dynamic_require.
//
// It is NOT eval: Socket reports eval/Function as usesEval, a separate
// alert, and so do we (cap.dynamic_eval*). Python's dynamic imports used to
// count as eval (cap.dynamic_eval, -3) until 2026-10-10.

var dynamicRequireRules signalRules

func init() {
	dynamicRequireRules.ByLang[LangJS] = compilePatterns([][2]string{
		// require(name), require(path.join(...)), require(cfg.plugin): the
		// argument starts with something that is not a quote or a template.
		// `\b(?:__)?` takes esbuild's __require(x) and node's require(x),
		// but not __webpack_require__(42), _require(x) or createRequire(.
		{`\b(?:__)?require\s*\(\s*[A-Za-z_$][\w$.]*\s*[,)(+\[]`, "require(identifier)"},
		// require('./locale/' + lang): a literal glued to an expression.
		{`\b(?:__)?require\s*\(\s*['"][^'"\n]*['"]\s*\+`, "require(literal + expr)"},
		// require(`./${name}`): a template with a substitution.
		{"\\b(?:__)?require\\s*\\(\\s*`[^`\\n]*\\$\\{", "require(`${}`)"},
	})
	// Python: the same three shapes for __import__(x) and import_module(x).
	// A literal name is a lazy import of a fixed module and does not count.
	dynamicRequireRules.ByLang[LangPython] = compilePatterns([][2]string{
		{`\b(?:__import__|import_module)\s*\(\s*[A-Za-z_][\w.]*\s*[,)(+\[%]`, "import(identifier)"},
		{`\b(?:__import__|import_module)\s*\(\s*[rbuRBU]?['"][^'"\n]*['"]\s*(?:[+%]|\.format\b)`, "import(literal + expr)"},
		{`\b(?:__import__|import_module)\s*\(\s*[rR]?[fF][rR]?['"][^'"\n]*\{`, "import(f-string)"},
	})
	finalizeRules(&dynamicRequireRules)
}

// ScanDynamicRequire looks for require() with a non-literal argument.
func ScanDynamicRequire(files map[string][]byte) Result { return runRules(files, &dynamicRequireRules) }

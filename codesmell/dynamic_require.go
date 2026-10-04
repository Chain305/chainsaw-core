package codesmell

// DynamicRequire is socket.dev's dynamicRequire alert: require() called with
// something other than a string literal, so the module loaded is decided at
// run time. JavaScript only. It feeds the weight-0 cap.dynamic_require.
//
// It is NOT eval: Socket reports eval/Function as usesEval, a separate
// alert, and so do we (cap.dynamic_eval*).

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
	finalizeRules(&dynamicRequireRules)
}

// ScanDynamicRequire looks for require() with a non-literal argument.
func ScanDynamicRequire(files map[string][]byte) Result { return runRules(files, &dynamicRequireRules) }

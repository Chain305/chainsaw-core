package capability

// cargo_scanner.go detects capabilities in an extracted .crate: line patterns
// over *.rs, plus file-level native markers (a `links` key in Cargo.toml,
// prebuilt libraries shipped in the crate).
//
// It keeps its own file loop instead of scanSourceTree because Rust needs two
// pieces of per-file state the shared walker has no hook for:
//   - `#[cfg(test)]` items (the idiomatic inline `mod tests { .. }`) are not
//     compiled for users. reqwest's src/tls.rs fired cap.filesystem_read from
//     one (2026-09-30).
//   - `#[wasm_bindgen] extern "C" { .. }` declares JavaScript imports, not C.
//     A file that mentions wasm_bindgen does not count its extern blocks.
//
// The build script (build.rs, or Cargo.toml's `build = "..."`) runs on the
// machine that BUILDS the crate, before any of its code is used, so its
// evidence is labelled "build script:".
//
// Decisions:
//   - Cargo-provided build metadata (env!("CARGO_PKG_VERSION"),
//     env::var("OUT_DIR") in a build script) is not environment access: cargo
//     sets those names for every crate. Any other env!/option_env! reads the
//     build machine's environment and counts.
//   - `Command::new` alone is not shell: clap's Command::new("app") is the
//     commonest spelling in the ecosystem. Shell needs `process::Command`, which
//     covers std::process, tokio::process and `use std::process::{Command, ..}`.
//   - Native code is an FFI block (`extern "C" { .. }`), #[link], a C build
//     (cc/cmake/bindgen/pkg-config), `links =` or a shipped library. An
//     `extern "C" fn` definition is a callback with a C ABI, not a call into C.
//   - Dynamic eval is runtime library loading: libloading or libc::dlopen.

import (
	"bufio"
	"bytes"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

func init() {
	registerScanner(scanCargo, "cargo", "crates")
}

// cargoProvidedEnv names what cargo sets for every build; reading one is not
// reading the user's environment.
const cargoProvidedEnv = `"(?:CARGO\w*|OUT_DIR|TARGET|HOST|PROFILE|OPT_LEVEL|DEBUG|NUM_JOBS|RUSTC\w*|RUSTDOC\w*|DEP_\w+)"`

var cargoPatterns = []linePattern{
	pat(CapShell, `\bprocess::(?:Command\b|\{[^}]*\bCommand\b)|\blibc::(?:system|execv\w*|execl\w*|fork|posix_spawnp?)\s*\(`),
	pat(CapNetwork, `\b(?:TcpStream|TcpListener|UdpSocket)\b|\b(?:reqwest|hyper|ureq|isahc|surf|attohttpc|curl|tungstenite|tokio_tungstenite)::`),
	{
		cap:    CapEnvAccess,
		re:     regexp.MustCompile(`\benv::(?:vars?(?:_os)?|set_var|remove_var)\b|\b(?:option_)?env!\s*\(`),
		ignore: regexp.MustCompile(`\benv::var(?:_os)?\s*\(\s*` + cargoProvidedEnv + `\s*\)|\b(?:option_)?env!\s*\(\s*` + cargoProvidedEnv + `\s*\)`),
	},
	pat(CapFilesystemWrite, `\bfs::(?:write|remove_file|remove_dir|remove_dir_all|create_dir|create_dir_all|rename|copy|hard_link|set_permissions)\s*\(|\bFile::create(?:_new)?\s*\(`),
	pat(CapFilesystemRead, `\bfs::(?:read|read_to_string|read_dir|read_link)\s*\(|\bFile::open\s*\(`),
	pat(CapDynamicEval, `\blibloading::|\blibc::dlopen\b`),
	pat(CapNativeCode, `#\[link\s*\(|\bcc::Build\b|\bcmake::(?:Config|build)\b|\bbindgen::|\bpkg_config::`),
}

var (
	// cargoFFIBlock is a foreign block; counted only outside wasm_bindgen files.
	cargoFFIBlock = regexp.MustCompile(`\bextern\s+(?:"(?:C|system|C-unwind)"\s*)?\{`)
	cargoWasm     = regexp.MustCompile(`\bwasm_bindgen\b`)
	cargoCfgTest  = regexp.MustCompile(`#\[cfg\((?:all\()?test\b[^\]]*\]`)
	// cargoBraceNoise is what must not count as a brace: strings, char
	// literals and trailing or inline comments.
	cargoBraceNoise = regexp.MustCompile(`"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)'|/\*.*?\*/|//.*`)
	cargoLinksKey   = regexp.MustCompile(`^\s*links\s*=\s*"`)
	cargoBuildKey   = regexp.MustCompile(`^\s*build\s*=\s*(?:"([^"]+)"|false)`)
)

// cargoPrebuiltExts are compiled libraries a crate can ship and link.
var cargoPrebuiltExts = map[string]bool{".a": true, ".lib": true, ".so": true, ".dylib": true, ".dll": true, ".o": true, ".obj": true}

func scanCargo(pkgDir string) (map[Capability][]Evidence, map[Capability]int, error) {
	if _, err := os.Stat(pkgDir); err != nil {
		return nil, nil, err
	}
	caps := map[Capability][]Evidence{}
	counts := map[Capability]int{}
	build := cargoManifest(pkgDir, caps, counts)
	isBuild := func(rel string) bool {
		if build == "" {
			return false
		}
		dir := path.Dir(build)
		return rel == build || (dir != "." && strings.HasPrefix(rel, dir+"/"))
	}
	err := filepath.WalkDir(pkgDir, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			if p != pkgDir && commonSkipDirs[strings.ToLower(d.Name())] {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(pkgDir, p)
		rel = filepath.ToSlash(rel)
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if cargoPrebuiltExts[ext] {
			counts[CapNativeCode]++
			addNPMEvidence(caps, CapNativeCode, Evidence{File: rel, Snippet: "prebuilt native library shipped in the crate"})
			return nil
		}
		if ext != ".rs" {
			return nil
		}
		if info, err := d.Info(); err != nil || info.Size() > MaxFileScanBytes {
			if err == nil {
				addNPMEvidence(caps, CapMinifiedOrBundled, Evidence{File: rel, Snippet: "file exceeds 5 MB — not scanned"})
			}
			return nil
		}
		scanCargoFile(rel, p, isBuild(rel), caps, counts)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	if len(caps) == 0 {
		return nil, nil, nil
	}
	return caps, counts, nil
}

// cargoManifest records `links =` and returns the build script's path relative
// to the crate root ("" when the crate has none).
func cargoManifest(pkgDir string, caps map[Capability][]Evidence, counts map[Capability]int) string {
	build := "build.rs"
	if _, err := os.Stat(filepath.Join(pkgDir, build)); err != nil {
		build = ""
	}
	f, err := os.Open(filepath.Join(pkgDir, "Cargo.toml"))
	if err != nil {
		return build
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		n++
		line := sc.Text()
		if cargoLinksKey.MatchString(line) {
			counts[CapNativeCode]++
			addNPMEvidence(caps, CapNativeCode, Evidence{File: "Cargo.toml", Line: n, Snippet: truncateBytes([]byte(strings.TrimSpace(line)), MaxSnippetLen)})
		}
		if m := cargoBuildKey.FindStringSubmatch(line); m != nil {
			build = path.Clean(filepath.ToSlash(m[1])) // `build = false` gives "."
			if m[1] == "" {
				build = ""
			}
		}
	}
	return build
}

// ponytail: brace counting over string-stripped lines, not a Rust lexer. A
// multi-line raw string inside a #[cfg(test)] item can end the skip early (a
// false positive) or extend it to end of file (a miss, and only for code
// already placed after test code). Upgrade only with a real parser.
func scanCargoFile(rel, abs string, isBuild bool, caps map[Capability][]Evidence, counts map[Capability]int) {
	f, err := os.Open(abs)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), MaxFileScanBytes+1)
	snippet := func(line []byte) string {
		s := bytes.TrimSpace(line)
		if isBuild {
			s = append([]byte("build script: "), s...)
		}
		return truncateBytes(s, MaxSnippetLen)
	}
	var ffi []Evidence
	wasm := false
	inBlock := false
	skipping, opened, depth := false, false, 0
	n := 0
	for sc.Scan() {
		n++
		line := sc.Bytes()
		code, still := stripCommentLine(line, inBlock, cComments)
		inBlock = still
		if len(bytes.TrimSpace(code)) == 0 {
			continue
		}
		if cargoWasm.Match(code) {
			wasm = true
		}
		if !skipping {
			loc := cargoCfgTest.FindIndex(code)
			if loc == nil {
				cargoMatchLine(code, line, rel, n, snippet, caps, counts, &ffi)
				continue
			}
			skipping, opened, depth = true, false, 0
			code = code[loc[1]:]
		}
		// Inside a #[cfg(test)] item: it ends at `;` before any brace, or when
		// its first brace closes.
		for _, ch := range cargoBraceNoise.ReplaceAll(code, nil) {
			switch {
			case ch == '{':
				depth++
				opened = true
			case ch == '}':
				depth--
			case ch == ';' && !opened:
				skipping = false
			}
			if opened && depth <= 0 {
				skipping = false
			}
			if !skipping {
				break
			}
		}
	}
	if err := sc.Err(); err != nil {
		addNPMEvidence(caps, CapMinifiedOrBundled, Evidence{File: rel, Line: n, Snippet: "scan stopped: " + err.Error()})
	}
	if !wasm {
		for _, ev := range ffi {
			counts[CapNativeCode]++
			addNPMEvidence(caps, CapNativeCode, ev)
		}
	}
}

func cargoMatchLine(code, line []byte, rel string, n int, snippet func([]byte) string, caps map[Capability][]Evidence, counts map[Capability]int, ffi *[]Evidence) {
	for _, pt := range cargoPatterns {
		target := code
		if pt.ignore != nil {
			target = pt.ignore.ReplaceAll(code, nil)
		}
		if pt.re.Match(target) {
			counts[pt.cap]++
			addNPMEvidence(caps, pt.cap, Evidence{File: rel, Line: n, Snippet: snippet(line)})
		}
	}
	if cargoFFIBlock.Match(code) {
		*ffi = append(*ffi, Evidence{File: rel, Line: n, Snippet: snippet(line)})
	}
}

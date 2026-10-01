package capability

// golang_scanner.go detects capabilities in a Go module zip. Go ships its own
// parser in the standard library, so this scanner reads the AST instead of
// matching lines: comments, string literals (code-generator templates) and a
// local variable that shadows a package name can never fire, and an import
// alias (`x "os/exec"`) is resolved rather than guessed.
//
// Decisions, mirroring socket.dev's concept meanings where they are defensible:
//   - unsafe, reflect and raw syscall.Syscall map to NOTHING. None of them is a
//     capability we have a constant for; socket.dev reports unsafe under a
//     separate "unsafe" capability. Socket's Go usesEval hits come mostly from
//     JS/PHP files shipped inside Go module zips (WordPress, pyright,
//     code-server in the 2026-09 corpus); this scanner reads only .go files.
//   - Go has no eval. plugin (load a .so and run its init) is the one way to run
//     code chosen at runtime, so it is cap.dynamic_eval.
//   - Native code is cgo (`import "C"`) and prebuilt .syso objects. Go assembly
//     (.s) is not: it is built by the Go toolchain from reviewed source and is
//     pervasive in golang.org/x/crypto.
//   - Network is keyed on the APIs that open connections or listeners, not on
//     the import: `net` is imported for net.IP parsing and `net/http` for
//     status codes and in-memory handler tests (testify) far more often than
//     for I/O.

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

func init() {
	registerScanner(scanGo, "go", "gomod", "golang")
}

// goImportCaps are packages whose import alone is the capability. Go refuses to
// compile an unused import, so an import is a use.
var goImportCaps = map[string]Capability{
	"os/exec":                      CapShell,
	"plugin":                       CapDynamicEval,
	"C":                            CapNativeCode,
	"net/rpc":                      CapNetwork,
	"net/rpc/jsonrpc":              CapNetwork,
	"net/smtp":                     CapNetwork,
	"google.golang.org/grpc":       CapNetwork,
	"golang.org/x/net/websocket":   CapNetwork,
	"github.com/gorilla/websocket": CapNetwork,
}

// goAPICaps maps an import path to the package members that are the
// capability. Anything not listed (types, constants, parsers) is not.
var goAPICaps = map[string]map[string]Capability{
	"os": goMerge(
		goNames(CapEnvAccess, "Getenv", "LookupEnv", "Environ", "ExpandEnv", "Setenv", "Unsetenv", "Clearenv"),
		goNames(CapFilesystemWrite, "WriteFile", "Create", "CreateTemp", "Mkdir", "MkdirAll", "MkdirTemp",
			"Remove", "RemoveAll", "Rename", "Chmod", "Chown", "Lchown", "Truncate", "Symlink", "Link"),
		goNames(CapFilesystemRead, "ReadFile", "Open", "ReadDir", "DirFS", "Readlink"),
		goNames(CapShell, "StartProcess"),
	),
	"io/ioutil": goMerge(
		goNames(CapFilesystemWrite, "WriteFile", "TempFile", "TempDir"),
		goNames(CapFilesystemRead, "ReadFile", "ReadDir"),
	),
	"syscall": goMerge(
		goNames(CapShell, "Exec", "ForkExec", "StartProcess"),
		goNames(CapEnvAccess, "Getenv", "Environ", "Setenv"),
	),
	"golang.org/x/sys/unix": goNames(CapShell, "Exec"),
	"net": goNames(CapNetwork, "Dial", "DialTimeout", "DialTCP", "DialUDP", "DialIP", "DialUnix",
		"Listen", "ListenPacket", "ListenTCP", "ListenUDP", "ListenIP", "ListenUnix", "ListenUnixgram",
		"ListenMulticastUDP", "Dialer", "ListenConfig", "Resolver", "DefaultResolver",
		"LookupHost", "LookupIP", "LookupAddr", "LookupCNAME", "LookupMX", "LookupNS", "LookupTXT", "LookupSRV", "LookupPort"),
	"net/http": goNames(CapNetwork, "Get", "Head", "Post", "PostForm", "Client", "DefaultClient",
		"Transport", "DefaultTransport", "ListenAndServe", "ListenAndServeTLS", "Serve", "ServeTLS", "Server"),
	"net/http/httputil": goNames(CapNetwork, "ReverseProxy", "NewSingleHostReverseProxy"),
	"crypto/tls":        goNames(CapNetwork, "Dial", "DialWithDialer", "Listen", "Dialer"),
}

// goOpenFileWriteFlag marks an os.OpenFile call that can write.
var goOpenFileWriteFlag = regexp.MustCompile(`O_WRONLY|O_RDWR|O_CREATE|O_APPEND|O_TRUNC`)

// goBuildIgnore is the constraint carried by `go run`/`go generate` programs
// and tools.go dependency pins; a normal build never compiles the file.
var goBuildIgnore = regexp.MustCompile(`^//(?:go:build| \+build)\s+(?:ignore|generate|tools)(?:\s|$)`)

// goSkipDir reports directories whose code does not run for a module's users:
// the shared test/example/vendor set, what the go tool itself ignores (_ and .
// prefixes), and test-helper packages (internal/testenv, acmetest, testutil).
func goSkipDir(name string) bool {
	lower := strings.ToLower(name)
	return commonSkipDirs[lower] || strings.HasPrefix(name, "_") || strings.HasPrefix(name, ".") ||
		lower == "testenv" || strings.HasPrefix(lower, "testutil") ||
		(len(lower) > 4 && strings.HasSuffix(lower, "test") && lower != "latest")
}

func goNames(c Capability, ns ...string) map[string]Capability {
	m := make(map[string]Capability, len(ns))
	for _, n := range ns {
		m[n] = c
	}
	return m
}

func goMerge(ms ...map[string]Capability) map[string]Capability {
	out := map[string]Capability{}
	for _, m := range ms {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

func scanGo(pkgDir string) (map[Capability][]Evidence, map[Capability]int, error) {
	if _, err := os.Stat(pkgDir); err != nil {
		return nil, nil, err
	}
	caps := map[Capability][]Evidence{}
	counts := map[Capability]int{}
	err := filepath.WalkDir(pkgDir, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			if p != pkgDir && goSkipDir(name) {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(pkgDir, p)
		rel = filepath.ToSlash(rel)
		if strings.HasPrefix(name, "_") || strings.HasPrefix(name, ".") {
			return nil
		}
		if strings.EqualFold(filepath.Ext(name), ".syso") {
			counts[CapNativeCode]++
			addNPMEvidence(caps, CapNativeCode, Evidence{File: rel, Snippet: ".syso prebuilt object linked into the binary"})
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		if info, err := d.Info(); err != nil || info.Size() > MaxFileScanBytes {
			if err == nil {
				addNPMEvidence(caps, CapMinifiedOrBundled, Evidence{File: rel, Snippet: "file exceeds 5 MB — not scanned"})
			}
			return nil
		}
		src, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		scanGoFile(rel, src, caps, counts)
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

func scanGoFile(rel string, src []byte, caps map[Capability][]Evidence, counts map[Capability]int) {
	fset := token.NewFileSet()
	f, _ := parser.ParseFile(fset, rel, src, parser.ParseComments)
	if f == nil {
		return
	}
	for _, cg := range f.Comments {
		if cg.Pos() > f.Package {
			break
		}
		for _, c := range cg.List {
			if goBuildIgnore.MatchString(c.Text) {
				return
			}
		}
	}
	lines := bytes.Split(src, []byte("\n"))
	seen := map[Capability]map[int]bool{}
	hit := func(c Capability, pos token.Pos) {
		line := fset.Position(pos).Line
		if seen[c] == nil {
			seen[c] = map[int]bool{}
		}
		if seen[c][line] {
			return
		}
		seen[c][line] = true
		counts[c]++
		snippet := ""
		if line > 0 && line <= len(lines) {
			snippet = truncateBytes(bytes.TrimSpace(lines[line-1]), MaxSnippetLen)
		}
		addNPMEvidence(caps, c, Evidence{File: rel, Line: line, Snippet: snippet})
	}

	// local package name -> import path
	local := map[string]string{}
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		if c, ok := goImportCaps[path]; ok {
			hit(c, imp.Pos())
		}
		name := path[strings.LastIndex(path, "/")+1:]
		if imp.Name != nil {
			name = imp.Name.Name
		}
		if name != "_" && name != "." {
			local[name] = path
		}
	}

	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CallExpr:
			// os.OpenFile writes only with a write flag; otherwise it is a read.
			if path, sel := goPkgSelector(n.Fun, local); path == "os" && sel == "OpenFile" && len(n.Args) >= 2 {
				flag := src[fset.Position(n.Args[1].Pos()).Offset:fset.Position(n.Args[1].End()).Offset]
				if goOpenFileWriteFlag.Match(flag) {
					hit(CapFilesystemWrite, n.Pos())
				} else {
					hit(CapFilesystemRead, n.Pos())
				}
			}
		case *ast.SelectorExpr:
			if path, sel := goPkgSelector(n, local); path != "" {
				if c, ok := goAPICaps[path][sel]; ok {
					hit(c, n.Pos())
				}
			}
		}
		return true
	})
}

// goPkgSelector returns the import path and member name when e is `pkg.Name`
// with pkg an imported package, not a local that shadows it.
func goPkgSelector(e ast.Expr, local map[string]string) (string, string) {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return "", ""
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok || id.Obj != nil {
		return "", ""
	}
	return local[id.Name], sel.Sel.Name
}

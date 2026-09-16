// Scan extracted package directories with chainsaw-core's own detectors.
// Static analysis only: files are READ, never executed.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/chain305/chainsaw-core/capability"
	"github.com/chain305/chainsaw-core/codesmell"
	"github.com/chain305/chainsaw-core/installscripts"
)

type out struct {
	Dir            string   `json:"dir"`
	Eco            string   `json:"eco"`
	Files          int      `json:"files"`
	Eval           bool     `json:"eval"`
	Network        bool     `json:"network"`
	Shell          bool     `json:"shell"`
	FS             bool     `json:"fs"`
	Env            bool     `json:"env"`
	URLs           bool     `json:"urls"`
	Entropy        bool     `json:"entropy"`
	Minified       bool     `json:"minified"`
	Native         bool     `json:"native"`
	Caps           []string `json:"caps"`
	Install        bool     `json:"install"`
	InstallRemote  bool     `json:"installRemote"`
	InstallEvalEnc bool     `json:"installEvalEnc"`
	InstallKind    string   `json:"installKind,omitempty"`
	Err            string   `json:"err,omitempty"`
}

func load(dir string) (map[string][]byte, error) {
	files := map[string][]byte{}
	err := filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() || fi.Size() > 4<<20 {
			return nil
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		files[rel] = b
		return nil
	})
	return files, err
}

// findFile returns the first file whose base name matches, at any depth.
func findFile(files map[string][]byte, base string) ([]byte, bool) {
	for name, b := range files {
		if filepath.Base(name) == base {
			return b, true
		}
	}
	return nil, false
}

func main() {
	eco := os.Args[1]
	enc := json.NewEncoder(os.Stdout)
	for _, dir := range os.Args[2:] {
		o := out{Dir: dir, Eco: eco}
		files, err := load(dir)
		if err != nil {
			o.Err = err.Error()
			_ = enc.Encode(o)
			continue
		}
		o.Files = len(files)
		f := codesmell.FilterTestVendorGenerated(files)
		o.Eval = codesmell.ScanEval(f).Fired
		o.Network = codesmell.ScanNetwork(f).Fired
		o.Shell = codesmell.ScanShell(f).Fired
		o.FS = codesmell.ScanFilesystem(f).Fired
		o.Env = codesmell.ScanEnvVars(f).Fired
		o.URLs = codesmell.ScanURLs(f).Fired
		o.Entropy = codesmell.ScanEntropy(f).Fired
		o.Minified = codesmell.ScanMinified(f).Fired
		o.Native = codesmell.ScanNativeBinary(files).Fired
		// Install scripts: the detector my first comparison omitted. It is a
		// separate provider from codesmell and catches a class codesmell
		// cannot see -- a package.json "preinstall" hook is configuration,
		// not source code.
		var ir installscripts.Result
		switch eco {
		case "npm":
			if b, ok := findFile(files, "package.json"); ok {
				ir = installscripts.NPMAST(b)
			}
		case "pypi", "pip":
			sp, _ := findFile(files, "setup.py")
			pt, _ := findFile(files, "pyproject.toml")
			if sp != nil || pt != nil {
				ir = installscripts.PipAST(sp, pt)
			}
		}
		o.Install = ir.HasInstallScript
		o.InstallRemote = ir.InstallScriptFetchesRemote
		o.InstallEvalEnc = ir.EvalEncoded
		o.InstallKind = string(ir.Kind)

		if rep, cerr := capability.Analyze(dir, eco); cerr == nil && rep != nil && !rep.Unsupported {
			for c := range rep.Capabilities {
				o.Caps = append(o.Caps, string(c))
			}
			sort.Strings(o.Caps)
		}
		_ = enc.Encode(o)
	}
	_ = fmt.Sprint()
	_ = strings.TrimSpace("")
}

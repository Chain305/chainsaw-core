//go:build corpus

package cli

// Guard/server parity for the Python formats on the lockfile corpus
// (scripts/lockfile-corpus, docs/PLANS_INTELLIGENCE.md#plan-non-registry-
// sources §4 "the guard and the server produce the same (name, version,
// class) set or the differences are listed"). The server reads a file with
// core/depparser's analyzer (internal/scan ParseLockfile); the guard with
// parsePythonLock (lockfiles) or readPipFile + applyRegistryFlags
// (requirements). Classes: public, registry-other, non-registry, local.
//
//	CORPUS_DIR=… go test -tags corpus ./cli/ -run TestPythonGuardServerParity -v
//
// Known, deliberate differences are not counted as failures but printed:
// the server leaves dev packages out (the analyzer's Dev filter), the guard
// sweeps them (`poetry install` installs them).

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	depanalyzer "github.com/chain305/chainsaw-core/depparser/analyzer"
	"github.com/chain305/chainsaw-core/depparser/origin"
	"github.com/chain305/chainsaw-core/depparser/parser/python"
	"github.com/chain305/chainsaw-core/depparser/parser/python/poetry"
)

func parityClass(src string, local bool) string {
	switch {
	case local || strings.HasPrefix(src, localOriginPrefix):
		return "local"
	case src == "":
		return "public"
	case origin.Classify("pypi", src) == origin.RegistryOther:
		return "registry-other"
	}
	return "non-registry"
}

func TestPythonGuardServerParity(t *testing.T) {
	dir := os.Getenv("CORPUS_DIR")
	if dir == "" {
		t.Fatal("DID NOT RUN: CORPUS_DIR unset")
	}
	withMirrors(t)
	f, err := os.Open("../../scripts/lockfile-corpus/manifest.tsv")
	if err != nil {
		t.Fatalf("DID NOT RUN: %v", err)
	}
	defer f.Close()
	files := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		c := strings.Split(sc.Text(), "\t")
		if len(c) < 2 || strings.HasPrefix(c[0], "#") {
			continue
		}
		id, format := c[0], c[1]
		if format != "poetry" && format != "uv" && format != "requirements" {
			continue
		}
		path := filepath.Join(dir, id)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("DID NOT RUN: %v", err)
		}
		files++
		key := func(name, version, class string) string {
			return python.NormalizePkgName(name, true) + "@" + version + " " + class
		}

		server := map[string]bool{}
		pkgs, err := depanalyzer.ParseBytes(context.Background(), filepath.Base(path), data)
		if err != nil {
			t.Fatalf("%s: server parse: %v", id, err)
		}
		for _, p := range pkgs {
			server[key(p.Name, p.Version, parityClass(p.Origin, false))] = true
		}

		guard := map[string]bool{}
		dev := map[string]bool{}
		if format == "requirements" {
			specs, flags := readPipFile(path, true, map[string]bool{})
			applyRegistryFlags("pip", nil, specs, flags)
			for _, s := range specs {
				if s.Name != "" {
					guard[key(s.Name, s.Version, parityClass(s.Origin, s.Local))] = true
				}
			}
		} else {
			reg, nonReg, local, err := parsePythonLock(filepath.Base(path), data)
			if err != nil {
				t.Fatalf("%s: guard parse: %v", id, err)
			}
			for _, c := range reg {
				guard[key(c.Name, c.Version, "public")] = true
			}
			for _, d := range nonReg {
				guard[key(d.Name, d.Version, parityClass(d.Origin, false))] = true
			}
			for _, c := range local {
				guard[key(c.Name, c.Version, "local")] = true
			}
			// The guard sweeps dev packages; the server does not. Dev is
			// read off the parser itself, so a guard-only key that is NOT a
			// dev package still counts as a difference.
			if format == "poetry" {
				all, _, err := poetry.NewParser().Parse(context.Background(), bytes.NewReader(data))
				if err != nil {
					t.Fatalf("%s: %v", id, err)
				}
				for _, p := range all {
					if p.Dev {
						dev[key(p.Name, p.Version, parityClass(p.Origin, false))] = true
					}
				}
			}
		}
		var onlyServer, onlyGuard []string
		for k := range server {
			if !guard[k] {
				onlyServer = append(onlyServer, k)
			}
		}
		for k := range guard {
			if !server[k] && !dev[k] {
				onlyGuard = append(onlyGuard, k)
			}
		}
		sort.Strings(onlyServer)
		sort.Strings(onlyGuard)
		t.Logf("%-50s server %4d guard %4d (dev/guard-only %d) | differ: server-only %v guard-only %v",
			id, len(server), len(guard), len(dev), onlyServer, onlyGuard)
		if len(onlyServer)+len(onlyGuard) > 0 {
			t.Errorf("%s: guard and server disagree", id)
		}
	}
	if files == 0 {
		t.Fatal("DID NOT RUN: no Python corpus rows")
	}
}

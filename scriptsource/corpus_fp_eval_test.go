package scriptsource

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// TestCorpusFalsePositives runs ScanPHP and ScanRuby over every package
// directory in CHAINSAW_SCRIPTSOURCE_CORPUS (an os.PathListSeparator list,
// e.g. each vendor/<vendor>/<package> of a Composer install and each entry of
// a gems/ directory) and lists each package either flags. A benign corpus
// should flag none; the run that set these rules is in the v0.22.106
// CHANGELOG entry. Planted droppers are scanned in the same run so a green
// result cannot come from rules that fire on nothing. Skips when unset.
func TestCorpusFalsePositives(t *testing.T) {
	list := os.Getenv("CHAINSAW_SCRIPTSOURCE_CORPUS")
	if list == "" {
		t.Skip("CHAINSAW_SCRIPTSOURCE_CORPUS not set")
	}
	var hits []string
	scanned, php, rb := 0, 0, 0
	for _, dir := range filepath.SplitList(list) {
		files := readTree(dir)
		if len(files) == 0 {
			continue
		}
		scanned++
		for name := range files {
			switch filepath.Ext(name) {
			case ".php":
				php++
			case ".rb":
				rb++
			}
		}
		for _, r := range []Result{ScanPHP(files), ScanRuby(files)} {
			if r.Detected {
				hits = append(hits, dir+" "+r.Kind+" "+r.Detail)
			}
		}
	}
	if scanned == 0 {
		t.Fatal("no readable package directory: the eval would pass having scanned nothing")
	}
	sort.Strings(hits)
	t.Logf("scanned %d packages (%d .php, %d .rb files), %d flagged", scanned, php, rb, len(hits))
	for _, h := range hits {
		t.Errorf("flagged: %s", h)
	}
	if !ScanRuby(map[string][]byte{"lib/x.rb": []byte(sleeperStage1)}).Detected ||
		!ScanPHP(map[string][]byte{"src/x.php": []byte("<?php\n$c = curl_exec($h);\neval($c);\n")}).Detected {
		t.Fatal("planted dropper not detected: the eval cannot fail")
	}
}

// readTree reads every regular file under root, keyed by its path relative
// to root.
func readTree(root string) map[string][]byte {
	out := map[string][]byte{}
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, err := d.Info(); err != nil || !info.Mode().IsRegular() || info.Size() > maxFileSize {
			return nil
		}
		if b, err := os.ReadFile(p); err == nil {
			rel, _ := filepath.Rel(root, p)
			out[filepath.ToSlash(rel)] = b
		}
		return nil
	})
	return out
}

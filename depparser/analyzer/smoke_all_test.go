package analyzer_test

// Full-ecosystem smoke: drop one representative fixture per registered
// lockfile format in /tmp/chainsaw-depparser-smoke/, run WalkDir, and
// check the expected packages come back from each. Not a correctness
// suite — just proves the registry's Required() patterns and the
// parsers' happy paths don't regress as we add more ecosystems.

import (
	"context"
	"os"
	"testing"

	depanalyzer "github.com/chain305/chainsaw-core/depparser/analyzer"
	ftypes "github.com/chain305/chainsaw-core/fanal"
)

func TestAllEcosystemSmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("requires external /tmp/chainsaw-depparser-smoke fixture")
	}

	const fixtureDir = "/tmp/chainsaw-depparser-smoke"
	if _, err := os.Stat(fixtureDir); err != nil {
		if os.IsNotExist(err) {
			t.Skip("requires external /tmp/chainsaw-depparser-smoke fixture")
		}
		t.Fatalf("stat fixture dir: %v", err)
	}

	pkgs, err := depanalyzer.WalkDir(context.Background(), fixtureDir)
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}

	// Map LangType → at least one expected (name, version).
	// We assert presence, not exhaustiveness — a parser may emit more
	// packages than listed here (e.g., npm v3 often includes transitives
	// we didn't stub) and that's fine.
	want := map[ftypes.LangType][][2]string{
		ftypes.Pipenv:    {{"requests", "2.31.0"}, {"urllib3", "2.0.7"}},
		ftypes.Uv:        {{"requests", "2.31.0"}, {"urllib3", "2.2.1"}},
		ftypes.PyLock:    {{"requests", "2.31.0"}, {"urllib3", "2.2.1"}},
		ftypes.Npm:       {{"lodash", "4.17.21"}, {"express", "4.18.2"}, {"@babel/core", "7.22.0"}},
		ftypes.Yarn:      {{"lodash", "4.17.21"}, {"@babel/core", "7.22.0"}},
		ftypes.Pnpm:      {{"lodash", "4.17.21"}, {"@babel/core", "7.22.0"}},
		ftypes.Bun:       {{"lodash", "4.17.21"}, {"@babel/core", "7.22.0"}},
		ftypes.Bundler:   {{"rails", "7.0.4"}, {"nokogiri", "1.15.0-arm64-darwin"}},
		ftypes.Composer:  {{"monolog/monolog", "3.4.0"}, {"symfony/console", "6.4.0"}},
		ftypes.Cargo:     {{"serde", "1.0.193"}, {"tokio", "1.35.0"}},
		ftypes.GoModule:  {{"github.com/stretchr/testify", "1.8.4"}, {"golang.org/x/sys", "0.15.0"}},
		ftypes.Gradle:    {{"com.fasterxml.jackson.core:jackson-databind", "2.15.2"}, {"org.springframework:spring-core", "6.0.11"}},
		ftypes.Sbt:       {{"com.typesafe.akka:akka-actor_2.13", "2.8.5"}, {"org.slf4j:slf4j-api", "2.0.9"}},
		ftypes.NuGet:     {{"Newtonsoft.Json", "13.0.3"}, {"EntityFramework", "6.4.4"}, {"log4net", "2.0.15"}},
		ftypes.Conan:     {{"zlib", "1.2.13"}, {"openssl", "3.1.2"}},
		ftypes.Hex:       {{"jason", "1.4.1"}, {"plug", "1.14.2"}},
		ftypes.Pub:       {{"http", "1.1.0"}, {"meta", "1.9.1"}},
		ftypes.Swift:     {{"alamofire", "5.8.0"}, {"swift-log", "1.5.3"}},
		ftypes.Cocoapods: {{"Alamofire", "5.6.0"}, {"SwiftyJSON", "5.0.0"}},
		ftypes.Julia:     {{"JSON", "0.21.4"}, {"HTTP", "1.10.0"}},
		ftypes.CondaEnv:  {{"python", "3.10"}, {"numpy", "1.26.0"}, {"requests", "2.31.0"}},

		// Manifest parsers — formerly hardcoded in scan.go, now
		// dispatched through the registry like every lockfile.
		// Npm carries manifest+lockfile fixtures; test proves both
		// reach this analyzer (fixtures above produce 3 lockfile
		// entries, this one adds ^4.17.21-stripped + 29.5.0 from
		// devDependencies, totalling 5 for Npm).
		ftypes.Pip: {{"requests", "2.31.0"}, {"urllib3", "2.0.7"}},
		ftypes.Pom: {{"org.springframework:spring-core", "6.1.2"}},
		// go.sum fixture already covers GoModule; go.mod adds the
		// same pair with a leading "v" that we strip. (Note: GoModule
		// here comes via the go.sum fixture; go.mod would emit "v1.8.4"
		// and "v0.15.0" without the /go.mod stripping.)
	}

	// Build (lang, name, version) → present index.
	got := map[ftypes.LangType]map[[2]string]bool{}
	for _, p := range pkgs {
		if got[p.Lang] == nil {
			got[p.Lang] = map[[2]string]bool{}
		}
		got[p.Lang][[2]string{p.Name, p.Version}] = true
	}

	for lang, pairs := range want {
		if len(got[lang]) == 0 {
			t.Errorf("lang %q: no packages parsed (parser or Required() broken)", lang)
			continue
		}
		for _, pair := range pairs {
			if !got[lang][pair] {
				t.Errorf("lang %q: missing (%s, %s); got keys: %v",
					lang, pair[0], pair[1], keysOf(got[lang]))
			}
		}
	}

	t.Logf("discovered %d packages across %d ecosystems", len(pkgs), len(got))
	for lang, m := range got {
		t.Logf("  %-20s %d pkgs", lang, len(m))
	}
}

func keysOf(m map[[2]string]bool) [][2]string {
	out := make([][2]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

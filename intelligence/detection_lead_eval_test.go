package intelligence

// detection_lead_eval_test.go — the REAL-WORLD detection-lead harness (the moat
// spike). Unlike malicious_corpus_test.go (synthetic shapes, internal-consistency
// only), this runs the OWN-BYTES detection providers against ACTUAL fetched
// package tarballs and measures:
//
//   - catch-rate on real malicious packages (own-bytes signals only — the
//     known-malicious LOOKUP path is deliberately excluded; that's the "cheat"
//     with zero time advantage over a competitor cron-ing the same feed),
//   - false-positive rate on real benign top packages (catch-rate is meaningless
//     without it — a signal that fires on everything is useless),
//   - content-coverage (how many seed entries were actually fetchable; malicious
//     versions are often unpublished — the honest bottleneck).
//
// "Caught" = a STRONG own-bytes signal fired: hidden-unicode hit, manifest
// confusion, or an install script that fetches+executes remote code. Plain
// "has install script" is NOT counted as caught (too common in benign packages).
//
// This is the measurement foundation for D-PKG″ (early-detection moat). The
// metric that matters is own-bytes-catch MINUS benign-false-positive — the real
// signal quality, before any cross-flow training. The cross-flow flywheel's job
// is to push catch up / FP down beyond this fixed-heuristic baseline.
//
// Run:
//   scripts/detection-eval/fetch-corpus.sh
//   CHAINSAW_DETECTION_EVAL_CORPUS=scripts/detection-eval/corpus \
//     go test ./core/intelligence/ -run TestDetectionLeadEval -v

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type evalSample struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Published string `json:"published"`
	Label     string `json:"label"` // malicious | benign
	File      string `json:"file"`
	Fetched   bool   `json:"fetched"`
}

// ownBytesVerdict runs the own-bytes providers on one artifact and reports
// whether a STRONG malicious signal fired, plus which ones.
func ownBytesVerdict(ctx context.Context, eco, name, ver string, tgz []byte) (caught bool, signals []string) {
	req := Request{
		Key:      Key{Ecosystem: eco, Package: name, Version: ver},
		Artifact: &ArtifactHandle{Bytes: tgz},
	}

	if pr, err := newHiddenUnicodeProvider().Run(ctx, req, nil); err == nil && pr.Scan != nil && pr.Scan.HiddenUnicodeHits > 0 {
		caught = true
		signals = append(signals, "hidden-unicode")
	}
	if pr, err := newManifestConfusionProvider().Run(ctx, req, nil); err == nil && pr.Scan != nil && pr.Scan.ManifestConfusion {
		caught = true
		signals = append(signals, "manifest-confusion")
	}
	if pr, err := newInstallScriptsProvider().Run(ctx, req, nil); err == nil && pr.Scan != nil && pr.Scan.HasInstallScript {
		// Strong only when the script fetches+executes remote code; a bare
		// install script is recorded but does not count as "caught".
		if strings.Contains(strings.ToLower(pr.Scan.InstallScriptKind), "fetch") ||
			strings.Contains(strings.ToLower(pr.Scan.InstallScriptKind), "remote") {
			caught = true
			signals = append(signals, "install-script-fetches-remote")
		} else {
			signals = append(signals, "install-script-present(weak)")
		}
	}
	return caught, signals
}

func TestDetectionLeadEval(t *testing.T) {
	dir := os.Getenv("CHAINSAW_DETECTION_EVAL_CORPUS")
	if dir == "" {
		t.Skip("set CHAINSAW_DETECTION_EVAL_CORPUS=<dir> (run scripts/detection-eval/fetch-corpus.sh first)")
	}
	f, err := os.Open(filepath.Join(dir, "manifest.jsonl"))
	if err != nil {
		t.Fatalf("open manifest: %v (run fetch-corpus.sh)", err)
	}
	defer f.Close()

	var samples []evalSample
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var s evalSample
		if json.Unmarshal([]byte(line), &s) == nil {
			samples = append(samples, s)
		}
	}

	ctx := context.Background()
	var (
		malTotal, malFetched, malCaught int
		benTotal, benFetched, benFP     int
		missSet                         []string
		fpSet                           []string
	)
	for _, s := range samples {
		isMal := s.Label == "malicious"
		if isMal {
			malTotal++
		} else {
			benTotal++
		}
		if !s.Fetched || s.File == "" {
			continue // content-unavailable: counted in total, excluded from rate
		}
		tgz, err := os.ReadFile(s.File)
		if err != nil || len(tgz) == 0 {
			continue
		}
		caught, sigs := ownBytesVerdict(ctx, s.Ecosystem, s.Name, s.Version, tgz)
		label := fmt.Sprintf("%s:%s@%s", s.Ecosystem, s.Name, s.Version)
		if isMal {
			malFetched++
			if caught {
				malCaught++
			} else {
				missSet = append(missSet, label+" "+strings.Join(sigs, ","))
			}
		} else {
			benFetched++
			if caught {
				benFP++
				fpSet = append(fpSet, label+" "+strings.Join(sigs, ","))
			}
		}
	}

	pct := func(n, d int) string {
		if d == 0 {
			return "n/a (0 fetched)"
		}
		return fmt.Sprintf("%d/%d = %.0f%%", n, d, 100*float64(n)/float64(d))
	}
	sort.Strings(missSet)
	sort.Strings(fpSet)

	t.Logf("=== DETECTION-LEAD EVAL (own-bytes only, lookup excluded) ===")
	t.Logf("malicious: catch-rate %s   (content-coverage %d/%d fetched)", pct(malCaught, malFetched), malFetched, malTotal)
	t.Logf("benign:    false-positive %s   (content-coverage %d/%d fetched)", pct(benFP, benFetched), benFetched, benTotal)
	t.Logf("net signal quality = catch%% - fp%% (the number the moat must improve via cross-flow training)")
	if len(missSet) > 0 {
		t.Logf("MISS set (own-bytes didn't catch — the cross-flow gap):\n  %s", strings.Join(missSet, "\n  "))
	}
	if len(fpSet) > 0 {
		t.Logf("FALSE-POSITIVE set (fired on benign — the FP cost):\n  %s", strings.Join(fpSet, "\n  "))
	}
	if malFetched == 0 {
		t.Logf("WARNING: 0 malicious samples fetchable — catch-rate unmeasurable. The corpus content is the bottleneck (malicious versions unpublished). Grow the seed from archived/OpenSSF sources.")
	}
}

package intelligence

// The L-02 cross-tenant counter could not answer the question it exists for.
//
// It incremented on ANY cross-org rewrite carrying a non-empty vulnerability
// section. But when both orgs computed that section from the same advisory
// snapshot — the same scannerDbDigest — the incoming section says what the
// prior one said and replacing it changes nothing. Production has 361
// foreign-read pairs across 13 of 15 orgs, so counting those benign rewrites
// left the counter permanently non-zero, and the L-02 gate asks for a ZERO. A
// number that can never be zero is not decision support.

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func priorWithDigest(t *testing.T, digest string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"vulnerabilities": map[string]any{"scannerDbDigest": digest, "isVulnerable": true},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestVulnFactsDiffer(t *testing.T) {
	cases := []struct {
		name  string
		prior []byte
		in    VulnSection
		want  bool
		why   string
	}{
		{
			name:  "same snapshot is NOT a meaningful overwrite",
			prior: priorWithDigest(t, "sha256:aaa"), in: VulnSection{ScannerDBDigest: "sha256:aaa"},
			want: false,
			why: "both orgs read the same advisory snapshot, so the incoming section says what the " +
				"prior one said — this is the population that kept the counter permanently non-zero",
		},
		{
			name:  "different snapshot IS a meaningful overwrite",
			prior: priorWithDigest(t, "sha256:aaa"), in: VulnSection{ScannerDBDigest: "sha256:bbb"},
			want: true, why: "the two orgs disagree about the facts, which is the event L-02 is about",
		},
		{
			name:  "unknown prior digest counts",
			prior: priorWithDigest(t, ""), in: VulnSection{ScannerDBDigest: "sha256:bbb"},
			want: true, why: "conservative: failing to count a real overwrite hides the event",
		},
		{
			name:  "unknown incoming digest counts",
			prior: priorWithDigest(t, "sha256:aaa"), in: VulnSection{},
			want: true, why: "conservative, same reason",
		},
		{
			name:  "no prior row counts",
			prior: nil, in: VulnSection{ScannerDBDigest: "sha256:aaa"},
			want: true, why: "nothing to compare against",
		},
		{
			name:  "unparseable prior counts",
			prior: []byte("{not json"), in: VulnSection{ScannerDBDigest: "sha256:aaa"},
			want: true, why: "a payload we cannot read is a payload we cannot clear",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := vulnFactsDiffer(c.prior, c.in); got != c.want {
				t.Errorf("vulnFactsDiffer = %v, want %v — %s", got, c.want, c.why)
			}
		})
	}
}

// A SOURCE guard on the call site. vulnFactsDiffer is pure and fully covered
// above, and that is not enough: the increment lives inside Upsert, behind a
// Postgres transaction, so dropping the condition leaves every test above green
// while the counter goes back to being permanently non-zero and useless.
func TestCrossOrgCounterUsesTheDigestDiscriminator(t *testing.T) {
	src, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatalf("read store.go: %v", err)
	}
	if !strings.Contains(string(src), "vulnFactsDiffer(priorPayload, r.Vulnerabilities)") {
		t.Fatal("the crossOrgVulnOverwrites increment does not consult vulnFactsDiffer. Without it " +
			"every benign same-snapshot rewrite counts, the counter can never reach zero, and the " +
			"L-02 gate it feeds cannot be answered either way.")
	}
}

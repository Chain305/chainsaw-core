package intelligence

// N5 — a truncated artifact walk must be reported as "not fully inspected",
// never as a clean absence of findings.
//
// artifactmap.Result.Truncated was computed at three caps and pinned by
// artifactmap_test.go, and then read by nobody. These tests are the missing
// consumer half: they drive the real provider Run methods and assert the
// warning reaches the PartialReport, including on the early-return paths that
// are exactly where "nothing found" is emitted.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/intelligence/artifactmap"
)

// truncatedHandle primes the memoised shared map so the provider sees
// Truncated=true without a multi-megabyte fixture. Legal from inside the
// package, and honest: SharedArtifactMap's only contract is "return the
// cached Result", which is exactly what it then does.
//
// TestSharedArtifactMapTruncatesForReal below proves the flag is reachable
// from a genuine archive under the DEFAULT options, so this shortcut is not
// asserting a state production cannot produce.
func truncatedHandle() *ArtifactHandle {
	h := &ArtifactHandle{Bytes: []byte("nonempty")}
	h.mapOnce.Do(func() {
		h.mapResult = artifactmap.Result{Files: artifactmap.ArtifactFileMap{}, Truncated: true}
	})
	return h
}

// cleanHandle is the control: same shape, Truncated=false.
func cleanHandle() *ArtifactHandle {
	h := &ArtifactHandle{Bytes: []byte("nonempty")}
	h.mapOnce.Do(func() {
		h.mapResult = artifactmap.Result{Files: artifactmap.ArtifactFileMap{}}
	})
	return h
}

func hasTruncationWarning(p PartialReport) bool {
	for _, w := range p.Warnings {
		if w.Code == WarnArtifactTruncated {
			return true
		}
	}
	return false
}

// TestProvidersReportPartialInspection is the core assertion, run across every
// provider that reads the shared artifact map. Each of these returns an empty
// or "performed, clean" PartialReport when it finds nothing — which, on a
// truncated archive, is a claim it has no basis for.
func TestProvidersReportPartialInspection(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name string
		run  func(h *ArtifactHandle) (PartialReport, error)
	}{
		{
			name: "shrinkwrap",
			run: func(h *ArtifactHandle) (PartialReport, error) {
				return newShrinkwrapProvider().Run(ctx,
					Request{Key: Key{Ecosystem: "npm", Package: "x", Version: "1.0.0"}, Artifact: h}, nil)
			},
		},
		{
			name: "hiddenunicode",
			run: func(h *ArtifactHandle) (PartialReport, error) {
				return newHiddenUnicodeProvider().Run(ctx,
					Request{Key: Key{Ecosystem: "npm", Package: "x", Version: "1.0.0"}, Artifact: h}, nil)
			},
		},
		{
			name: "installscripts",
			run: func(h *ArtifactHandle) (PartialReport, error) {
				return newInstallScriptsProvider().Run(ctx,
					Request{Key: Key{Ecosystem: "npm", Package: "x", Version: "1.0.0"}, Artifact: h}, nil)
			},
		},
		{
			name: "manifestconfusion",
			run: func(h *ArtifactHandle) (PartialReport, error) {
				return newManifestConfusionProvider().Run(ctx, Request{
					Key:                   Key{Ecosystem: "npm", Package: "x", Version: "1.0.0"},
					Artifact:              h,
					RegistryMetadataBytes: []byte(`{"name":"x"}`),
				}, nil)
			},
		},
		{
			name: "manifestconfusion-pypi",
			run: func(h *ArtifactHandle) (PartialReport, error) {
				return newPyPIManifestConfusionProvider().Run(ctx, Request{
					Key:                   Key{Ecosystem: "pip", Package: "x", Version: "1.0.0"},
					Artifact:              h,
					RegistryMetadataBytes: []byte(`{"info":{"name":"x"}}`),
				}, nil)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.run(truncatedHandle())
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if !hasTruncationWarning(got) {
				t.Fatalf("%s returned a clean absence over a TRUNCATED artifact map with no "+
					"%s warning — 'could not look' is being reported as 'looked and found nothing' (N5). warnings=%+v",
					tc.name, WarnArtifactTruncated, got.Warnings)
			}

			// Control: an untruncated walk must stay silent, or the warning is
			// noise and operators learn to ignore it.
			clean, err := tc.run(cleanHandle())
			if err != nil {
				t.Fatalf("Run (clean): %v", err)
			}
			if hasTruncationWarning(clean) {
				t.Errorf("%s emitted the truncation warning on a COMPLETE walk", tc.name)
			}
		})
	}
}

// TestTruncationWarningIsVerdictNeutral pins the deliberate scope limit. The
// fail-closed posture decision for partially-inspected artifacts is deferred;
// what ships is the record, not a verdict change. If someone later wires this
// into scoring, this test should be updated on purpose, not tripped over.
func TestTruncationWarningIsVerdictNeutral(t *testing.T) {
	ctx := context.Background()
	req := Request{Key: Key{Ecosystem: "npm", Package: "x", Version: "1.0.0"}}

	req.Artifact = cleanHandle()
	base, err := newHiddenUnicodeProvider().Run(ctx, req, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	req.Artifact = truncatedHandle()
	trunc, err := newHiddenUnicodeProvider().Run(ctx, req, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if (base.Scan == nil) != (trunc.Scan == nil) {
		t.Fatalf("truncation changed whether a Scan section is produced: base=%v trunc=%v",
			base.Scan != nil, trunc.Scan != nil)
	}
	if base.Scan != nil && trunc.Scan != nil {
		if base.Scan.HiddenUnicodeHits != trunc.Scan.HiddenUnicodeHits ||
			base.Scan.Performed != trunc.Scan.Performed {
			t.Error("truncation altered the Scan section — this signal is observability only; " +
				"the fail-closed posture decision is deliberately deferred")
		}
	}
	if len(trunc.Warnings) != len(base.Warnings)+1 {
		t.Errorf("expected exactly one extra warning, got base=%d trunc=%d",
			len(base.Warnings), len(trunc.Warnings))
	}
}

// TestSharedArtifactMapTruncatesForReal proves the state the tests above prime
// is genuinely reachable through SharedArtifactMap under the DEFAULT options
// production uses — otherwise the primed handle would be asserting a fiction.
func TestSharedArtifactMapTruncatesForReal(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	// One past MaxFiles is the cheapest real cap to cross: tiny entries, so
	// this is a few MB of tar and a trivial gzip.
	for i := 0; i < artifactmap.MaxFiles+10; i++ {
		body := "x"
		hdr := &tar.Header{
			Name:     fmt.Sprintf("pkg/f%05d.js", i),
			Mode:     0o644,
			Size:     int64(len(body)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header: %v", err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatalf("write body: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}

	h := &ArtifactHandle{Bytes: buf.Bytes()}
	res := h.SharedArtifactMap()
	if !res.Truncated {
		t.Fatalf("a %d-entry archive did not set Truncated under the default caps "+
			"(MaxFiles=%d) — the signal these tests consume is unreachable in production",
			artifactmap.MaxFiles+10, artifactmap.MaxFiles)
	}

	// And end-to-end through a real provider, no priming anywhere.
	got, err := newHiddenUnicodeProvider().Run(context.Background(),
		Request{Key: Key{Ecosystem: "npm", Package: "x", Version: "1.0.0"}, Artifact: h}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasTruncationWarning(got) {
		t.Fatalf("real truncated archive produced no %s warning; warnings=%+v",
			WarnArtifactTruncated, got.Warnings)
	}
	for _, w := range got.Warnings {
		if w.Code != WarnArtifactTruncated {
			continue
		}
		if !strings.Contains(w.Message, "not fully inspected") {
			t.Errorf("warning message does not say the artifact was not fully inspected: %q", w.Message)
		}
	}
}

// TestNoTruncationWarningWithoutArtifact — a provider that never had bytes
// must not claim a partial inspection. Absence of an artifact is a different
// condition (WarnNeedsArtifact) and conflating them would make the new warning
// fire on every metadata-only scan.
func TestNoTruncationWarningWithoutArtifact(t *testing.T) {
	got, err := newShrinkwrapProvider().Run(context.Background(),
		Request{Key: Key{Ecosystem: "npm", Package: "x", Version: "1.0.0"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if hasTruncationWarning(got) {
		t.Fatal("nil artifact produced an 'artifact not fully inspected' warning")
	}
}

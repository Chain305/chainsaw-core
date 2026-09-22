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

// TestProvidersReportPartialInspection is the core assertion, and it now
// runs through the SCANNER rather than calling each provider directly.
//
// The warning used to be applied inside each artifact-reading provider's
// Run. Five core providers did it and seven premium ones did not, so on
// an enterprise build a truncated archive produced a silent clean result
// from provider_aiartifact, provider_codesmell and
// provider_wave4_artifact — "we examined part of this package and found
// nothing" presented as "nothing is there" (qa_phase11 section 6b).
//
// A per-provider test could never have caught that: it asserts the
// providers it lists, and the defect was the providers nobody listed.
// Driving the scanner asserts the property for EVERY provider that
// declares NeedsArtifact, including ones added later.
func TestProvidersReportPartialInspection(t *testing.T) {
	ctx := context.Background()
	req := func(h *ArtifactHandle) Request {
		return Request{
			Key:                   Key{Ecosystem: "npm", Package: "x", Version: "1.0.0"},
			Artifact:              h,
			RegistryMetadataBytes: []byte(`{"name":"x"}`),
		}
	}

	// A provider that reads the artifact and reports a clean absence —
	// the exact shape the warning exists to qualify.
	artifactReader := &fakeProvider{
		name:     "artifact-reader",
		signal:   SignalHiddenUnicode,
		needsArt: true,
		partial:  PartialReport{Scan: &ArtifactScanSection{Performed: true}},
	}
	// A provider that never opens the archive. It must NOT be warned
	// about: a warning naming the wrong provider invites someone to go
	// looking at the wrong component.
	metadataOnly := &fakeProvider{
		name:    "metadata-only",
		signal:  SignalTyposquat,
		partial: PartialReport{SupplyChain: &SupplyChainSection{TyposquatStatus: "clean"}},
	}

	svc := New(Config{Providers: []Provider{artifactReader, metadataOnly}})

	rep, err := svc.Scan(ctx, req(truncatedHandle()))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	var sawReader, sawMetadata bool
	for _, w := range rep.Observation.Warnings {
		if w.Code != WarnArtifactTruncated {
			continue
		}
		switch w.Provider {
		case "artifact-reader":
			sawReader = true
		case "metadata-only":
			sawMetadata = true
		}
	}
	if !sawReader {
		t.Errorf("an artifact-reading provider returned a clean absence over a TRUNCATED map with no %s warning — "+
			"'could not look' is being reported as 'looked and found nothing'. warnings=%+v",
			WarnArtifactTruncated, rep.Observation.Warnings)
	}
	if sawMetadata {
		t.Errorf("a provider that never reads the artifact was warned about truncation; "+
			"the warning names the wrong component. warnings=%+v", rep.Observation.Warnings)
	}

	// Control: a complete walk must stay silent, or the warning is noise
	// and operators learn to ignore it.
	clean, err := svc.Scan(ctx, req(cleanHandle()))
	if err != nil {
		t.Fatalf("Scan (clean): %v", err)
	}
	for _, w := range clean.Observation.Warnings {
		if w.Code == WarnArtifactTruncated {
			t.Errorf("truncation warning emitted on a COMPLETE walk (provider %q)", w.Provider)
		}
	}
}

// TestTruncationWarningIsNotDoubleApplied — the wrap moved from the
// providers to the scanner. A provider that also wraps its own return
// would now emit the warning twice, which reads as two findings.
func TestTruncationWarningIsNotDoubleApplied(t *testing.T) {
	ctx := context.Background()
	p := &fakeProvider{
		name:     "double-check",
		signal:   SignalHiddenUnicode,
		needsArt: true,
		partial:  PartialReport{Scan: &ArtifactScanSection{Performed: true}},
	}
	svc := New(Config{Providers: []Provider{p}})
	rep, err := svc.Scan(ctx, Request{
		Key:      Key{Ecosystem: "npm", Package: "x", Version: "1.0.0"},
		Artifact: truncatedHandle(),
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	var n int
	for _, w := range rep.Observation.Warnings {
		if w.Code == WarnArtifactTruncated && w.Provider == "double-check" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("truncation warning applied %d times, want exactly 1", n)
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
	// The provider itself no longer appends the warning -- the scanner
	// does, once, for every NeedsArtifact provider. So a DIRECT Run over
	// a truncated handle must now produce exactly the same warnings as a
	// clean one. That is the invariant that proves the wrap really moved
	// rather than being duplicated.
	if len(trunc.Warnings) != len(base.Warnings) {
		t.Errorf("a direct provider Run changed its warning count on truncation (base=%d trunc=%d); "+
			"the truncation warning belongs to the scanner now, and a provider adding its own would double it",
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

	// And end-to-end through the SCANNER with a real provider, no
	// priming anywhere. Through the scanner rather than a bare Run
	// because that is where the warning is applied now -- once, for
	// every provider declaring NeedsArtifact, instead of in each
	// provider's own return where seven of them had forgotten it.
	svc := New(Config{Providers: []Provider{newHiddenUnicodeProvider()}})
	rep, err := svc.Scan(context.Background(),
		Request{Key: Key{Ecosystem: "npm", Package: "x", Version: "1.0.0"}, Artifact: h})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	got := PartialReport{Warnings: rep.Observation.Warnings}
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

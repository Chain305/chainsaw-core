package intelligence

// This file preserves the pre-Wave-0a per-provider archive walker as a
// narrow-path fallback. The production code path in every Tier-2
// provider goes through ArtifactHandle.SharedArtifactMap, which invokes
// artifactmap.Build exactly once per Scan. The helpers below only fire
// when the shared map returned zero files — in practice, that path is
// unreachable from Service.Scan (any non-empty archive will populate
// the map), but we keep it for tests that construct a provider
// directly against a malformed or empty-but-non-nil handle.

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
	"strings"

	"github.com/chain305/chainsaw-core/intelligence/artifactmap"
)

// Legacy constants preserved verbatim so the fallback behaves exactly
// like the pre-refactor implementation.
const (
	legacyMaxManifestFileBytes       = 2 * 1024 * 1024
	legacyMaxArtifactBytesForInspect = 256 * 1024 * 1024
)

func legacyWalkManifests(h *ArtifactHandle) map[string][]byte {
	return legacyWalkArtifact(h, artifactmap.WantsInstallManifest)
}

func legacyWalkHiddenUnicodeText(h *ArtifactHandle) map[string][]byte {
	return legacyWalkArtifact(h, artifactmap.WantsHiddenUnicodeText)
}

func legacyWalkArtifact(h *ArtifactHandle, want func(name string) bool) map[string][]byte {
	if h == nil || len(h.Bytes) == 0 {
		return nil
	}
	payload := h.Bytes
	if len(payload) > legacyMaxArtifactBytesForInspect {
		payload = payload[:legacyMaxArtifactBytesForInspect]
	}
	if looksLikeZipPayload(payload) {
		return legacyWalkZip(payload, want)
	}
	if looksLikeGzipPayload(payload) {
		gzr, err := gzip.NewReader(bytes.NewReader(payload))
		if err != nil {
			return nil
		}
		defer gzr.Close()
		return legacyWalkTar(gzr, want)
	}
	return legacyWalkTar(bytes.NewReader(payload), want)
}

func looksLikeZipPayload(payload []byte) bool {
	return len(payload) >= 4 && bytes.Equal(payload[:4], []byte("PK\x03\x04"))
}

func looksLikeGzipPayload(payload []byte) bool {
	return len(payload) >= 2 && payload[0] == 0x1f && payload[1] == 0x8b
}

func legacyWalkTar(r io.Reader, want func(name string) bool) map[string][]byte {
	out := make(map[string][]byte)
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return out
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		name := hdr.Name
		if !want(name) {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(tr, legacyMaxManifestFileBytes))
		if err != nil {
			continue
		}
		out[strings.ToLower(name)] = body
	}
	return out
}

func legacyWalkZip(payload []byte, want func(name string) bool) map[string][]byte {
	out := make(map[string][]byte)
	zr, err := zip.NewReader(bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		return out
	}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		name := f.Name
		if !want(name) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(rc, legacyMaxManifestFileBytes))
		rc.Close()
		if err != nil {
			continue
		}
		out[strings.ToLower(name)] = body
	}
	return out
}

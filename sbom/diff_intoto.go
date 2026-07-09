package sbom

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// SBOMFormat identifies which on-disk SBOM document layout we're
// dealing with. Detected by inspecting the JSON for signature keys.
type SBOMFormat int

const (
	FormatUnknown SBOMFormat = iota
	FormatCycloneDX
	FormatInToto
)

func (f SBOMFormat) String() string {
	switch f {
	case FormatCycloneDX:
		return "cyclonedx"
	case FormatInToto:
		return "in-toto"
	default:
		return "unknown"
	}
}

// ErrUnknownSBOMFormat is returned when neither a CycloneDX nor an
// in-toto signature is found in the input.
var ErrUnknownSBOMFormat = errors.New("sbom: unknown SBOM format (expected CycloneDX or in-toto)")

// detectSBOMFormat inspects the JSON structure to determine which
// format the bytes represent. Looks at top-level keys rather than
// substring-matching the raw bytes, so an embedded `"bomFormat"` deep
// inside an in-toto predicate doesn't fool the detector.
func detectSBOMFormat(data []byte) SBOMFormat {
	// Cheap pre-screen on the first slice of bytes — if neither
	// signature key appears at all, skip parsing.
	prefixLimit := 512
	if len(data) < prefixLimit {
		prefixLimit = len(data)
	}
	prefix := string(data[:prefixLimit])
	hasCDXHint := strings.Contains(prefix, `"bomFormat"`)
	hasInTotoHint := strings.Contains(prefix, `"predicateType"`) || strings.Contains(prefix, `"_type"`)
	if !hasCDXHint && !hasInTotoHint {
		// Fall through to a structural decode in case keys appear
		// later in a heavily-prefixed document.
	}

	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return FormatUnknown
	}
	if raw, ok := probe["bomFormat"]; ok {
		var s string
		if err := json.Unmarshal(raw, &s); err == nil && strings.EqualFold(s, "CycloneDX") {
			return FormatCycloneDX
		}
	}
	if rawType, ok := probe["_type"]; ok {
		var s string
		if err := json.Unmarshal(rawType, &s); err == nil && strings.Contains(s, "in-toto") {
			return FormatInToto
		}
	}
	if _, ok := probe["predicateType"]; ok {
		// An in-toto Statement always carries predicateType; the
		// presence of that field together with a `subject` array is
		// the canonical signature.
		if _, hasSubject := probe["subject"]; hasSubject {
			return FormatInToto
		}
	}
	return FormatUnknown
}

// intotoToComponents normalizes an in-toto Statement to the
// format-neutral Component slice. The current chainsaw producer
// (WrapSBOMAsInToto) embeds a CycloneDX 1.6 document as the predicate,
// so we delegate component extraction to cycloneDXToComponents once
// the predicate is unmarshalled.
//
// Returns an error if the predicate cannot be parsed as CycloneDX —
// other predicate types (SPDX in-toto, raw subject-only attestations)
// are not yet supported by the diff path.
func intotoToComponents(stmt *InTotoStatement) ([]Component, error) {
	if stmt == nil {
		return nil, errors.New("sbom: nil in-toto statement")
	}
	if len(stmt.Predicate) == 0 {
		// Subject-only attestation — no components to diff.
		return nil, nil
	}
	var bom CycloneDXBOM
	if err := json.Unmarshal(stmt.Predicate, &bom); err != nil {
		return nil, fmt.Errorf("sbom: parse in-toto predicate as CycloneDX: %w", err)
	}
	if !strings.EqualFold(bom.BOMFormat, "CycloneDX") && len(bom.Components) == 0 {
		return nil, fmt.Errorf("sbom: in-toto predicate is not a CycloneDX BOM (predicateType=%q)", stmt.PredicateType)
	}
	return cycloneDXToComponents(&bom), nil
}

// DiffFiles compares two SBOM files. The format of each file is
// auto-detected by inspecting the JSON structure: bomFormat ==
// "CycloneDX" means CycloneDX, presence of `_type`/`predicateType`
// signals in-toto. Returns ErrUnknownSBOMFormat when the format is
// unknown, and a clear error when the two files are different formats
// (mixing is unsupported in this iteration).
func DiffFiles(aData, bData []byte) (DiffResult, error) {
	aFmt := detectSBOMFormat(aData)
	bFmt := detectSBOMFormat(bData)
	if aFmt == FormatUnknown {
		return DiffResult{}, fmt.Errorf("first input: %w", ErrUnknownSBOMFormat)
	}
	if bFmt == FormatUnknown {
		return DiffResult{}, fmt.Errorf("second input: %w", ErrUnknownSBOMFormat)
	}
	if aFmt != bFmt {
		return DiffResult{}, fmt.Errorf("sbom: cannot diff mixed formats (%s vs %s); both inputs must be the same format", aFmt, bFmt)
	}

	aComps, err := componentsFromBytes(aData, aFmt)
	if err != nil {
		return DiffResult{}, fmt.Errorf("parse first input: %w", err)
	}
	bComps, err := componentsFromBytes(bData, bFmt)
	if err != nil {
		return DiffResult{}, fmt.Errorf("parse second input: %w", err)
	}
	return DiffComponents(aComps, bComps), nil
}

func componentsFromBytes(data []byte, format SBOMFormat) ([]Component, error) {
	switch format {
	case FormatCycloneDX:
		var bom CycloneDXBOM
		if err := json.Unmarshal(data, &bom); err != nil {
			return nil, fmt.Errorf("parse CycloneDX: %w", err)
		}
		return cycloneDXToComponents(&bom), nil
	case FormatInToto:
		var stmt InTotoStatement
		if err := json.Unmarshal(data, &stmt); err != nil {
			return nil, fmt.Errorf("parse in-toto statement: %w", err)
		}
		return intotoToComponents(&stmt)
	default:
		return nil, ErrUnknownSBOMFormat
	}
}

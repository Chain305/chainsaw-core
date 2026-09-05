package cli

// policy_import_repair.go — P9F-UD-05, the residual B7 (commit 72445469) left
// behind.
//
// B7 fixed the export side: `policy export --format yaml` no longer renders an
// int64 precedence as a float. Files exported BEFORE that fix still contain
// e.g. `precedence: -1.7874035210424883e+18` for a policy whose precedence is
// -1787403521042488196, and this is what happens when one is re-imported:
//
//	yaml.v3 decodes it to float64          -1.7874035210424883e+18
//	encoding/json marshals that back as    -1787403521042488300
//	the server's `Precedence int` ACCEPTS  -1787403521042488300
//
// encoding/json only uses exponent notation for |v| >= 1e21 and no int64 gets
// near that, so the float is always re-emitted as a plain integer literal that
// json.Unmarshal happily decodes into an `int`. The ledger for P9F-051/B7 says
// the server "rejects" these rows; it does not. The row is imported with a
// precedence 124 away from the exported one, silently reordering policy
// evaluation. That is worse than a skip and completely invisible.
//
// The value cannot be repaired. float64 has a 53-bit significand, so above
// 2^53 consecutive representable values are 2, 4, … apart; at this magnitude
// the gap is 256, meaning 256 distinct int64 precedences all encode to this
// one float. "Recovering" it would mint an id-like number the user never
// wrote. So we refuse the row and say exactly why and what to do — option (b).
//
// Below 2^53 every integer IS exactly representable, so `precedence: 100.0`
// names exactly one integer and is left alone: the guard keys on
// unrecoverability, not on the YAML node happening to be a float.

import (
	"fmt"
	"math"
	"sort"
	"strconv"
)

// maxExactIntegerFloat64 is 2^53. Every integer with magnitude at or below it
// is exactly representable as a float64; above it, integers start sharing
// representations and a decoded float no longer names a single integer.
const maxExactIntegerFloat64 = float64(1 << 53)

// checkPolicyNumberFidelity reports why a decoded policy cannot be imported
// faithfully, or nil when it can. It is deliberately a detector and not a
// repairer: every value it lets through re-encodes to the exact bytes the file
// asked for, and every value it stops is one whose original it cannot know.
//
// The walk is generic rather than precedence-only. Today `precedence` is the
// only int64-valued field on the wire (ids and timestamps are strings; ages,
// SLSA levels and 0-100/0-10/0-1 scores are all small — core/policy/store.go),
// so the recursion costs nothing now and catches the next large integer field
// somebody adds without them having to remember this file exists.
func checkPolicyNumberFidelity(file string, policy map[string]any) error {
	return walkPolicyNumbers(file, "", policy)
}

func walkPolicyNumbers(file, path string, v any) error {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys) // deterministic first-error, so the message is stable
		for _, k := range keys {
			if err := walkPolicyNumbers(file, joinPolicyPath(path, k), t[k]); err != nil {
				return err
			}
		}
	case map[any]any: // yaml.v3 only produces this for non-string keys
		for k, val := range t {
			if err := walkPolicyNumbers(file, joinPolicyPath(path, fmt.Sprint(k)), val); err != nil {
				return err
			}
		}
	case []any:
		for i, val := range t {
			if err := walkPolicyNumbers(file, fmt.Sprintf("%s[%d]", path, i), val); err != nil {
				return err
			}
		}
	case float64:
		return checkPolicyFloat(file, path, t)
	}
	return nil
}

func joinPolicyPath(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

// integerPolicyFields are the fields the server models as a Go integer, where
// a fractional value is an error rather than a legitimate score. Kept explicit
// so genuine floats (cvssMin, epssMax, …) are never second-guessed.
var integerPolicyFields = map[string]bool{"precedence": true}

func checkPolicyFloat(file, path string, f float64) error {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return fmt.Errorf("%s in %s is %v, which is not a number the server can store", path, file, f)
	}
	if f != math.Trunc(f) {
		if integerPolicyFields[path] {
			return fmt.Errorf("%s in %s is %s; %s must be a whole number", path, file, formatPolicyFloat(f), path)
		}
		return nil // a genuinely fractional field (cvssMin, epssMax, …)
	}
	if math.Abs(f) <= maxExactIntegerFloat64 {
		// Exactly representable: the float names one integer and re-encodes to
		// that integer's literal. Nothing was lost, nothing to say.
		return nil
	}

	// Integral, but too large for float64 to have preserved which integer it
	// was. Report the size of the ambiguity and the value that WOULD be stored,
	// so the message is checkable rather than hand-wavy.
	abs := math.Abs(f)
	ulp := math.Nextafter(abs, math.Inf(1)) - abs
	return fmt.Errorf(
		"%s in %s is %s — a float, not an integer, and too large for float64 to have kept it exactly: "+
			"%s distinct whole numbers encode to that same float, so the value that was exported cannot be recovered. "+
			"Importing it would store %s instead and silently reorder your policies. "+
			"This file was written by `chainsaw policy export --format yaml` before commit 72445469, "+
			"which rendered int64 %s as a float; re-run `chainsaw policy export` against the source org "+
			"and import the fresh file",
		path, file, formatPolicyFloat(f), strconv.FormatFloat(ulp, 'f', -1, 64), wouldStore(f), path)
}

// wouldStore is the integer the server would actually persist if this float
// were allowed through: encoding/json writes a float64 in this range with
// strconv 'f' shortest-representation formatting, and the server's
// `Precedence int` parses that literal. It is NOT int64(f) — the exact value
// of the double here is -1787403521042488320 while the literal on the wire is
// -1787403521042488300 — so the message has to be built the same way the wire
// bytes are, or it names a number the user will never see.
func wouldStore(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// formatPolicyFloat renders the float the way the file spells it, so the user
// can find the line.
func formatPolicyFloat(f float64) string {
	s := strconv.FormatFloat(f, 'g', -1, 64)
	if e := strconv.FormatFloat(f, 'e', -1, 64); len(e) < len(s) {
		return e
	}
	return s
}

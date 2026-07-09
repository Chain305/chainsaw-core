# npm scoped→unscoped typosquat: `raect-dom` competes with `react-dom` (`@react/*` reserved)

## Attack shape

Some teams treat the unofficial `@react/*` npm scope as a reserved
namespace for first-party React-ecosystem code, even though Meta does
not actually own that scope on the public npm registry. An attacker
publishes **unscoped** `raect-dom` (transposed `react` → `raect`) on
the public registry. Because the developer's reservedNamespaces policy
only blocks `@react/*`, the unscoped attacker slips past the
namespace check — the typosquat detector is the only line of defence.

This fixture exercises that gap: the depconfusion checker (correctly)
does NOT flag the unscoped name against an `@react/*` pattern, but the
typosquat detector should flag it against popular `react-dom` via the
edit-distance branch (transposition, distance 2 — well within the
short-name threshold of 2 for an 8-char name).

## What the detectors should output

`typosquat.Detector.Check("npm", "raect-dom")` against an
index that includes `react-dom` should return:

- `IsSuspected: true`
- `Method: "edit-distance"`
- `SimilarTo: "react-dom"`
- `Distance` ≤ 2 (transposition is one Damerau-Levenshtein op; the
  second character difference is the swap)
- `Confidence: "medium"` or `"high"` depending on distance

`internal/depconfusion.Checker.Check("raect-dom", ["@react/*"])` should
return `IsViolation: false` — this is the gap the typosquat detector
covers.

See `expected.json` for the machine-checked assertion.

## Why this fixture exists

The typosquat and depconfusion detectors are complementary; this
fixture is the only one in the corpus that exercises *both* in a
single name (one positive, one negative) so a future regression that
miswires the two paths against each other gets caught.

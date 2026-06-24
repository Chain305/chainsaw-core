# npm typosquat: `lod_ash` → `lodash`

## Attack shape

An attacker publishes `lod_ash` to the npm registry, hoping to catch
`npm install lod_ash` typos for the legitimate `lodash` (top-10 npm
package, ~50M downloads/week). The substitution replaces a single
character (`a` → `_`) — a one-edit-distance mutation that the typosquat
detector's BK-tree search is supposed to catch at `Confidence: high`
(distance == 1).

## What the detector should output

`typosquat.Detector.Check("npm", "lod_ash")` against an index
that includes `lodash` should return:

- `IsSuspected: true`
- `Method: "edit-distance"`
- `SimilarTo: "lodash"`
- `Distance: 1`
- `Confidence: "high"`

See `expected.json` for the machine-checked assertion.

## Why this fixture exists

The detector unit tests in `typosquat/detector_test.go` use
inline string cases for the same shapes, but no end-to-end fixture
existed under `testing/fixtures/` to parallel the
`install_scripts/historic_malicious/` corpus. This fixture is the
typosquat-detector's analogue: a real-on-disk manifest that the
detector pipeline can be pointed at, so a future regression where the
detector stops loading its index, or where the fixture-loading path
breaks, lights up immediately.

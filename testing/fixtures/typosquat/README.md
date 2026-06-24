# Typosquat / namespace-confusion fixtures

Sanitized recreations of typosquat and dependency-confusion attack shapes
that the chainsaw `typosquat` and (enterprise) `internal/depconfusion`
detectors are responsible for catching.

These fixtures parallel the `install_scripts/historic_malicious/` corpus:
each subdirectory carries (a) the manifest the attacker would publish to
the public registry, (b) a README explaining the attack shape, and
(c) an `expected.json` that pins the detector booleans the corresponding
detector contract is supposed to emit. The Go test
`typosquat/fixture_corpus_test.go` walks this tree, runs each
fixture through the appropriate detector, and asserts the booleans.

Dependency-confusion (`internal/depconfusion`) detection is an enterprise
feature and is not part of the open-core module; the depconfusion fixtures
here are corpus-only and exercise the enterprise detector when it is
present.

## What is and is not in scope

- These are **input** manifests, not exploit payloads. There are no live
  exfil URLs and no executable install hooks — the typosquat / namespace
  signal lives in the package *name*, not the script body. The lifecycle
  scripts present (e.g. `postinstall`) carry a placeholder `echo` so
  the manifest parses cleanly without standing up a second-order risk.
- Each `expected.json` reflects the detector behaviour at fixture-add
  time. If the detector legitimately tightens (e.g. raises confidence,
  switches method) the fixture's expected file should be updated in the
  same commit so the corpus stays the source of truth.

## Adding a new fixture

1. Create a new subdirectory under `typosquat/` named after the attack
   shape (`<ecosystem>_<short-tag>`).
2. Drop in the manifest the attacker would publish (`package.json`,
   `pyproject.toml`, etc.) plus a `README.md` that names the
   target popular package and the detection method the fixture is
   meant to exercise.
3. Add an `expected.json` matching the schema in
   `typosquat/fixture_corpus_test.go` (`PackageName`,
   `Ecosystem`, `Detector`, `IsSuspected`/`IsViolation`,
   `Method`/`MatchedPattern`, optional `SimilarTo`, etc.).
4. Add a row to the `cases` table in `fixture_corpus_test.go`.

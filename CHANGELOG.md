# Changelog

Notable changes to the Chainsaw open-core engine — the `chainsaw` CLI and the
decision libraries in this module (proxy, policy, intelligence, risk, typosquat,
malware, depgraph, SBOM, provenance). Format loosely follows
[Keep a Changelog](https://keepachangelog.com/).

A human-readable, product-wide view lives at <https://chain305.com/changelog/>.
Tagged releases (each with a published SHA-256 checksum) appear on the
[GitHub Releases](https://github.com/chain305/chainsaw-core/releases) page
once the first signed release is cut.

## Unreleased

### Added
- Intel-bundle signature verification: always-on digest binding, plus opt-in
  full Sigstore authenticity (Fulcio + Rekor + OIDC issuer + signer-identity)
  behind `CHAINSAW_INTEL_BUNDLE_STRICT_VERIFY` / `RequireAuthenticity`.
- `chainsaw bundle verify --strict` and `chainsaw doctor --offline` distinguish
  digest-bound integrity from full Sigstore authenticity.
- **Local-first install guard** — `chainsaw npm/pip/go` wraps the package manager
  and refuses malicious/typosquatted packages at install time, evaluated on-box.
  Offline typosquat (npm/PyPI/Go) + an embedded known-malicious floor of famous
  attacks; `npm install`/`npm ci` and `pip install -r` scan the resolved lockfile.
  `chainsaw guard update` (opt-in, the only networked command) pulls the full
  OpenSSF malicious-packages set into a local cache (`CHAINSAW_GUARD_DB`) the guard
  merges. Fail-open with a visible notice when coverage is thin.

- **`chainsaw guard allow <eco>:<name>`** — a local, offline allowlist for the
  install guard, so a package the typosquat lane refuses by mistake can be
  cleared once, permanently, without disabling the guard. `guard allow --list`
  shows the store; `--remove` reverses it. Known-malicious and homoglyph
  verdicts are **not** waivable, and a waived verdict still prints a `~ waived`
  line on every install — including under `--quiet` — so an entry in that file
  can never be a silent hole.

### Changed
- **Typosquat block lane now asks whether the edit looks like a typo**, not only
  whether the target is popular. A rune added to or dropped from an *end* of a
  popular name is how sibling packages get named (`nan`→`nano`, `arg`→`args`,
  `listr`→`listr2`), not how names get mistyped, so those demote to a warning;
  appends against a top-500 target still block. Measured on 24,206 real package
  names held out of the detector's own popularity seed, false blocks fall from
  **1.87% to 1.02%**. This is a trade, and both halves belong together: measured
  against 227,525 real malicious coordinates from the OpenSSF feed, the guard
  gives up **8.2% of the typosquat lane's block recall**. 247 of the held-out
  packages are still refused — the class is narrowed, not closed. Method and the
  full survivor list: `docs/launch/fp-rate-measurement.md`.
- **Typosquat verdicts are now deterministic.** Equidistant matches were resolved
  by Go map-iteration order, so the same package on the same binary could refuse
  on one run and warn on the next once the block decision started depending on
  which target was matched. Ties now resolve by nearest, then most popular
  target, then lexicographically.
- Engine relicensed to **Apache-2.0**; builds standalone via
  `go install github.com/chain305/chainsaw-core/cmd/chainsaw@latest`.

_Versioned entries begin with the first tagged release._

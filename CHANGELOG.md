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

### Changed
- Engine relicensed to **Apache-2.0**; builds standalone via
  `go install github.com/chain305/chainsaw-core/cmd/chainsaw@latest`.

_Versioned entries begin with the first tagged release._

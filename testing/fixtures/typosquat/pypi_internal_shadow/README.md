# PyPI namespace-confusion: `acme-internal-billing` shadows internal-only name

> **Enterprise feature.** Dependency-confusion detection
> (`internal/depconfusion`) is not part of the open-core module. This
> fixture is corpus-only — it exercises the enterprise checker when that
> code is present and is retained here so the shared corpus stays the
> source of truth.

## Attack shape

A tenant publishes their internal Python package `acme-internal-billing`
to a private index only. An attacker registers the *same name* on the
public PyPI. Because pip's default index resolution prefers higher
versions across all configured indexes, an attacker who publishes
`acme-internal-billing 99.0.0` to PyPI wins the resolution against the
internal `0.0.1` — the canonical Alex Birsan 2021 attack.

The defence is name-based: the tenant declares `acme-internal-*` in
their `reservedNamespaces` policy, and chainsaw refuses any public-PyPI
resolution of a matching name regardless of version.

## What the detector should output

`internal/depconfusion.Checker.Check("acme-internal-billing", ["acme-internal-*"])`
should return:

- `IsViolation: true`
- `MatchedPattern: "acme-internal-*"`
- `Reason: "package matches reserved namespace; may be a dependency confusion attempt"`

See `expected.json` for the machine-checked assertion. The
`reservedNamespaces` array used by the test is loaded inline
(per-fixture) — the corpus does not depend on a tenant policy file.

## Why this fixture exists

The depconfusion checker has unit tests with inline namespace strings
but no on-disk manifest fixture. This fixture mirrors the
`historic_malicious/` pattern so the corpus exercises both ecosystems
the depconfusion checker is meant to cover (npm scoped + PyPI prefix).

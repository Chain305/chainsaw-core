# chainsaw-core

The open-core of [Chainsaw](https://chain305.com) — a firewall for your package
managers. This module ships the `chainsaw` CLI and the embeddable proxy/policy/
intelligence libraries it is built on. The enterprise control plane (multi-tenant
server, dashboard, premium intelligence, SSO/SCIM, signed-policy hardening) lives
in a separate private module and is not part of this repository.

> **Module:** `github.com/chain305/chainsaw-core`

## What's here

- **`chainsaw` CLI** (`cmd/chainsaw`) — guard installs locally (`chainsaw npm/pip/go`
  refuses malicious/typosquatted packages before they hit your build), point your
  package managers at a Chainsaw proxy, wire install hooks (`install-hook`), scan PRs
  (`pr-scan`), inspect packages, and run `doctor` health checks.
- **Proxy + policy engine** (`proxy/`, `policy/`, `policyengine/`) — the
  pull-through policy proxy and its precedence-based rule engine, usable as a
  library.
- **Supply-chain intelligence** (`intelligence/`, `risk/`, `typosquat/`,
  `malware/`, `depgraph/`, `sbom/`, `provenance/`) — the deterministic,
  locally-computable signals (typosquat, reserved-namespaces, hidden-unicode,
  install-scripts, checksum, manifest-confusion, release-freshness, license,
  embedded-keyring provenance) that run on every ecosystem.
- **Ecosystem format parsers** (`formats/`, `depparser/`) for npm, PyPI,
  RubyGems, Maven, NuGet, Composer, Cargo, Docker, Go modules, Swift, CocoaPods,
  Hugging Face, APT, and Yum/DNF.

## Install

Install the CLI from source with the Go toolchain:

```sh
go install github.com/chain305/chainsaw-core/cmd/chainsaw@latest
```

This drops a `chainsaw` binary in `$(go env GOPATH)/bin`. Make sure that
directory is on your `PATH`.

Or install the pre-built binary with the hosted one-liner (detects your
OS/arch and verifies the SHA-256 checksum):

```sh
curl -fsSL https://chain305.com/install.sh | sh
```

Signed GitHub Releases (SLSA provenance + Sigstore signatures) will follow
once the first signed release is cut (pending the release-signer bot); until
then, the one-liner above, `go install`, and building from source are the
supported install paths.

## Quickstart

```sh
# 1. Guard your installs — run your package manager THROUGH Chainsaw and
#    malicious or typosquatted packages are refused before they enter the build.
#    Fully local: the default path sends nothing off your machine.
chainsaw npm install lodash        # also: chainsaw pip install … / chainsaw go get …

# 2. Check local package-manager wiring and report what's installed/wired.
chainsaw doctor

# 3. Point a package manager at a Chainsaw proxy (writes the managed block
#    into its user config; re-runnable and idempotent).
chainsaw install-hook npm

# 4. In CI, diff a PR's manifest/lockfile changes and flag added or
#    upgraded dependencies before they merge.
chainsaw pr-scan
```

`chainsaw npm/pip/go` evaluate every install locally and refuse on a hit, then
hand off to the real tool — offline typosquat detection (npm, PyPI, Go) plus a
built-in known-malicious floor of well-known attacks. A bare `chainsaw npm install`
/ `npm ci` or `pip install -r requirements.txt` scans the whole resolved lockfile.
The default path is offline and sends nothing; for the full OpenSSF
malicious-packages set, run the opt-in `chainsaw guard update` (the one networked
step). If signal coverage is thin the guard fails open with a visible notice — it
never breaks `npm install`.

To make it automatic, add `eval "$(chainsaw guard init zsh)"` (or `bash`/`fish`) to
your shell config — `npm`, `pip`, and `go` then route through the guard with no
extra typing.

`chainsaw doctor` is read-only and safe to run anywhere. `install-hook`
edits a package manager's user config (and can be reverted with
`uninstall-hook`). `pr-scan` is intended as a CI status check.

Run `chainsaw --help` for the full command list.

## Free core vs Enterprise

This repository is the **free, open-core** of Chainsaw. It ships the
`chainsaw` CLI and the proxy/policy/intelligence libraries it is built on,
which run standalone with no server.

The **enterprise control plane** lives in a separate private module and is
not part of this repository. It adds the multi-tenant server and dashboard,
premium intelligence, SSO/SCIM, the admin hardening wizard and signed-policy
bundles, SIEM connectors, and billing. The signals in this module
(typosquat, reserved-namespaces, hidden-unicode, install-scripts, checksum,
manifest-confusion, release-freshness, license, embedded-keyring provenance)
are deterministic and locally computable, so the open core is useful on its
own; the enterprise tier layers org-wide policy, central reporting, and the
premium detectors on top.

See the docs at <https://docs.chain305.com> for the full product picture.

## Build

```sh
go build ./cmd/chainsaw        # builds the chainsaw CLI
go test ./...                  # runs the suite
```

The module is self-contained: it builds standalone with `GOWORK=off go build ./...`.

## License

Apache License 2.0 — see [LICENSE](LICENSE). This module (the `chainsaw` CLI
and the decision engine: proxy, policy, intelligence, risk, typosquat,
malware, depgraph, SBOM, provenance) is free and open source, no account
required. The enterprise control plane (multi-tenant server, dashboard,
premium intelligence, SSO/SCIM, hardening, policy signing, SIEM) is
closed-source commercial software in a separate private module.

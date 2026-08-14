# chainsaw

**A firewall for your package managers.** It refuses malicious and typosquatted
packages at the moment you install them — before any install script runs, on your
machine, with no account and nothing sent anywhere.

```
$ chainsaw npm install flatmap-stream
chainsaw  ✗ blocked  npm:flatmap-stream — known-malicious (CHW-FLOOR-flatmap-stream)
chainsaw  ✗ refused at the install path — nothing was installed

$ chainsaw npm install lodahs        # typo for lodash
chainsaw  ✗ blocked  npm:lodahs — looks like a typosquat of "lodash" (distance 1, edit-distance, target rank #101)
chainsaw  ✗ refused at the install path — nothing was installed

$ chainsaw npm install lodash        # real package, gets out of the way
added 1 package in 195ms
```

Every other supply-chain tool tells you about the compromised dependency *after*
it is in your lockfile, your `node_modules`, and your CI cache. A postinstall
script does not wait for your next scan. Chainsaw sits at the install path and
says no.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/chain305/chainsaw-core.svg)](https://pkg.go.dev/github.com/chain305/chainsaw-core)
[![Go Report Card](https://goreportcard.com/badge/github.com/chain305/chainsaw-core)](https://goreportcard.com/report/github.com/chain305/chainsaw-core)

---

## Install

```sh
curl -fsSL https://chain305.com/install.sh | sh
```

Or with the Go toolchain:

```sh
go install github.com/chain305/chainsaw-core/cmd/chainsaw@latest
```

## Try it in 30 seconds

```sh
# 1. Watch it refuse a real piece of malware. Nothing is installed, and
#    nothing about your machine is sent anywhere.
chainsaw npm install flatmap-stream

# 2. Ask why.
chainsaw why npm flatmap-stream

# 3. Make it automatic — npm/pip/go then route through the guard with no
#    extra typing.
eval "$(chainsaw guard init zsh)"     # or bash / fish
```

That is the whole product on a laptop. No signup, no config file, no daemon.

## What it actually catches

We publish both halves of the measurement, from a single run over one corpus,
because a catch rate without a false-positive rate is marketing:

| | Real malware (597 samples) | Top packages (860) |
|---|---|---|
| **Hard-block** — refuses the install | **46.2%** | **0.81%** false-block |
| **Any signal** — surfaces, does not block | 69% | 5% |

Measured 2026-08-12 on the byte-level guard, *before* the 231k-entry
known-malicious name feed that catches known-bad coordinates by name on top of
this. Every false block was PyPI; npm measured zero. The seven false blocks are
nameable — `tqdm`'s Telegram progress bar, `litellm`'s Slack alerting,
`ipython`'s `%pastebin` — and the corpus is rebuildable with a committed script.

We do not claim zero false positives. We published a 0.00% once; it did not
reproduce under a wider corpus, so we retired the claim. A reproducible 0.81% is
worth more than an unreproducible zero.

## How it is different

- **It blocks, it does not report.** The verdict happens at the install path, not
  in a dashboard you read on Tuesday.
- **Offline by default.** The typosquat corpus and a known-malicious floor are
  embedded in the binary. The default path makes no network calls — run it on an
  air-gapped box and it still works. `chainsaw guard update` is the one opt-in
  networked step, and it fetches the full OpenSSF malicious-packages set.
- **Nothing leaves your machine.** Your dependency graph is not uploaded to
  anyone, including us. There is no account to create.
- **It fails open, on purpose.** If a signal cannot be evaluated, it prints a
  visible notice and lets the install proceed. A thin feed or an unreachable
  server must never break `npm install`. That default is changeable — see
  [fail-closed coverage](#refusing-when-a-signal-cannot-be-evaluated) — but you
  have to ask for it.

## Ecosystems

npm · yarn · bun · PyPI · Go modules · Cargo · RubyGems · Maven · Gradle ·
NuGet · Composer · Docker/OCI · Swift · CocoaPods · Dart/pub · Hugging Face ·
APT · Yum/DNF

Typosquat detection is offline for npm, PyPI and Go. The known-malicious floor
and the rest of the signals run on every ecosystem above.

## Beyond the laptop

```sh
chainsaw doctor              # read-only: what's wired, what isn't
chainsaw install-hook npm    # point a package manager at a Chainsaw proxy
chainsaw pr-scan --base main # CI status check: flag deps added or upgraded in a PR
chainsaw scan --path .       # scan a whole project's resolved lockfiles
chainsaw sbom export         # CycloneDX / SPDX
```

`chainsaw --help` lists all 50 commands.

## How it works

The guard evaluates every install locally and refuses on a hit, then hands off to
the real package manager. The signals are deterministic and locally computable —
typosquat distance against an embedded popularity corpus, reserved namespaces,
hidden Unicode, install scripts, checksum mismatch, manifest confusion, release
freshness, license, and embedded-keyring provenance — so they need no server and
no account.

This repository is also a set of Go libraries, not just a CLI: the pull-through
policy proxy (`proxy/`, `policy/`, `policyengine/`), the intelligence and risk
engines (`intelligence/`, `risk/`, `typosquat/`, `malware/`, `depgraph/`,
`sbom/`, `provenance/`), and the ecosystem parsers (`formats/`, `depparser/`)
are all importable.

```sh
go build ./cmd/chainsaw   # build the CLI
go test ./...             # run the suite
```

The module is self-contained: it builds standalone with `GOWORK=off go build ./...`.

### Refusing when a signal cannot be evaluated

Fail-open is right for a workstation and wrong for some regulated and air-gapped
deployments. An opt-in, off-by-default gate lets you name the data sources that
must be evaluable and refuse the package when one is not:

```sh
export CHAINSAW_COVERAGE_MODE=warn          # off (default) | warn | closed
export CHAINSAW_COVERAGE_REQUIRED=typosquat,malware
```

Start in `warn` — it reports exactly what `closed` would have refused and refuses
nothing. Be honest about what an offline guard can see: `typosquat` always works,
`malware` needs `chainsaw guard update`, and `cve` / `registry_metadata` /
`provenance` need the server and are never available offline. Requiring one the
guard cannot see refuses every install, with a readable reason — that is the
intended answer, not a bug. Full reference:
[docs.chain305.com](https://docs.chain305.com).

## Open core, and what's commercial

Everything in this repository is free and Apache-2.0, runs standalone with no
server, and requires no account. That includes the CLI, the guard, the proxy and
policy engine, and every locally-computable signal listed above.

The commercial control plane is a separate, private module: the multi-tenant
server and dashboard, premium intelligence, SSO/SCIM, signed-policy bundles,
SIEM connectors, and billing. It layers org-wide policy, central reporting and
the premium detectors on top of this core — it does not gate what is here.

## Security

- **Reporting a vulnerability:** see [SECURITY.md](SECURITY.md).
- **Release signing:** binaries are currently distributed with SHA-256 checksums
  over TLS. Sigstore-signed releases with SLSA provenance are pending the
  release-signer identity; the installer's signature check is opt-in until then
  and says so rather than pretending to verify.

## Links

[Docs](https://docs.chain305.com) ·
[chain305.com](https://chain305.com) ·
[Contributing](CONTRIBUTING.md) ·
[Changelog](CHANGELOG.md)

Apache-2.0 — see [LICENSE](LICENSE).

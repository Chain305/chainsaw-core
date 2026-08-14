# chainsaw

**Refuses typosquatted and known-malicious packages at install time, offline, on
your machine.** No account, no server, no daemon. You can read every line of the
code that makes the decision.

```
$ chainsaw npm install lodahs
chainsaw  offline known-malicious + typosquat active; run `chainsaw guard update` for the full OpenSSF malicious-package set
chainsaw  behavioral byte scan not run; using name/feed/typosquat checks only (set CHAINSAW_GUARD_DEEP=1 or stage artifacts for byte-level coverage)
chainsaw  ✗ blocked  npm:lodahs — looks like a typosquat of "lodash" (distance 1, edit-distance, target rank #101)
chainsaw  ✗ refused at the install path — nothing was installed
chainsaw: usage telemetry is OFF until you opt in. Enable with `chainsaw telemetry on` (anonymous usage + blocked-package data, helps improve detection). See https://chain305.com/legal/privacy
```

That is the real output, copied verbatim — every notice included, nothing
trimmed. It is noisier than a marketing screenshot and we would rather you see
it now than be surprised by it.

The typosquat check needs no feed and no network: it catches names that have
never been seen before, which is the point, because a brand-new typosquat is on
nobody's blocklist yet.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/chain305/chainsaw-core.svg)](https://pkg.go.dev/github.com/chain305/chainsaw-core)

---

## Install

```sh
curl -fsSL https://chain305.com/install.sh | sh
```

Or with the Go toolchain:

```sh
go install github.com/chain305/chainsaw-core/cmd/chainsaw@latest
```

## Try it

```sh
chainsaw npm install lodahs      # typosquat — refused
chainsaw npm ci                  # scans every package in the resolved lockfile
chainsaw doctor                  # read-only: what's wired, what isn't
eval "$(chainsaw guard init zsh)"   # make it automatic (or bash / fish)
```

**Heads-up on the first run in a real terminal.** After the first block you get
two prompts, and **both default to Yes, so a blind Enter accepts them**:

1. *"Download the full OpenSSF malicious-package feed now?"* — a ~40MB fetch
   from GitHub that replaces the 11-entry embedded floor with ~231k entries. It
   takes a minute or two.
2. *"Share detection signals?"* — turns on telemetry. See
   [Telemetry](#telemetry) for exactly what that sends.

Decline either and nothing is lost; the offline typosquat check is unaffected.
To skip both entirely, `export CHAINSAW_OFFLINE=1`. Neither prompt appears in a
non-interactive shell, so CI never fetches and never sends.

## What it does, precisely

Read this section before you decide whether it is useful to you. Being wrong
about scope is worse than being narrow.

**Covered install verbs.** `npm install|i|add|ci`, `pip install`,
`cargo install|add`, `gem install`, `go get`, `go mod download`. Anything else
delegates straight to the real tool.

**Not covered:** `npx` / `npm exec`. The download-and-execute path is not
guarded today.

**What gets checked.**

| You run | Chainsaw evaluates |
|---|---|
| `npm install <name>` | that coordinate only — **not** its dependency tree |
| `npm install` / `npm ci` | every package in the resolved lockfile |
| `pip install -r req.txt` | every pinned requirement |
| `go mod download` | everything in `go.sum` |

**Signals that run by default, offline:** typosquat distance against an embedded
popularity corpus (npm, PyPI, Go), plus an embedded known-malicious floor of
**11 historic incidents**. `chainsaw guard update` replaces that floor with the
full ~231k-entry OpenSSF malicious-packages set — and on an interactive terminal
the guard *offers* to run it for you, defaulting to Yes (see
[Try it](#try-it)). Everything else — CVE lookup, registry metadata, provenance
— needs the server and is unavailable offline.

The offline claim is testable, and we have tested it adversarially: run the
guard under a network-denying sandbox and every block still fires identically.
Nothing on the default path requires egress. What the tool does do on a TTY is
*ask* whether you want the feed.

**Byte-level behavioural analysis is opt-in and off by default.** It needs
either a staged artifact directory (`CHAINSAW_GUARD_ARTIFACT_DIR`, you supply
the archives, still offline) or `CHAINSAW_GUARD_DEEP=1`, which fetches the
archive over the network and so waives the offline guarantee. Deep fetch is
further limited to **npm and cargo, and only for a version-pinned install** —
`chainsaw npm install foo` gets no byte scan even with deep mode on. The binary
tells you on every run when it did not run.

**It is bypassable, on purpose.** The shell hook wraps your package manager; a
determined developer types `/usr/local/bin/npm install` and routes around it.
Our own test suite says so
([`cli/bypass_matrix_test.go`](cli/bypass_matrix_test.go)). Closing that is a
registry-proxy and lockfile-pinning property, not something a local wrapper can
promise. Treat this as a seatbelt on your own machine, not a control you can
attest to an auditor.

**It fails open.** If a signal cannot be evaluated it prints a notice and lets
the install proceed. A thin feed must never break `npm install`. That default is
changeable — see [fail-closed coverage](#refusing-when-a-signal-cannot-be-evaluated).

## Known false positives

The typosquat detector blocks by edit distance against a popularity corpus, and
it does produce false positives on short, legitimate names. Two we know of:

```
npm:nano  — blocked as a typosquat of "nan"   (nano is the Apache CouchDB client)
npm:args  — blocked as a typosquat of "arg"
```

If one bites you: `chainsaw why npm <name>` explains the verdict, and the
package still installs by calling your package manager directly. We would rather
list these than let you discover them mid-launch. Reports of others are welcome
in the issue tracker.

## Measured detection rate

Published numbers, with their scope stated plainly, because a catch rate without
a false-positive rate is marketing:

| | Real malware (597 samples) | Benign corpus (860 packages) |
|---|---|---|
| **Hard-block** | 46.2% | 0.81% false-block |
| **Any signal** (surfaces, does not block) | 69% | 5% |

**Read the caveats before quoting these.**

- They measure the **byte-level scanner**, which is the opt-in deep mode
  described above — *not* the default install path.
- The benign corpus is drawn from the same popularity seed lists the typosquat
  detector uses as its target index, so it systematically under-counts exactly
  the class of false positive listed in the section above. The 0.81% is a floor,
  not an estimate of what you will experience.
- It is a composite: npm measured 0/600, PyPI 7/260 = 2.69%.
- The 597 malware samples are a deterministic first-N slice of a public dataset,
  not a random sample.
- Detector changes were made against this corpus and then re-measured on it.

We do not claim zero false positives. We published a 0.00% once, it did not
reproduce on a wider corpus, and we retired it. Method and the full miss
breakdown are in the private monorepo today; moving the measurement harness into
this repository so the numbers are independently reproducible is tracked work.

## How it compares

Blocking at install time is not unique to us — JFrog Curation, Sonatype
Repository Firewall, Socket and Aikido all do a version of it, and several have
far deeper behavioural analysis than the free tier here. What is unusual about
this project:

- **It runs with no account and no server.** Your dependency list is not
  uploaded anywhere to get an answer.
- **The decision code is open.** You can read exactly why a package was refused,
  and disagree with it in a pull request.
- **It self-hosts.** The proxy tier runs in your own network, including
  air-gapped.

If you want maximum behavioural detection depth on npm today, look at Socket. If
you want a blocker whose logic you can audit and run offline, this is that.

## Beyond the laptop

Some commands are local; some are clients for the Chainsaw server and will tell
you so if no server is configured.

```sh
# Local, no server needed:
chainsaw doctor                 # package-manager wiring health
chainsaw pr-scan --base main    # CI check: flag deps added or upgraded in a PR
chainsaw scan-repo .            # find committed bypass config
chainsaw sbom diff a.json b.json

# Server-backed (needs `chainsaw auth login`):
chainsaw scan --path .          # full CVE + intelligence scan
chainsaw policy list            # org policy
chainsaw sbom export
```

`chainsaw --help` lists all 50 commands and marks which are which.

## Telemetry

Off until you opt in. On the first guard block in an interactive terminal you
get a consent prompt; **pressing Enter accepts**, so read it. When enabled it
sends anonymous usage plus **blocked package names** to
`https://chain305.com/api/telemetry/ingest` — and a blocked name could be an
internal package of yours. Clean installs are never sent.

`chainsaw telemetry status | on | off` at any time. Non-interactive runs (CI)
never prompt and never send.

## Libraries

This is also a set of Go packages, not just a CLI: the pull-through policy proxy
(`proxy/`, `policy/`, `policyengine/`), the intelligence and risk engines
(`intelligence/`, `risk/`, `typosquat/`, `malware/`, `depgraph/`, `sbom/`,
`provenance/`), and parsers for npm, PyPI, Go, Cargo, RubyGems, Maven, Gradle,
NuGet, Composer, Docker/OCI, Swift, CocoaPods, Dart, Hugging Face, APT and
Yum/DNF (`formats/`, `depparser/`).

```sh
go build ./cmd/chainsaw
go test ./...
```

Builds standalone with `GOWORK=off go build ./...`.

### Refusing when a signal cannot be evaluated

Fail-open is right for a workstation and wrong for some regulated and air-gapped
deployments. An opt-in, off-by-default gate lets you name data sources that must
be evaluable and refuse when one is not:

```sh
export CHAINSAW_COVERAGE_MODE=warn          # off (default) | warn | closed
export CHAINSAW_COVERAGE_REQUIRED=typosquat,malware
```

Start in `warn` — it reports what `closed` would have refused and refuses
nothing. `typosquat` always works offline; `malware` needs `guard update`;
`cve`, `registry_metadata` and `provenance` need the server and are never
available offline. Requiring one the guard cannot see refuses every install,
with a readable reason — intended, not a bug.

## Open core

Everything here is Apache-2.0 and runs standalone. There is no license check, no
plan gate, and no kill switch in this code — `guard update` fetches from
OpenSSF's repository, not from us.

The commercial control plane is a separate private module: the multi-tenant
server and dashboard, premium intelligence, SSO/SCIM, signed-policy bundles,
SIEM connectors, billing. Several CLI commands above are clients for it.

## Security

Vulnerability reports: [SECURITY.md](SECURITY.md).

Binaries ship with SHA-256 checksums over TLS. They are **not signed** —
Sigstore signing with SLSA provenance is pending a release-signer identity, and
the installer's signature check is opt-in and says so rather than pretending to
verify.

## Links

[Docs](https://docs.chain305.com) · [chain305.com](https://chain305.com) ·
[Contributing](CONTRIBUTING.md) · [Changelog](CHANGELOG.md)

Apache-2.0 — see [LICENSE](LICENSE).

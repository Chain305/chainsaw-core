# chainsaw

**Supply-chain enforcement for package installs — on the developer's machine, in
CI, at the registry proxy, at publish time, and at Kubernetes admission.** It
refuses known-malicious and typosquatted packages, known-vulnerable versions,
bad licences, and anything else your policy declines: **76 risk signals, 16
package ecosystems**, one policy language, five enforcement surfaces.

**The install-time guard runs entirely offline with no account, no server and no
daemon.** That is the part most people meet first, and it is what the demo below
shows. Everything broader — CVE and EPSS data, licence and provenance signals,
org policy, SBOM export, admission control — is served by the Chainsaw proxy or
control plane. This repository holds the open-core of *both*: the guard, the
detection engines, the policy engine, the registry proxy, and the parsers.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/chain305/chainsaw-core.svg)](https://pkg.go.dev/github.com/chain305/chainsaw-core)
[![Go 1.25+](https://img.shields.io/badge/go-1.25%2B-00ADD8.svg)](go.mod)

![Chainsaw refusing a typosquatted npm package at install time](assets/chainsaw-demo.gif)

<sub>Real session, real binary — only the keystroke timing is simulated. The
script is [`assets/record-demo.sh`](assets/record-demo.sh) and the raw cast is
[`assets/chainsaw-demo.cast`](assets/chainsaw-demo.cast), so you can replay or
re-record it yourself.</sub>

The block, as text:

```console
$ npm install expresss
chainsaw  ✗ blocked  npm:expresss — looks like a typosquat of "express" (distance 1, edit-distance, target rank #262)
chainsaw  if you have verified this package is real: chainsaw guard allow npm:expresss
chainsaw  ✗ refused at the install path — nothing was installed
```

Exit code `1`. Nothing was fetched, nothing was executed, nothing left the
machine. You typed `npm` — a shell function routed it through the guard first.
That verdict came from name analysis alone: no feed, no lookup, and no prior
sighting of `expresss` by anyone.

<details>
<summary>The same run, untrimmed — it is noisier than the excerpt above</summary>

Chainsaw states on every run which checks did *not* run. This is a fresh install
with no feed downloaded yet:

```console
$ npm install expresss
chainsaw  offline known-malicious + typosquat active; run `chainsaw guard update` for the full OpenSSF malicious-package set
chainsaw  behavioral byte scan not run; using name/feed/typosquat checks only (set CHAINSAW_GUARD_DEEP=1 or stage artifacts for byte-level coverage)
chainsaw  ✗ blocked  npm:expresss — looks like a typosquat of "express" (distance 1, edit-distance, target rank #262)
chainsaw  if you have verified this package is real: chainsaw guard allow npm:expresss
chainsaw  ✗ refused at the install path — nothing was installed
```

An interactive terminal adds two more lines the first time around: a one-off
telemetry notice ([Telemetry](#telemetry)) and, once you are past the first few
blocks, an occasional prompt to sign up. Neither appears in CI.

</details>

Everything here is Apache-2.0 and runs standalone — no licence check, no plan
gate, no phone-home. [What is and isn't in this repo](#open-core).

---

## Contents

**Understand it** — [What Chainsaw does](#what-chainsaw-does) ·
[Ecosystems](#ecosystems) · [Risk signals](#risk-signals) · [Policy and
enforcement](#policy-and-enforcement)

**Use it** — [Quickstart](#quickstart) · [How the guard
works](#how-the-guard-works) · [What gets checked](#what-gets-checked) ·
[CI](#ci) · [CLI reference](#cli-reference) · [Configuration](#configuration)

**Evaluate it** — [Scope and limits](#scope-and-limits) · [Measured
performance](#measured-performance) · [False
positives](#false-positives-and-the-escape-hatch) · [How it
compares](#how-it-compares)

**Build on it** — [Go libraries](#go-libraries) · [Open core](#open-core) ·
[Telemetry](#telemetry) · [Security](#security)

**Full reference** — [docs/](docs/) — [CLI](docs/cli.md) ·
[Configuration](docs/configuration.md) · [Ecosystems](docs/ecosystems.md) ·
[Signals](docs/signals.md) · [Policy](docs/policy.md) ·
[Measurement](docs/measurement.md)

---

## What Chainsaw does

Chainsaw evaluates a package and decides whether it may enter your environment.
The same decision engine runs at five points, so a rule you write once fires
wherever its inputs exist.

| Capability | Local CLI, no account | Server-backed |
|---|:---:|:---:|
| Typosquat detection (4 methods, embedded corpus) | ✅ | ✅ |
| Known-malicious index (OpenSSF, ~231k entries) | ✅ | ✅ |
| Byte-level behavioural scan (IOC + hidden-Unicode) | ✅ opt-in | ✅ |
| Blocking installs of npm/pip/go/cargo/gem | ✅ | ✅ |
| Lockfile and manifest diffing in CI (`pr-scan`) | ✅ | ✅ |
| Bypass-config detection (`scan-repo`) | ✅ | ✅ |
| GitHub Actions workflow risk (`scan-actions`) | ✅ | ✅ |
| SBOM diffing | ✅ | ✅ |
| Rego policy evaluation against a local bundle | ✅ | ✅ |
| CVE / CVSS / EPSS / KEV vulnerability data | — | ✅ |
| Licence, maintenance, provenance, capability signals | — | ✅ |
| Registry pull-through proxy (16 ecosystems) | — | ✅ |
| Org policy, exceptions, audit trail, findings triage | — | ✅ |
| SBOM / VEX export, provenance attestation chains | — | ✅ |
| Kubernetes admission control, publish-time gating | — | ✅ |
| Air-gapped signed intelligence bundles | — | ✅ |

"Server-backed" means a Chainsaw proxy or control plane — which you can run
yourself, including fully air-gapped, or use hosted. The client code for all of
it is in this repository; the multi-tenant server is the commercial module. See
[Open core](#open-core).

---

## Ecosystems

Three surfaces with three different reaches. Conflating them is the easiest way
to mis-state what Chainsaw covers, so they are listed apart.

| Surface | Reach |
|---|---|
| Offline install guard | **5 package managers** — npm, pip, Go, Cargo, RubyGems |
| Local lockfile parsing (`pr-scan`) | **12 manifest formats** across those 5 |
| Registry proxy + risk engine | **16 ecosystems** |

The sixteen: npm, PyPI, Maven, Cargo, Composer, RubyGems, NuGet, Go, Hugging
Face, CocoaPods, Swift, Pub (Dart), Docker/OCI, APT, Yum, DNF.

Coverage across them is **not uniform** — of 46 policy conditions, npm supports
40 fully and APT supports 12, because an upstream that publishes no maintainer
metadata cannot produce a maintainer signal. The matrix is compiled into the
binary ([`policy/proxy_matrix.go`](policy/proxy_matrix.go)), queryable at
`GET /api/policies/support-matrix`, and a rule skipped for this reason emits a
`policy.rule.skipped` audit event rather than silently never firing.

**Per-ecosystem numbers and every supported manifest format:
[docs/ecosystems.md](docs/ecosystems.md).**

---

## Risk signals

**76 signals are registered** ([`risk/registry.go`](risk/registry.go)), each
scored with a severity and a weight rather than a bare boolean.

| Category | Count | Examples |
|---|---:|---|
| Supply chain | 48 | known-malicious, typosquat (3 confidence tiers), install script fetches remote, manifest confusion, publisher changed, hidden Unicode, transitive malware, capability flags (network / shell / filesystem / eval), unsafe pickle opcodes, unpinned GitHub Action refs |
| Licence | 9 | copyleft, non-permissive, missing, unidentified, ambiguous classifier, changed from previous version |
| Vulnerability | 7 | critical / high / medium / low CVSS, EPSS high exploit probability, KEV known-exploited, fix available |
| Quality | 6 | checksum mismatch, minified code, version anomaly, declared MCP server / agent tool |
| Maintenance | 6 | abandoned repo, no recent release, single maintainer, very new package, very low downloads |

The full set is evaluated server-side. **The offline guard runs the subset
needing no external data**: typosquat, known-malicious, and — opt-in — the
byte-level checks.

**All 76 with severities and weights: [docs/signals.md](docs/signals.md).**

---

## Policy and enforcement

Policy is Rego (Open Policy Agent). One bundle, one input schema, and the same
decision call at every surface — a rule you write once fires wherever its input
fields are populated.

| Surface | Where it runs |
|---|---|
| `runtime` | package-manager install hook — the local guard |
| `pr` | GitHub Actions pull-request check |
| `proxy` | registry pull-through fetch |
| `publish` | pre-publish gate |
| `deploy` | Kubernetes admission webhook |

Evaluate a bundle locally, no server, no account:

```console
$ chainsaw policy gate proxy --bundle ./policies --input event.json
surface=proxy action=allow violations=0 bundle=aaf8cc651c8d
```

**The registry proxy** is the enforcement point a shell wrapper cannot be: it
covers every client including CI runners and machines you do not administer, and
cannot be routed around by calling the real binary directly. It runs in your own
network — `proxy/`, `policy/` and `policyengine/` here are its open core.

**Air-gapped**, intelligence ships as a Sigstore-signed bundle with per-file
content hashes, verified before it is trusted (`chainsaw bundle verify`).

Org policy management, monitor-mode rollout with would-block previews, scoped
exceptions with expiry, Kubernetes admission and the audit trail are
server-backed. **Details: [docs/policy.md](docs/policy.md).**

---

## Quickstart

```sh
curl -fsSL https://chain305.com/install.sh | sh
```

<details>
<summary>Other install methods</summary>

```sh
# Go toolchain
go install github.com/chain305/chainsaw-core/cmd/chainsaw@latest

# From source
git clone https://github.com/Chain305/chainsaw-core && cd chainsaw-core
go build ./cmd/chainsaw
```

Prebuilt binaries: macOS, Linux and Windows on `amd64` and `arm64`, statically
linked (`CGO_ENABLED=0`).

</details>

Wire it into your shell — one command, idempotent, safe to re-run:

```sh
chainsaw guard init --install
```

That appends a single `eval` line to your shell rc file. Use `--dry-run` to see
the exact file and line first, or skip it entirely and put
`eval "$(chainsaw guard init zsh)"` in your rc yourself. `bash`, `zsh`, `fish`,
`powershell` and `pwsh` are supported; on PowerShell the activation line is
`chainsaw guard init powershell | Invoke-Expression` and `--install` writes to
your PowerShell profile.

`cmd` is print-only. cmd.exe has no startup file, and doskey macros are not
expanded inside `.bat`/`.cmd` scripts — so `--install cmd` refuses instead of
persisting a wiring that would miss every scripted install. On Windows, either
use PowerShell or call the guard explicitly: `chainsaw npm install <package>`.

Then just use your package manager normally:

```sh
npm install expresss         # typosquat — refused
npm ci                       # every package in the resolved lockfile
pip install -r req.txt       # every pinned requirement
chainsaw why npm expresss    # explain any verdict
chainsaw doctor              # read-only: what's wired, what isn't
```

### First run in a real terminal

After your first block you get two prompts. **Both default to Yes, so a blind
Enter accepts them.** Saying no to either costs you nothing — the offline
typosquat check is unaffected.

| Prompt | What it does |
|---|---|
| *Download the full OpenSSF malicious-package feed?* | ~40MB from GitHub, replaces the 11-entry embedded floor with ~231k entries. Takes a minute or two. Same as running `chainsaw guard update`. |
| *Share detection signals?* | Turns on telemetry — see [Telemetry](#telemetry) for exactly what that sends. |

`export CHAINSAW_OFFLINE=1` skips both. **Neither prompt ever appears in a
non-interactive shell**, so CI never fetches and never sends.

---

## How the guard works

This section is about the local, offline install guard. There is no daemon, no
background process, and no network call on the default path. `guard init` prints
seven lines of shell:

```console
$ chainsaw guard init zsh
# chainsaw install guard — https://chain305.com
npm() { command chainsaw npm "$@"; }
pip() { command chainsaw pip "$@"; }
pip3() { command chainsaw pip "$@"; }
go() { command chainsaw go "$@"; }
cargo() { command chainsaw cargo "$@"; }
gem() { command chainsaw gem "$@"; }
```

That is the entire integration. It is recursion-safe by construction: chainsaw
resolves the real `npm` through `exec.LookPath`, and a shell function cannot
shadow a PATH lookup — so `npm` (function) → `chainsaw npm` → real `npm` binary.

```
  you type: npm install expresss
        │
        ▼
  shell function ──► chainsaw npm install expresss
                            │
                            ├─ 1. parse the verb + coordinates      (no network)
                            ├─ 2. known-malicious index             (no network)
                            ├─ 3. typosquat detector                (no network)
                            ├─ 4. local allowlist                   (no network)
                            │
                     ┌──────┴──────┐
                  clear          blocked
                     │              │
                     ▼              ▼
              exec real npm    exit 1, nothing installed
```

**The known-malicious index.** 11 curated historic incidents are compiled into
the binary as a floor (`event-stream`/`flatmap-stream`, `ua-parser-js` and
similar). `chainsaw guard update` replaces that floor with the full OpenSSF
malicious-packages set (~231k entries), cached on disk and read offline
thereafter. The feed comes from
[OpenSSF's repository](https://github.com/ossf/malicious-packages), not from us.

**The typosquat detector.** Four methods — `edit-distance`, `homoglyph`,
`combosquat` and `reorder` — run against an embedded popularity corpus. No feed,
no network, and crucially no prior sighting of the attacking name: a brand-new
typosquat is on nobody's blocklist, but it is still one edit away from `lodash`.

Corpus depth differs by ecosystem, and it matters:

| Ecosystem | Embedded corpus |
|---|---|
| npm | 5,000 names |
| PyPI | 3,000 names |
| Go | 244 modules |
| Cargo | 177 crates |
| RubyGems | 158 gems |

Corpus membership grants an exact-match exemption, so it is a trust decision. It
rides reviewed data — a seed PR in this repo, or a Sigstore-verified bundle —
never a live per-client fetch, whose ranking would be attacker-gameable.

Config, the local allowlist and the cached feed are three plain files you can
read, diff and back up; paths are in
[docs/configuration.md](docs/configuration.md#where-state-lives).

---

## What gets checked

Still the local guard. (For the wider server-backed surfaces, see [What Chainsaw
does](#what-chainsaw-does).)

**Guarded verbs.** `npm install|i|add|ci`, `pip install`, `cargo install|add`,
`gem install`, `go get`, `go mod download`. Every other invocation delegates
straight to the real tool, untouched.

| You run | Chainsaw evaluates |
|---|---|
| `npm install <name>` | that coordinate only — **not** its dependency tree |
| `npm install` / `npm ci` | every package in the resolved lockfile |
| `pip install -r req.txt` | every pinned requirement |
| `go mod download` | everything in `go.sum` |

The verb is located defensively: a chainsaw flag can never swallow an install
verb as its value and silently downgrade the command to an unscanned passthrough
— that path fails closed and is covered by tests.

---

## CI

A GitHub Action ships from this repository. It diffs the dependencies a PR adds
or upgrades and comments on the PR; flip `mode: block` and wire it as a required
status check when you're ready to enforce.

```yaml
# .github/workflows/chainsaw.yml
name: Chainsaw Guard
on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  pull-requests: write

jobs:
  chainsaw-preflight:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0        # required: pr-scan needs the base commit to diff against

      - uses: Chain305/chainsaw-core/enforcement/github-actions@action-v1
        with:
          mode: warn            # warn | block
          scan-repo: true
```

`pr-scan` exit codes, so you can gate on exactly what you mean:

| Code | Meaning |
|---|---|
| `0` | clean |
| `10` | a dependency was added or upgraded (fires on most PRs — opt in deliberately) |
| `20` | a blocking finding |
| `30` | a manifest failed to parse |

Full inputs: [`enforcement/github-actions/action.yml`](enforcement/github-actions/action.yml).

---

## CLI reference

49 top-level commands. Full table, marked local vs server-backed, plus global
flags and exit codes: **[docs/cli.md](docs/cli.md)**.

The ones you need on day one:

```sh
chainsaw guard init --install   # route npm/pip/go/cargo/gem through the guard
chainsaw why npm <pkg>          # explain any verdict
chainsaw guard allow <coord>    # clear a false typosquat block
chainsaw doctor                 # what's wired, what isn't
chainsaw pr-scan --base main    # CI: flag deps added or upgraded in a PR
chainsaw features               # what this binary can do
```

---

## Configuration

Environment variables, on-disk state locations, and the opt-in fail-closed
coverage gate: **[docs/configuration.md](docs/configuration.md)**.

The two most load-bearing:

```sh
export CHAINSAW_OFFLINE=1        # never touch the network; suppresses both first-run prompts
export CHAINSAW_COVERAGE_MODE=warn   # off (default) | warn | closed — refuse when a signal is unavailable
```

---

## Scope and limits

Read this before you decide whether it is useful to you. Being wrong about scope
is worse than being narrow.

**`npx` and `npm exec` are not covered.** The download-and-execute path is not
guarded today.

**It is bypassable, on purpose.** The shell hook wraps your package manager; a
determined developer types `/usr/local/bin/npm install` and routes around it.
Our own test suite asserts exactly that
([`cli/bypass_matrix_test.go`](cli/bypass_matrix_test.go)). Closing the gap is a
registry-proxy and lockfile-pinning property, not something a local wrapper can
promise — that is exactly what the [registry proxy](docs/policy.md#registry-proxy) is for.
**Treat the local guard as a seatbelt on your own machine, not a control you can
attest to an auditor.**

**It fails open.** If a signal cannot be evaluated it prints a notice and lets
the install proceed. A thin feed must never break `npm install`. That default is
changeable — see [fail-closed coverage](docs/configuration.md#refusing-when-a-signal-cannot-be-evaluated).

**Byte-level analysis is opt-in and off by default.** It needs either a staged
artifact directory (`CHAINSAW_GUARD_ARTIFACT_DIR` — you supply the archives,
still offline) or `CHAINSAW_GUARD_DEEP=1`, which fetches the archive over the
network and therefore waives the offline guarantee. Deep fetch covers **npm and
cargo only, and only for a version-pinned install**: `chainsaw npm install foo`
gets no byte scan even with deep mode on.

**CVE lookup, registry metadata and provenance need the server.** Never
available offline, in any mode.

The binary tells you on every run which checks did **not** run:

```
chainsaw  behavioral byte scan not run; using name/feed/typosquat checks only (set CHAINSAW_GUARD_DEEP=1 or stage artifacts for byte-level coverage)
```

**The offline claim is testable, and we test it adversarially.** Run the guard
under a network-denying sandbox and every block fires identically. Nothing on
the default path requires egress. What the tool does on a TTY is *ask* whether
you want the feed.

---

## Measured performance

A catch rate without a false-positive rate is marketing. Both are published,
and the typosquat harnesses ship in this repository.

**Name-level typosquat — the default install path:**

| | |
|---|---|
| False-block rate | **1.02%** on 24,206 real names held out of the detector's own seed index |
| Still refused | 247 of 24,206 |
| Recall cost of that reduction | **8.2%** of the typosquat lane's blocks on the OpenSSF feed (92 of 1,122) |

Quoting either number without the other misrepresents the trade.

**Byte-level scanner — the opt-in deep mode, not the default path:**

| | Real malware (597 samples) | Benign corpus (860 packages) |
|---|---|---|
| Hard-block | 46.2% | 0.81% false-block |
| Any signal (surfaces, does not block) | 69% | 5% |

**We do not claim zero false positives.** We published a 0.00% once, it did not
reproduce on a wider corpus, and we retired it.

Every caveat that belongs with these numbers — what the corpora are, why 0.81%
is a floor rather than an estimate, the npm 0/600 vs PyPI 2.69% split, that
detector changes were made against this corpus and then re-measured on it, and
what is not yet independently reproducible — is in
**[docs/measurement.md](docs/measurement.md)**. Please read it before quoting
any of the above.

---

## False positives, and the escape hatch

Name-similarity inference refuses legitimate packages. It is a real cost, and it
is designed for rather than hand-waved: **a block with no way forward gets the
guard uninstalled**, so every refusal the local allowlist can clear prints the
way out on the same screen.

Real packages still refused include `npm:jsdoc` (against `jsdom`), `npm:stylus`
(against `stylis`), `npm:tslint` (against `eslint`) and the whole
`pypi:nvidia-*-cu11` family. The class is narrow, not gone.

If one bites you, clear that single coordinate on this machine — offline,
permanently, without turning the guard off:

```sh
chainsaw guard allow npm:jsdoc            # clear one false typosquat block
chainsaw guard allow --list               # what this machine has allowed, and why
chainsaw guard allow --remove npm:jsdoc   # undo it
```

**A waiver is scoped and never silent.** It clears typosquat verdicts only —
known-malicious feed hits and byte-level checks are refused by `guard allow` and
keep blocking. Every install of a waived coordinate reprints the suppressed
verdict and how to undo it, and that line survives `--quiet`, so a stale or
planted entry shows up in the CI log rather than only under `guard allow --list`:

```
chainsaw  ~ waived  npm:jsdoc — looks like a typosquat of "jsdom" (distance 1, edit-distance, target rank #451) (a local allowlist entry cleared this — undo: chainsaw guard allow --remove npm:jsdoc)
```

A waiver deliberately does **not** enter the local `chainsaw why` ring or the
telemetry stream. It was not a refusal, so recording it as one would report a
block that never happened and corrupt the blocked counts — and a waived name is
more sensitive than a blocked one, not less.

`chainsaw why npm <name>` explains any verdict:

```console
$ chainsaw why npm expresss
Package:    npm/expresss@(unpinned)
Outcome:    BLOCKED (local install guard)
Severity:   typosquat-high
Reason:     looks like a typosquat of "express" (distance 1, edit-distance, target rank #262)
Source:     this machine's offline guard (known-malicious floor + typosquat)
```

Why the detector was narrowed, and what that cost in recall:
[docs/measurement.md](docs/measurement.md). Reports of other false blocks are
welcome in the issue tracker.

---

## How it compares

Blocking at install time is not unique — JFrog Curation, Sonatype Repository
Firewall, Socket and Aikido all do a version of it, and the commercial engines in
this category run deeper behavioural analysis than the byte scanner here. What is
unusual about this project:

- **No account, no server, no daemon.** Your dependency list is not uploaded
  anywhere to get an answer. The default path makes zero network calls.
- **The deciding code is open.** Every verdict in this README traces to source
  in this repository — you can read why a package was refused, and disagree with
  it in a pull request.
- **It self-hosts.** The proxy tier runs in your own network, including
  air-gapped.
- **The numbers come with their caveats attached**, and the harnesses ship with
  the code.

---

## Go libraries

This is a library set, not just a CLI. Everything below is importable under
`github.com/chain305/chainsaw-core/…`:

| Area | Packages |
|---|---|
| Pull-through policy proxy | [`proxy/`](proxy) [`policy/`](policy) [`policyengine/`](policyengine) |
| Detection & risk | [`typosquat/`](typosquat) [`malware/`](malware) [`risk/`](risk) [`intelligence/`](intelligence) [`trustscore/`](trustscore) [`iocscan/`](iocscan) [`hiddenunicode/`](hiddenunicode) |
| Supply chain | [`sbom/`](sbom) [`provenance/`](provenance) [`attestation/`](attestation) [`depgraph/`](depgraph) [`kev/`](kev) |
| Ecosystem parsers | [`formats/`](formats) [`depparser/`](depparser) |

Parsers cover npm, PyPI, Go, Cargo, RubyGems, Maven, Gradle, NuGet, Composer,
Docker/OCI, Swift, CocoaPods, Dart, Hugging Face, APT and Yum/DNF.

```sh
go build ./cmd/chainsaw
go test ./...
GOWORK=off go build ./...      # builds standalone, outside the monorepo workspace
```

Start at [pkg.go.dev](https://pkg.go.dev/github.com/chain305/chainsaw-core).

---

## Open core

Everything in this repository is **Apache-2.0 and runs standalone**. There is no
license check, no plan gate, and no kill switch in this code. `guard update`
fetches from OpenSSF's repository, not from us. `chainsaw features` will tell you
exactly what your binary can do:

```console
$ chainsaw features
Edition: community

Local capabilities
  ✓  Offline install-time guard
  ✗  Enterprise build extensions
```

**What lives in the separate commercial module:** the multi-tenant server and
dashboard, premium intelligence, SSO/SCIM, signed-policy bundles, SIEM
connectors, and billing. The control-plane commands in the reference above are
clients for it — they are open source clients for a closed server, which is why
they ship here and tell you when no server is configured.

**What that means in practice:** the guard, the detectors, the parsers, the
proxy and every verdict you have read about here are yours under Apache-2.0,
today, with no strings. The commercial tier is for teams that need one place to
see and enforce across many machines.

---

## Telemetry

**Off until you opt in.** On the first guard block in an interactive terminal you
get a consent prompt, and **pressing Enter accepts it** — so read it.

When enabled it sends anonymous usage plus **blocked package names** to
`https://chain305.com/api/telemetry/ingest`. A blocked name could be an internal
package of yours; that is the honest reason to think about it before saying yes.
Clean installs are never sent.

```sh
chainsaw telemetry status | on | off
```

Non-interactive runs (CI) never prompt and never send. `CHAINSAW_TELEMETRY_DISABLED=1`
forces it off. `chainsaw telemetry reset` forgets the install id.

---

## Security

Vulnerability reports: [SECURITY.md](SECURITY.md).

Binaries ship with SHA-256 checksums over TLS. They are **not signed** — Sigstore
signing with SLSA provenance is pending a release-signer identity, and the
installer's signature check is opt-in and says so rather than pretending to
verify. In a supply-chain security tool that gap is worth naming plainly: verify
the checksum, or build from source, until it closes.

---

[Docs](https://docs.chain305.com) · [chain305.com](https://chain305.com) ·
[Contributing](CONTRIBUTING.md) · [Changelog](CHANGELOG.md)

Apache-2.0 — see [LICENSE](LICENSE).

# CLI reference

49 top-level commands. `chainsaw <command> --help` gives flags for any of them.

Commands marked **local** need no account and no server. The rest are clients
for a Chainsaw control plane and each says so when none is configured — they are
open-source clients for a closed server, which is why they ship here.

## Guard (install-time) — all local

| Command | |
|---|---|
| `npm` `pip` `go` `cargo` `gem` | Run the package manager through the guard |
| `guard init` | Print (or `--install`) the shell functions that do that automatically |
| `guard update` | Fetch the full known-malicious set for offline use |
| `guard allow` | Clear a false typosquat block, locally and permanently |
| `guard status` | Local guard activity, privacy state, account sync |
| `install-hook` / `uninstall-hook` | Wire chainsaw into a package manager's own config, or remove it |
| `cargo-credentials` | Cargo credential-provider helper |

`guard init` supports `bash`, `zsh` and `fish`. `--install` appends the
activation line to your shell rc file idempotently; `--dry-run` shows the target
file and the exact line without writing.

## Target and scan

| Command | |
|---|---|
| `why` | **local** — explain why a package install was blocked |
| `pr-scan` | **local** — diff manifests, flag added or upgraded dependencies |
| `scan-repo` | **local** — scan a repo tree for chainsaw-bypass config files |
| `scan-actions` | **local** — scan GitHub Actions workflows for supply-chain risk |
| `sbom` | **local** for `diff`; `export` is server-backed |
| `scan` | Scan packages for vulnerabilities |
| `scan-remote` | Upload one lockfile, stream the aggregated report |

## Policy and enforcement

| Command | |
|---|---|
| `policy eval` | **local** — evaluate a Rego bundle against a JSON input fixture |
| `policy gate <surface>` | **local** — run a decision for one enforcement surface |
| `policy` | Manage release policies (create, simulate, flip-to-block, import/export) |
| `admission` | Kubernetes admission webhook helpers, incl. shadow-mode soak gate |
| `risk-weights` | Show, preview and apply per-signal risk-weight overrides |

`policy eval` and `policy gate` read a bundle and an input file from disk and
need nothing else. See [policy.md](policy.md).

## Intelligence

| Command | |
|---|---|
| `intel` | Query the v1 risk-intelligence API (package, scan, signals, health) |
| `pkg` | Package discovery and inspection |
| `deps` | Dependency commands |
| `affected` | Which repos, clients and SBOMs contain a package or CVE |
| `verify` | Verify a package's provenance attestation chain |

`chainsaw intel signals` lists the registered signals grouped by category. The
full set is in [signals.md](signals.md).

## Audit and findings

| Command | |
|---|---|
| `finding` | Triage lifecycle: ack / snooze / resolve / suppress / reopen |
| `exception` | Scoped allow-rules with expiry (`create`, `renew`, `delete`, `list`) |
| `audit` | Audit event commands |
| `report` | Cross-org reports derived from install events |

## Config and auth

| Command | |
|---|---|
| `setup` | Interactive first-time wizard |
| `auth` | Log in / out — `--device` for headless, CI and AI-agent paths |
| `introduce` | **local** — mental models, personas and vocabulary shared by every surface |
| `onboard` · `onboarding` | Record and inspect onboarding state |
| `bundle` | **local** — verify the offline intelligence bundle |
| `org` | Manage the active organization (delete behind a simulate-then-confirm gate) |
| `repo` | Manage upstream proxies and registries |
| `team` · `codeowners` | Repo→team ownership mappings, CODEOWNERS sync |
| `token` | API tokens (PATs and AI-agent credentials) |
| `status` | Server, org and authentication status |
| `undo` | Roll back the most recent agent action, or one by id |

## Debug and diagnostics

| Command | |
|---|---|
| `doctor` | **local** — diagnose package-manager wiring and install health |
| `features` | **local** — edition capabilities and server entitlements |
| `coverage` | **local** — inspect install-coverage measurements (opt-in) |
| `telemetry` | **local** — inspect or control local analytics |
| `version` | **local** — version, commit, build date, edition |
| `completion` | **local** — shell autocompletion script |
| `logs` | Inspect chainsaw-proxy logs (kubectl wrapper; `--stdin` for non-k8s) |

## Global flags

| Flag | |
|---|---|
| `--json` / `--format table\|json` | Output format (`--json` is sugar for `--format=json`) |
| `-o, --output <file>` | Write results to a file; logs and progress stay on stderr |
| `-q, --quiet` | Suppress progress and chatter |
| `-v, --verbose` | Extra diagnostic detail on stderr |
| `--no-color` | Disable coloured output |
| `--server <url>` | Override the configured server |
| `--token <token>` | Override the configured auth token |
| `--org <id>` | Local-only org id for display, `org delete` targeting and SBOM/VEX metadata — it is **not** sent to the server; your org comes from the token identity |

`--quiet` suppresses chatter only. Results and block reasons are always emitted,
including waived-verdict notices, so a suppressed block still shows up in a CI
log.

## Exit codes

The install guard exits `1` on a block. `pr-scan` uses:

| Code | Meaning |
|---|---|
| `0` | clean |
| `10` | a dependency was added or upgraded (fires on most PRs — opt in deliberately) |
| `20` | a blocking finding |
| `30` | a manifest failed to parse |

`policy eval` and `policy gate` share one exit-code vocabulary so the same
CI-status mapping works at every surface. `bundle verify` returns `0` verified
and fresh, `1` verified but stale, `2` verification failure.

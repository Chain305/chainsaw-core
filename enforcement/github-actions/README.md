# Chainsaw Guard — GitHub Action

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](#license)

> Consume it pinned to a commit SHA:
> `uses: Chain305/chainsaw-core/enforcement/github-actions@4b6142b568b8b8aa34364b20fbcb46c7be3b9532 # v0.22.115`.
> Since v0.22.116 pr-scan blocks every action referenced by tag or branch, this
> one included, so `@action-v1` fails the check it installs. The SHA above is
> the open-core commit carrying the v0.22.115 action. `action-v1` itself was
> moved on 2026-10-21 to `action-v1.0.3` (open-core `0b078db`, CLI v0.22.119);
> before that it was on `action-v1.0.2` (open-core `3930bf0`, CLI v0.22.116)
> from 2026-10-18, and on `action-v1.0.1` (CLI v0.22.100) before that.
> It is **not** on the GitHub Marketplace yet — a Marketplace listing requires
> `action.yml` at a repository root, and this action ships from a subdirectory
> of the open-core repo.

**Block vulnerable, typosquatted, malicious, or unlicensed packages in your pull requests before they reach `main`.** Chainsaw Guard runs on every PR, inspects your lockfiles and package-manager configuration, and fails the build — or just comments — when something unsafe slips in.

---

## 30-second quickstart

1. Drop this file at `.github/workflows/chainsaw.yml` in your repo.
2. Commit it on a branch and open a PR.
3. Watch Chainsaw post a findings comment on the PR. That's it.

```yaml
name: Package security scan
on: [pull_request]

permissions:
  contents: read
  pull-requests: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
        with:
          # Required: pr-scan diffs against the PR's merge base, which a
          # shallow clone does not contain. Without this the pr-scan leg
          # silently scans nothing.
          fetch-depth: 0
      - uses: Chain305/chainsaw-core/enforcement/github-actions@4b6142b568b8b8aa34364b20fbcb46c7be3b9532 # v0.22.115
        with:
          mode: warn   # warn | block
```

No server, no token, no account required for the default `warn` mode. When you're ready to enforce on a required status check, flip `mode: block` and point `server` at your Chainsaw control plane.

---

## Inputs

| Name | Description | Default | Required |
| --- | --- | --- | --- |
| `mode` | `warn` posts a PR comment; `block` fails the job on any policy hit (use as a required status check). | `warn` | no |
| `server` | Chainsaw control-plane URL. Leave empty for offline mode (bundled policy pack). | `""` | no |
| `token` | `CHAINSAW_TOKEN` secret. Required only when `server` is set. | `""` | no |
| `attest` | POST the doctor report to `/api/attestations` so the compliance dashboard sees this runner. | `true` | no |
| `scan-repo` | Run `chainsaw scan-repo` to detect committed bypass files (`.npmrc`, public `--index-url`, raw Docker `FROM`, etc.). | `true` | no |
| `version` | CLI version to install. `latest` or a pinned tag (e.g. `v0.16.0`). | `latest` | no |
| `comment-on-pr` | Post a summary comment on pull requests. Requires `pull-requests: write`. | `true` | no |

## Outputs

| Name | Description |
| --- | --- |
| `findings` | Total findings from `scan-repo` (bypass files, policy hits, lockfile drifts). `0` means clean. |
| `policy-hits` | Subset of `findings` that matched a blocking rule. Drives the exit code in `mode: block`. |
| `report-path` | Absolute path to the JSON report. Upload as an artifact for triage or SARIF conversion. |
| `exit-code` | Raw exit from `chainsaw doctor --strict`: `0` clean, `10` drift/bypass, `30` runner can reach public registries, `40` unsupported package manager. |

Example — fail only when blocking policies hit, but always upload the report:

```yaml
- id: guard
  uses: Chain305/chainsaw-core/enforcement/github-actions@4b6142b568b8b8aa34364b20fbcb46c7be3b9532 # v0.22.115
  with:
    mode: warn

- uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4
  if: always()
  with:
    name: chainsaw-report
    path: ${{ steps.guard.outputs.report-path }}

- if: steps.guard.outputs.policy-hits != '0'
  run: |
    echo "::error::Chainsaw blocked ${{ steps.guard.outputs.policy-hits }} package(s)"
    exit 1
```

---

## How it works

- Installs the `chainsaw` CLI from the public release host (no private-registry auth).
- Runs `chainsaw scan-repo` over the checked-out tree to detect bypass files and unpinned dependencies.
- Runs `chainsaw doctor --strict` to verify the runner's package-manager config hasn't drifted from policy.
- When `server` is set, POSTs an attestation so the control-plane dashboard records the runner.
- Posts a single collapsible comment on the PR summarizing findings and a one-line fix hint.

Runner support: Linux (`ubuntu-*`) and macOS (`macos-*`) runners are fully supported. Windows runners are not currently supported — run the action inside an `ubuntu-latest` matrix leg if your repo ships Windows code.

---

## Advanced

- **Deeper coverage with the inline proxy.** The GitHub Action catches what's already in the tree. For install-time protection against malicious packages that never hit your lockfile, point your package managers at the [Chainsaw inline proxy](../../docs/) and enforce at fetch time.
- **Organization-level policies.** Define allow/block/quarantine rules once in the control plane and every runner inherits them. Per-repo overrides live in `.chainsaw.yaml`.
- **SSO + audit trail.** Connect your IdP (Okta, Entra ID, Google Workspace) so every attestation is signed with a verified identity, and every bypass flows through the compliance dashboard.

See the [main Chainsaw docs](../../docs/) for the full enterprise feature set.

---

## License

The Action wrapper in this directory — `action.yml`, the example workflows, the marketplace listing copy, and the helper scripts — is licensed under the Apache License, Version 2.0. See [`enforcement/github-actions/LICENSE`](../../enforcement/github-actions/LICENSE).

The Chainsaw binary that the Action downloads and runs (`chainsaw`, `chainsaw-proxy`) is closed-source commercial software governed by your Chainsaw subscription, **not** by Apache-2.0.

Chainsaw and the Chainsaw logo are trademarks of the project maintainers.

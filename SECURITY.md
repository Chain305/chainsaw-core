# Security Policy

This document covers the open-core Chainsaw module: the `chainsaw` CLI and
the embeddable proxy/policy/intelligence libraries in this repository. The
enterprise control plane (multi-tenant server, dashboard, premium
intelligence, SSO/SCIM, hardening wizard, policy signing, SIEM) lives in a
separate private module and is reported separately — see "Scope" below.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** by email to
**security@chain305.com**. Do **not** open a public GitHub issue, draft a
public PR, or discuss the issue in chat or social media before a fix has
shipped.

Encrypted email is preferred. A maintainer PGP key will be published here
once provisioned; until then, please send the report unencrypted and we
will coordinate a secure channel on first reply. (PGP key: TBD.)

A useful report includes:

- A description of the issue and the affected component.
- The Chainsaw version (`chainsaw version`) and how you're running it.
- A minimal reproduction or proof-of-concept.
- Any known mitigations or workarounds.
- Whether you would like public credit in the eventual advisory.

## Scope

In-scope for this repository:

- The `chainsaw` CLI (`cmd/chainsaw`) and its subcommands.
- The pull-through policy proxy (`proxy/`) and the policy engine
  (`policy/`, `policyengine/`) used as libraries.
- The supply-chain intelligence signals (`intelligence/`, `risk/`,
  `typosquat/`, `malware/`, `depgraph/`, `sbom/`, `provenance/`) and the
  ecosystem format parsers (`formats/`, `depparser/`).

Out-of-scope here (report separately to **security@chain305.com**, noting
it's an enterprise report):

- The multi-tenant server, dashboard, premium intelligence, SSO/SCIM,
  hardening wizard, signed-policy bundles, SIEM, and billing — these ship
  from the private enterprise module.

Also out-of-scope: third-party upstreams that Chainsaw proxies (please
report those to the upstream project), and self-built forks that diverge
from mainline.

## Security posture — what the local guard does and does not guarantee

Read this before filing a report about the guard "letting something
through". Several of these behaviours are deliberate.

**The workstation guard fails open by default.** `chainsaw npm/pip/go …`
evaluates a package against the signals it can compute locally and, when a
signal cannot be evaluated — feed absent or stale, artifact bytes
unavailable, server preflight unreachable, parse error — it prints a notice
and lets the install proceed. Breaking `npm install` on our own inability to
look is a worse default for a developer workstation than allowing. A report
that a signal did not run is a bug; a report that an *unevaluable* signal
did not block is expected behaviour.

**Fail-closed is available, and it is opt-in.** `CHAINSAW_COVERAGE_MODE`
(`off` | `warn` | `closed`) with `CHAINSAW_COVERAGE_REQUIRED` names data
sources that must be evaluable, and refuses the package when one is not.
`off` is the default, and with the variable unset no code path changes. See
the README for the source names and for what an offline guard can honestly
attest. `CHAINSAW_COVERAGE_BREAK_GLASS=1` is a documented, loudly-logged
escape hatch — its existence is intentional, not a bypass finding.

**The guard is defence-in-depth, not proof.** It runs as a shell shim on a
machine the developer controls, so it can be uninstalled, bypassed by
invoking the package manager directly, or run with the break-glass variable
set. It is not, and does not claim to be, a tamper-proof control. The
enforcement chokepoints an organisation can actually rely on are the
registry proxy, CI, publish, and K8s admission. "A developer can bypass the
local guard" is a documented property, not a vulnerability.

**Refusals on a bare `chainsaw guard` install are best-effort by design.**
The offline path ships an embedded known-malicious floor and typosquat
corpus; the full OpenSSF malicious-packages set arrives only after the
opt-in `chainsaw guard update`. A package missing from the offline seed is a
coverage gap, not a control failure.

Genuinely in scope for a security report: a package that the guard *did*
evaluate and should have refused but allowed; a way to make an
explicitly-configured `CHAINSAW_COVERAGE_MODE=closed` posture silently
degrade to open; a path that reads or transmits data off the machine on the
default offline path; and anything that lets a proxied artifact be served or
executed without the checks that were configured to run.

### Notable fail-closed defaults

- **Swift `github_convention` is off.** The SE-0292 `scope.name` →
  `github.com/<scope>/<name>.git` auto-translator *guesses* a repository
  from a package identifier, and nothing binds the two — so with it enabled
  and unconstrained, whoever registers that GitHub org has their code served
  as the legitimate package. It is off by default, requires a non-empty
  `swift.github_org_allowlist` when on (an empty or all-blank list denies),
  and the unconstrained combination is refused at construction rather than
  downgraded. The supported way to resolve Swift packages is the explicit
  `swift.identifier_map_path`.
- **`CHAINSAW_OFFLINE` is honoured by the Swift git fallback**, which
  refuses network git operations when offline mode is in force.
- **`CHAINSAW_ALLOW_INSECURE_TLS` is off by default.** Until it is set,
  per-remote TLS skip-verify flags are ignored and upstream certificates are
  always validated.

## Disclosure window

We follow a **90-day coordinated disclosure** window by default, measured
from our acknowledgement of the report. We may request a short extension
for complex fixes; we will not extend silently. If we cannot ship a fix in
that window, we will work with you on a public advisory regardless.

## Response timeline

- **Acknowledgement:** within **72 hours** of receipt (typically faster
  during business days).
- **Status updates:** at least **once per week** while the report is open,
  including when we are blocked or waiting on you.
- **Fix and advisory:** scheduled jointly with the reporter once severity
  and a candidate fix are understood.

## Safe-harbour

We will not pursue legal action against good-faith security research that
respects this policy: stays within the scope above, avoids privacy
violations, destruction of data, and degradation of service to other
users, and gives us a reasonable chance to remediate before disclosure.

## Verifying a release

> **Pre-GA:** no public release has been cut yet and the `Chain305`
> Sigstore signer identity is not yet provisioned, so the signed-release
> artefacts and the `cosign`/`slsa-verifier` commands below are not available
> today. Until the first signed release ships, install via the hosted
> one-liner (`curl -fsSL https://chain305.com/install.sh | sh`, which verifies
> the published SHA-256 checksum) or `go install`, and track the signing
> cutover in the release notes.

Once published, every tagged release of this module ships:

- **SLSA Build L3 provenance** (`multiple.intoto.jsonl`) for every CLI
  binary, generated by the [slsa-github-generator] reusable workflow.
- **Sigstore-signed binaries** (one `<binary>.sigstore` bundle per
  artifact), signed via cosign keyless OIDC against the GitHub Actions
  workflow identity.

Verification commands — run these before deploying a release.

> **Pin the workflow, not just the repository.** This document previously
> pinned `^https://github\.com/chain305/chainsaw-core/` — no workflow path,
> so ANY workflow in this repository satisfied it. `chainsaw-core` is
> public, so anyone can open a pull request; a workflow that runs on
> `pull_request` with `id-token` permission would mint a certificate that
> passes such a check. The org casing was wrong too (`chain305` vs
> `Chain305`), and Fulcio SANs are matched exactly.
>
> The identity below is a pre-GA placeholder: release signing for this
> repository is not provisioned yet, so the command fails closed rather
> than accepting anything. Pinned by `TestSigningIdentityPinsAWorkflow`.

```sh
# Verify the cosign signature
cosign verify-blob \
  --bundle chainsaw_<version>_linux_amd64.sigstore \
  --certificate-identity-regexp '^https://github\.com/Chain305/chainsaw/\.github/workflows/release\.yml@refs/tags/v.+$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  chainsaw_<version>_linux_amd64

# Verify SLSA Build L3 provenance
slsa-verifier verify-artifact \
  --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/chain305/chainsaw-core \
  chainsaw_<version>_linux_amd64
```

The CLI can also verify any package it proxies, end-to-end:

```sh
chainsaw verify npm leftpad 1.0.0
```

prints the SLSA level, builder identity, source repo + commit, and Rekor
entry URL. Exits non-zero on any failure so CI gates work.

[slsa-github-generator]: https://github.com/slsa-framework/slsa-github-generator

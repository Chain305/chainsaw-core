# Contributing to chainsaw-core

Thanks for helping improve Chainsaw. This document covers the conventions
this repository expects for changes, releases, and security reports.

This is the open-core module (`github.com/chain305/chainsaw-core`): the
`chainsaw` CLI and the embeddable proxy/policy/intelligence libraries. The
enterprise control plane (multi-tenant server, dashboard, premium
intelligence, SSO/SCIM, hardening wizard, policy signing, SIEM, billing)
lives in a separate private repository and is not developed here.

## Building and testing

The module is self-contained and builds standalone:

```sh
go build ./...                 # build everything
go build ./cmd/chainsaw        # build just the CLI
go test ./...                  # run the suite
```

`go build ./...` and `go test ./...` must pass before you open a PR.

If your change touches the policy engine, proxy transformers, or the
supply-chain intelligence subsystem, add or update the relevant unit tests
alongside the change. New code should not reduce coverage in the files it
touches — if you change a behaviour that a test exercised, recover the
coverage in the same PR by testing the new shape.

Postgres-backed logic should gate its integration tests behind
`CHAINSAW_DATABASE_URL`, matching the pattern already established in the
`pgstore` tests, so the default `go test ./...` run stays hermetic.

## Versioning

Chainsaw follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Pre-1.0, MINOR bumps may include breaking changes; PATCH is bug-fix only.

The canonical version string lives in `VERSION`. Bump it in the same commit
that prepares the release section in `CHANGELOG.md`.

## CHANGELOG discipline

Every PR that touches user-visible behaviour appends an entry to the
`## [Unreleased]` section of `CHANGELOG.md` under one of the
Keep-a-Changelog buckets:

- **Added** — new capabilities, flags, commands.
- **Changed** — behavioural changes to existing functionality.
- **Fixed** — bug fixes that users can notice.
- **Security** — CVE-class fixes, new boundaries, crypto changes.
- **Deprecated** — features scheduled for removal.

Rules:

- Write in past tense with a user-facing voice. "Caught a typosquat that
  swapped a single character" beats "fix detector bug".
- Leave internal filenames and commit refs out of the bullet unless they
  are load-bearing context.
- At release time, the `[Unreleased]` section is renamed to
  `## [X.Y.Z] — YYYY-MM-DD` and a fresh empty `[Unreleased]` block is
  opened above it.

## Commit message convention

Prefer the Conventional-Commit form for new work (`type(scope): subject`,
e.g. `fix(typosquat): ...`, `docs(readme): ...`). A clear imperative
subject line is also accepted. Keep the subject under 72 characters and put
any additional context in the body. A `Co-Authored-By:` trailer is expected
for pair-programmed and agent-authored commits.

## Error messages

Error strings returned to users follow a **problem + cause + fix**
convention. The reader should be able to diagnose what went wrong,
understand why, and know what to do next without reading source code.

```go
// Bad — what was invalid? what should the caller do?
return errors.New("invalid request payload")

// Good — names the operation, the failure mode, and the fix.
return errors.New("install-hook npm received no registry; pass a proxy " +
    "URL with --registry or set CHAINSAW_PROXY_URL")
```

Guidelines:

- Name the command, field, or operation that produced the error.
- Say *why* it failed in one short clause (cause).
- End with a concrete next step the caller can take (fix).
- Keep error strings lower-case and without trailing punctuation, matching
  standard Go style.

**Exception: authentication / authorisation errors** must remain
deliberately vague (e.g. `invalid credentials`) so a probing attacker
cannot tell whether a given token or identity exists.

## Security reports

Please report suspected vulnerabilities privately to
**security@chain305.com**. Do not open a public GitHub issue for security
reports; use the email address above. See [SECURITY.md](SECURITY.md) for
the full policy, scope, and disclosure window.

## Code of conduct

Be respectful and assume good intent. Disagree with the idea, not the
person; give and accept feedback gracefully; keep discussion focused on the
technical work. Conduct concerns can be reported to **conduct@chain305.com**
(or **security@chain305.com** if `conduct@` is not yet provisioned). Reports
are treated confidentially.

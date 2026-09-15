# Documentation

Start at the [project README](../README.md) — install, the offline guard, and
what Chainsaw does at a glance.

| Page | Covers |
|---|---|
| [cli.md](cli.md) | Every command, which ones are local, global flags, exit codes |
| [configuration.md](configuration.md) | Environment variables, where state lives on disk, the fail-closed coverage gate, first-run prompts |
| [ecosystems.md](ecosystems.md) | The three surfaces and their different reach; per-ecosystem policy-condition coverage; every manifest and lockfile format |
| [signals.md](signals.md) | All 77 risk signals with severity and weight; counts drift-tested against the registry |
| [policy.md](policy.md) | Rego policy, the five enforcement surfaces, registry proxy, Kubernetes admission, air-gapped signed bundles |
| [measurement.md](measurement.md) | Measured false-block and detection rates, their caveats, and how to reproduce them |

Also in the repository root: [SECURITY.md](../SECURITY.md),
[CONTRIBUTING.md](../CONTRIBUTING.md), [CHANGELOG.md](../CHANGELOG.md).

Hosted documentation: [docs.chain305.com](https://docs.chain305.com).

## A note on the tables

The tables in `signals.md` and the coverage tables in `ecosystems.md` describe
Go source — [`risk/registry.go`](../risk/registry.go) and
[`policy/proxy_matrix.go`](../policy/proxy_matrix.go) respectively. They are
hand-maintained, not generated: no generator exists for either page. The signal
counts in `signals.md` are pinned to the registry by a drift test
(`risk.TestSignalCountMatchesMarkdown`), so a signal added or removed in Go
fails the suite until this page catches up. If a table here disagrees with the
code, the code is right and the page is stale; please open an issue.

# Documentation

Start at the [project README](../README.md) — install, the offline guard, and
what Chainsaw does at a glance.

| Page | Covers |
|---|---|
| [cli.md](cli.md) | Every command, which ones are local, global flags, exit codes |
| [configuration.md](configuration.md) | Environment variables, where state lives on disk, the fail-closed coverage gate, first-run prompts |
| [ecosystems.md](ecosystems.md) | The three surfaces and their different reach; per-ecosystem policy-condition coverage; every manifest and lockfile format |
| [signals.md](signals.md) | All 76 risk signals with severity and weight, generated from the registry |
| [policy.md](policy.md) | Rego policy, the five enforcement surfaces, registry proxy, Kubernetes admission, air-gapped signed bundles |
| [measurement.md](measurement.md) | Measured false-block and detection rates, their caveats, and how to reproduce them |

Also in the repository root: [SECURITY.md](../SECURITY.md),
[CONTRIBUTING.md](../CONTRIBUTING.md), [CHANGELOG.md](../CHANGELOG.md).

Hosted documentation: [docs.chain305.com](https://docs.chain305.com).

## A note on generated pages

`signals.md` and the coverage tables in `ecosystems.md` are generated from the
Go source — [`risk/registry.go`](../risk/registry.go) and
[`policy/proxy_matrix.go`](../policy/proxy_matrix.go) respectively — rather than
hand-maintained. If a table here disagrees with the code, the code is right and
the page is stale; please open an issue.

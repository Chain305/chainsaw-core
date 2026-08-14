# Policy, enforcement surfaces, and deployment

## One decision engine, five surfaces

Policy is Rego (Open Policy Agent). There is one bundle, one input schema, and
one `Decide()` call — every surface produces the same input shape, and only the
`surface` string differs. A rule you write once fires wherever its input fields
are populated.

| Surface | Where it runs |
|---|---|
| `runtime` | package-manager install hook — the local guard |
| `pr` | GitHub Actions pull-request check |
| `proxy` | registry pull-through fetch |
| `publish` | pre-publish gate |
| `deploy` | Kubernetes admission webhook |

Author rules against the surface tag:

```rego
package chainsaw.policy

# only refuse at the registry, warn everywhere else
deny if {
    input.surface == "proxy"
    input.signals["sc.known_malicious"]
}
```

A sixth value, `promote` (environment-to-environment promotion), exists in the
enum but has **no production caller**. It is reserved, not shipped. It is
mentioned here only because you will encounter it in the source.

## Evaluating locally

Both of these read files from disk and need no server:

```sh
chainsaw policy eval  --bundle ./policies --input fixture.json
chainsaw policy gate proxy --bundle ./policies --input event.json
```

```console
$ chainsaw policy gate proxy --bundle ./policies --input event.json
surface=proxy action=allow violations=0 bundle=aaf8cc651c8d
```

Exit codes are identical across surfaces, so one CI-status mapping works
everywhere.

## Coverage caveat

A rule whose condition is unsupported for the target ecosystem cannot fire. That
is a property of upstream metadata, not a bug, and Chainsaw makes it visible
rather than silent:

- the support matrix is compiled in ([`policy/proxy_matrix.go`](../policy/proxy_matrix.go))
- the UI warns inline when you build a rule on an unsupported condition
- a skipped rule emits a `policy.rule.skipped` audit event

Per-ecosystem numbers are in [ecosystems.md](ecosystems.md).

## Server-backed policy management

Org policy lives on the control plane: create, list, enable/disable, import and
export, plus scoped exceptions with expiry dates and a full audit trail.

Monitor mode is the intended path to enforcement — run a rule in report-only
mode, accumulate would-block statistics, then flip it:

```sh
chainsaw policy rollout                    # monitor-mode policies + would-block stats
chainsaw policy flip-to-block <policy-id>  # flip, with a would-block preview first
chainsaw policy simulate <pkg@version>     # what would happen to this package
```

## Registry proxy

The proxy sits in front of your registries as a pull-through cache and applies
policy on fetch. It is the enforcement point a shell wrapper cannot be: it
covers every client, including CI runners and machines you do not administer,
and it cannot be routed around by invoking the real package-manager binary
directly.

It speaks the 16 ecosystems in [ecosystems.md](ecosystems.md), and it runs in
your own network. `proxy/`, `policy/` and `policyengine/` in this repository are
its open core.

## Kubernetes admission

`chainsaw admission` provides the webhook helpers, including a shadow-mode soak
gate so you can measure what a policy would reject before it rejects anything.

Infrastructure and signal unavailability fail **closed** at admission — the
opposite of the local guard's default, deliberately, because a workstation that
blocks installs on a feed hiccup is broken while a cluster that admits unchecked
images is a hole.

## Air-gapped operation

The offline guard needs nothing at all. For a fully disconnected proxy,
intelligence ships as a **signed bundle**: a manifest with per-file content
hashes plus a Sigstore signature, verified before it is trusted.

```console
$ chainsaw bundle verify ./intel-bundle
```

| Exit | Meaning |
|---|---|
| `0` | verified and fresh |
| `1` | verified but stale (warn only) |
| `2` | verification failure, load error, or an unverified bundle without `--allow-unverified` |

Point the proxy at it with `CHAINSAW_INTEL_BUNDLE_PATH`. An unverified bundle
never underwrites a corpus-membership exemption — the popularity corpus that
grants exact-match exemptions must ride reviewed data or a verified signature,
never an unauthenticated file.

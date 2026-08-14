# Configuration

## Environment variables

Guard-relevant variables:

| Variable | Effect |
|---|---|
| `CHAINSAW_OFFLINE=1` | Never touch the network. Suppresses both first-run prompts. |
| `CHAINSAW_CONFIG_HOME` | Override the config directory (CI, Nix, portable installs). |
| `CHAINSAW_GUARD_DB` | Override the cached known-malicious feed path. |
| `CHAINSAW_GUARD_DEEP=1` | Enable byte-level analysis by fetching archives. **Waives the offline guarantee.** npm and cargo, pinned versions only. |
| `CHAINSAW_GUARD_ARTIFACT_DIR` | Byte-level analysis over archives *you* stage. Stays offline. |
| `CHAINSAW_COVERAGE_MODE` | `off` (default) · `warn` · `closed` — see below. |
| `CHAINSAW_COVERAGE_REQUIRED` | Comma-separated data sources that must be evaluable. |
| `CHAINSAW_TELEMETRY_DISABLED=1` | Force telemetry off regardless of local state. |
| `CHAINSAW_QUIET` / `CHAINSAW_VERBOSE` | Output level, same as `-q` / `-v`. |
| `CHAINSAW_SERVER` / `CHAINSAW_TOKEN` | Control-plane URL and credentials. |
| `CHAINSAW_INTEL_BUNDLE_PATH` | Path to a signed offline intelligence bundle (proxy-side). |

## Where state lives

| What | Where |
|---|---|
| Config directory | `$CHAINSAW_CONFIG_HOME`, else `$XDG_CONFIG_HOME/chainsaw` or `~/.config/chainsaw` (Linux) · `%APPDATA%\Chainsaw` (Windows) · `~/.chainsaw` (macOS) |
| Local allowlist | `<config>/guard_allowlist.json` |
| Cached malicious feed | `<user cache dir>/chainsaw/known_malicious.json`, or `$CHAINSAW_GUARD_DB` |

All three are plain files you can read, diff, back up, or ship in a golden
image.

## Refusing when a signal cannot be evaluated

The guard fails **open** by default: if a signal cannot be evaluated it prints a
notice and lets the install proceed, because a thin feed must never break
`npm install`. That is right for a workstation and wrong for some regulated and
air-gapped deployments.

An opt-in, off-by-default gate lets you name the data sources that must be
evaluable, and refuse when one is not:

```sh
export CHAINSAW_COVERAGE_MODE=warn          # off (default) | warn | closed
export CHAINSAW_COVERAGE_REQUIRED=typosquat,malware
```

Start in `warn` — it reports what `closed` would have refused, and refuses
nothing.

| Source | Availability |
|---|---|
| `typosquat` | always works offline |
| `malware` | needs `chainsaw guard update` (or a staged feed) |
| `cve` | needs the server — never available offline |
| `registry_metadata` | needs the server — never available offline |
| `provenance` | needs the server — never available offline |

Requiring a source the guard cannot see refuses every install, with a readable
reason. That is intended, not a bug — it is what fail-closed means.

`chainsaw coverage` inspects what is currently measurable.

## First-run prompts

On the first block in an interactive terminal you get two prompts, and **both
default to Yes, so a blind Enter accepts them**:

| Prompt | What it does |
|---|---|
| *Download the full OpenSSF malicious-package feed?* | ~40MB from GitHub, replacing the 11-entry embedded floor with ~231k entries. Equivalent to `chainsaw guard update`. |
| *Share detection signals?* | Turns on telemetry. |

`CHAINSAW_OFFLINE=1` skips both. **Neither prompt ever appears in a
non-interactive shell**, so CI never fetches and never sends.

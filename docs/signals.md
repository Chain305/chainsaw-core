# Risk signals

Chainsaw registers **76 risk signals**. Each is scored, not merely
boolean: a signal carries a severity and a weight, and the evaluator rolls the
fired set up into an overall score.

[`risk/registry.go`](../risk/registry.go) is the source of truth, not this
table. The counts on this page — the total, the category table and every
`## Category (N)` heading — are pinned to the registry by a drift test
(`risk.TestSignalCountMatchesMarkdown`), which also checks that each section
lists as many rows as the registry has signals in that category. The prose in
the "What it means" column is hand-written.

**Where they run.** The full set is evaluated server-side. The offline install
guard runs the subset that needs no external data: typosquat, known-malicious,
and — opt-in — the byte-level checks (`sc.hidden_unicode` and the IOC scan).
Everything requiring registry metadata, CVE feeds or repository data needs a
Chainsaw proxy or control plane.

Per-org weights can be overridden with `chainsaw risk-weights`, except for
signals flagged as not tunable. `chainsaw intel signals` lists the live set from
a configured server.

| Category | Signals |
|---|---:|
| Supply chain | 48 |
| Vulnerability | 7 |
| Licence | 9 |
| Maintenance | 6 |
| Quality | 6 |
| **Total** | **76** |


## Supply chain (48)

| ID | Severity | Weight | What it means |
|---|---|---:|---|
| `action.malicious` | high | -50.00 | GitHub Action ref flagged as malicious |
| `action.typosquat` | high | -40.00 | GitHub Action name resembles a popular Action |
| `action.unknown_publisher` | low | -5.00 | GitHub Action from unknown publisher |
| `action.unpinned_ref` | medium | -15.00 | Unpinned GitHub Action reference |
| `ai.agent_tool_dangerous_capability` | high | -30.00 | Agent tool declares dangerous capability |
| `ai.dangerous_pickle_opcode` | critical | -100.00 | Dangerous pickle opcode in model weights |
| `ai.model_card_injection` | medium | -20.00 | Model card contains injection markers |
| `ai.prefers_safetensors` | info | 5.00 | Safetensors weights available |
| `ai.prompt_template_injection` | medium | -20.00 | Prompt template contains injection markers |
| `ai.suspicious_pickle_opcode` | medium | -15.00 | Pickle imports uncommon for model weights |
| `ai.unsafe_serialization_format` | low | -10.00 | Unsafe serialization format (pickle without safetensors) |
| `cap.dynamic_eval` | low | -3.00 | Package uses dynamic code evaluation |
| `cap.env_access` | info | 0.00 | Package reads environment variables |
| `cap.filesystem_read` | info | 0.00 | Package can read from the filesystem |
| `cap.filesystem_write` | info | 0.00 | Package can write to the filesystem |
| `cap.native_code` | info | 0.00 | Package uses native (C/C++) bindings |
| `cap.network` | info | 0.00 | Package can open network connections |
| `cap.shell` | info | 0.00 | Package can execute shell commands |
| `sc.deprecated_by_maintainer` | medium | -15.00 | Deprecated by maintainer |
| `sc.first_time_collaborator` | medium | -15.00 | First-time collaborator on this package |
| `sc.git_url_dependency` | low | -8.00 | Git URL dependency |
| `sc.hidden_unicode` | medium | -20.00 | Hidden Unicode in source |
| `sc.http_url_dependency` | low | -8.00 | HTTP(S) tarball URL dependency |
| `sc.install_script_fetches_remote` | high | -25.00 | Install script makes network calls |
| `sc.install_script_only` | low | -5.00 | Install lifecycle script present |
| `sc.known_malicious` | critical | -1000.00 | Known-malicious package |
| `sc.maintainer_account_somewhat_young` | low | -5.00 | Maintainer account under 6 months |
| `sc.maintainer_account_very_young` | high | -25.00 | Maintainer account very young (<30 days) |
| `sc.maintainer_account_young` | medium | -15.00 | Maintainer account young (<90 days) |
| `sc.manifest_confusion` | high | -45.00 | Registry/tarball manifest mismatch |
| `sc.non_existent_author` | high | -20.00 | Declared author does not exist on registry |
| `sc.provenance_verified` | info | 15.00 | Verified build provenance |
| `sc.publish_velocity_anomaly` | medium | -15.00 | Abnormal publish velocity |
| `sc.publisher_changed` | high | -25.00 | Publisher changed from previous version |
| `sc.repo_archived` | medium | -12.00 | Source repo archived |
| `sc.repo_missing` | medium | -12.00 | Source repo missing |
| `sc.repo_ownership_mismatch` | high | -20.00 | Source repo ownership mismatch |
| `sc.reserved_namespace_violation` | high | -25.00 | Reserved namespace violation |
| `sc.shrinkwrap_present` | low | -10.00 | Bundled dependency lockfile |
| `sc.signature_verified` | info | 5.00 | Upstream signature verified |
| `sc.slsa_level_bonus` | info | 0.00 | SLSA build level bonus |
| `sc.suspicious_repo_stars` | high | -25.00 | Suspicious repo: low stars + young repo + young maintainer |
| `sc.transitive_critical_vuln` | critical | -40.00 | Transitive critical vulnerability |
| `sc.transitive_high_vuln` | high | -20.00 | Transitive high-severity vulnerability |
| `sc.transitive_malware` | critical | -1000.00 | Malware in transitive closure |
| `sc.typosquat_high` | critical | -40.00 | Likely typosquat (high confidence) |
| `sc.typosquat_low` | low | -8.00 | Name similarity to popular package (low confidence) |
| `sc.typosquat_medium` | medium | -20.00 | Possible typosquat (medium confidence) |

## Vulnerability (7)

| ID | Severity | Weight | What it means |
|---|---|---:|---|
| `vuln.cvss_critical` | critical | -35.00 | Critical-severity CVE |
| `vuln.cvss_high` | high | -20.00 | High-severity CVE |
| `vuln.cvss_low` | low | -3.00 | Low-severity CVE |
| `vuln.cvss_medium` | medium | -10.00 | Medium-severity CVE |
| `vuln.epss_high` | high | -15.00 | High exploit probability (EPSS) |
| `vuln.fix_available` | info | 5.00 | Fix available |
| `vuln.kev` | critical | -60.00 | Known-exploited vulnerability |

## Licence (9)

| ID | Severity | Weight | What it means |
|---|---|---:|---|
| `lic.changed_from_previous_version` | medium | -15.00 | License changed from previous version |
| `lic.missing` | medium | -15.00 | No license declared |
| `lic.policy_blocked` | high | -30.00 | License blocked by policy |
| `lic.spdx_present` | info | 5.00 | SPDX license declared |
| `license.ambiguous_classifier` | low | -10.00 | Ambiguous license expression |
| `license.copyleft` | medium | -10.00 | Copyleft license |
| `license.exception_present` | info | -5.00 | License carries a WITH exception |
| `license.non_permissive` | medium | -20.00 | Non-permissive license |
| `license.unidentified` | medium | -15.00 | Unidentified license |

## Maintenance (6)

| ID | Severity | Weight | What it means |
|---|---|---:|---|
| `maint.abandoned_repo` | high | -25.00 | Source repository looks abandoned |
| `maint.healthy_cadence` | info | 10.00 | Healthy release cadence |
| `maint.no_recent_release` | medium | -15.00 | No recent releases |
| `maint.single_maintainer` | low | -5.00 | Single maintainer |
| `maint.unpopular_package` | info | 0.00 | Very low download count |
| `maint.very_new_package` | medium | -10.00 | Very new package |

## Quality (6)

| ID | Severity | Weight | What it means |
|---|---|---:|---|
| `ai.agent_tool_declared` | info | 0.00 | Package declares an MCP server / agent tool |
| `ai.mcp_server_unverified` | low | -8.00 | MCP server lacks verified provenance |
| `qual.checksum_mismatch` | critical | -1000.00 | Artifact checksum mismatch |
| `qual.checksum_verified` | info | 5.00 | Checksum verified |
| `qual.minified_code` | info | 0.00 | Shipped source appears minified or bundled |
| `qual.version_anomaly` | medium | -10.00 | Version publishing anomaly |

# Ecosystems and coverage

Chainsaw has three surfaces with three different reaches. Conflating them is
the easiest way to over- or under-state what it does, so they are listed apart.

## 1. The offline install guard — 5 package managers

`npm`, `pip`, `go`, `cargo`, `gem`. These are the managers the shell shim
intercepts, blocking at the install path with no account and no network. See
[the guard section of the README](../README.md#how-the-guard-works).

## 2. Local manifest and lockfile parsing — `pr-scan`

Runs locally, no server:

| Ecosystem | Files |
|---|---|
| npm | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `npm-shrinkwrap.json` |
| pip | `requirements*.txt` (matched by prefix, so `requirements-dev.txt` too), `Pipfile.lock`, `poetry.lock`, `uv.lock` |
| Go | `go.sum` |
| Cargo | `Cargo.lock` |
| RubyGems | `Gemfile.lock` |

The parser packages ([`depparser/`](../depparser), [`formats/`](../formats))
reach further — Maven `pom.xml`, Gradle (`build.gradle`, `build.gradle.kts`,
`gradle.lockfile`), NuGet `packages.lock.json`, Composer `composer.lock`, Swift
`Package.resolved`, CocoaPods `Podfile.lock`, Dart `pubspec.lock`, plus Conda,
Hex, Julia, SBT and C dependency formats. Those feed SBOM generation and
server-side scanning rather than the local `pr-scan` path.

## 3. The registry proxy and risk engine — 16 ecosystems

Coverage is **not uniform**, and pretending otherwise would be the dishonest
way to present this. Of the **53 policy conditions**, each ecosystem
supports a different subset — an upstream that publishes no maintainer metadata
cannot produce a maintainer signal.

| Ecosystem | Full | Partial | Not supported |
|---|---:|---:|---:|
| npm | 43 | 4 | 6 |
| PyPI | 45 | 4 | 4 |
| Maven | 21 | 14 | 18 |
| Cargo | 36 | 2 | 15 |
| Composer | 33 | 4 | 16 |
| RubyGems | 37 | 4 | 12 |
| NuGet | 24 | 11 | 18 |
| Go | 29 | 1 | 23 |
| Hugging Face | 21 | 2 | 30 |
| CocoaPods | 26 | 2 | 25 |
| Swift | 21 | 8 | 24 |
| Pub (Dart) | 19 | 11 | 23 |
| Docker / OCI | 16 | 1 | 36 |
| APT | 12 | 1 | 40 |
| Yum | 14 | 1 | 38 |
| DNF | 14 | 1 | 38 |

**Partial** means the condition is wired but the underlying signal is
incomplete in practice — Swift licence-to-SPDX mapping, for example, or
OS-package provenance where the hash-chain walk is deferred.

This table is compiled into the binary
([`policy/proxy_matrix.go`](../policy/proxy_matrix.go)) rather than kept as
prose, and a drift test asserts it matches the published matrix
(`TestEcosystemsDocMatchesSupportMatrix` in `policy/proxy_matrix_test.go` reads
this file directly and recounts every cell; `TestSupportMatrixMatchesMarkdown`
does the same for [`docs/POLICY_PROXY_MATRIX.md`](../../docs/POLICY_PROXY_MATRIX.md)). It is queryable
at `GET /api/policies/support-matrix`, the UI warns inline when you build a rule
on an unsupported condition, and at evaluation time a rule skipped for this
reason emits a `policy.rule.skipped` audit event — so an inert rule is visible
rather than silent.

## The 53 policy conditions

```
Scorecard                           HasHiddenUnicode                    EnvVarAccess
MalwareIndex                        PublishVelocityAnomaly              NativeBinaryPresent
EPSS                                LicenseCopyleft                     HighEntropyStrings
CVE                                 LicenseNonPermissive                URLStrings
PackageAge                          LicenseExceptionPresent             MinifiedCode
Cooldown                            LicenseAmbiguousClassifier          TrivialPackage
License                             LicenseUnidentified                 TooManyFiles
HasProvenance                       DeprecatedByMaintainer              NonExistentAuthor
Typosquat                           ShrinkwrapPresent                   FirstTimeCollaborator
CVSS                                ManifestConfusion                   SuspiciousRepoStars
ReservedNamespaces                  GitDependency                       DangerousPickle
HasInstallScript                    HTTPTarballDependency               UnsafeSerializationFormat
InstallScriptFetchesRemote          WildcardDependencyRange             ModelCardInjection
ImportTimeExecution                 BadDependencySemver                 AgentToolDangerousCapability
MaliciousIOC                        UsesEval                            MCPServerDeclared
BuildRsExecutes                     NetworkAccess                       PromptTemplateInjection
PublisherChanged                    ShellAccess                         MaintainerAccountAge
VersionAnomaly                      FilesystemAccess
```

# established-table-gen

Generates the install guard's embedded **established tables** by census
(since 2026-10-21):

- `core/cli/seeds/established_npm.tsv`
- `core/cli/seeds/established_pypi.tsv`
- `core/cli/seeds/established_cargo.tsv`
- `core/cli/seeds/established_pub.tsv`

## What a row is

The guard consults the table for any name its typosquat lane flags at medium
or high confidence. So the census reads the registry's **full public name
list** and runs the guard's own detector — same corpus, normalization,
distance and thresholds — over every name. A candidate is any name it flags
(homoglyph hits excluded; the guard decides those before any table). Two
tiers, recorded per candidate: **block** (the d=1 lookalike of a target
ranked within the block cutoff, 2,500 — `cli.guardTyposquatBlockRankCutoff`)
and **warn** (every other medium/high hit: distance 2–3 within the
detector's thresholds, reorder matches, d=1 past the cutoff). A candidate is
admitted only when the registry shows it is long-standing and used in its own
right — **both halves of either line**, the same lines for both tiers:

| line | age (first published, before the build) | downloads a week |
| --- | --- | --- |
| downloads line | ≥ 2 years | ≥ 100,000 |
| old-package line (2026-10-23), warn tier | ≥ 5 years | ≥ 1,000 |
| old-package line, block tier | ≥ 5 years | ≥ 20,000 |

Downloads are npm last-week, PyPI pypistats `last_week`, crates.io 90-day ×
7/90 and pub.dev 30-day × 7/30. Downloads alone is a pumped young package; a
version count alone is cheap (create-jst shipped 28 versions in 30 days), so
neither admits on its own. The old-package line is low on purpose and safe
only because of the version gate below: downloads are cheap to inflate and
old dormant names get taken over, so a row admitted on it still warns on
every install that is not an exact build-time pin. The block tier's higher
bar is measured: at 1,000 a week the line admitted `loadash` (lodash, 2
releases, 14.4k a week) and `expres` (express, 2.9k), the guard's canary
squats, and lowered their blocks to warnings; no version-count rule separates
them from `as-number` (1 release, 47k). The guard's runtime clear
takes the same line (`risk.EstablishedTableClear`); the server's clear
(`risk.EstablishedClear`) does not, because it has no release set to gate on.
**Never admitted:** a name in the known-malicious feed, an npm security
placeholder (highest version is npm's `-security` holding release:
`npm:http`), a name with no registry data, and a name on the **reviewed
keep-blocked list** (`keepBlocked` in `census.go`: ecosystem, name, reason,
review date), applied after admission. The list holds names that meet a line
but whose traffic an expert hand-review found to be mis-installs of the
target (2026-10-23: npm `user`; PyPI `websocket`, `config-parser`, `slack`,
`google-oauth`). `TestKeepBlockedNeverAdmitted` fails if any is ever
admitted.

Row format (TSV):

```
name <TAB> weekly_downloads <TAB> version_count <TAB> first_published <TAB> last_published <TAB> releases
```

`releases` (comma-separated, sorted) is every version that existed at build
time. The guard is **silent only for an exact pin inside it**; every other
install of the name (no version, a range, a tag, a release newer than the
build) keeps the typosquat lane: a block is lowered to a printed warning, and
a warning stays a warning. A warn-tier row therefore only ever silences a
medium-confidence warning on a pinned build-time release; it cannot touch a
block the block-tier rules would not already lower.
See `core/cli/guard_established.go`, THE VERSION GATE. Weekly downloads are
stored scaled to a week so the guard's runtime clear (`risk.EstablishedClear`,
downloads line) agrees with the census.

## Why a census (and what it replaced)

Until 2026-10-21 the candidate universe was the popular seeds plus a customer
SBOM export, admission was "any clear line", and **rail 3** held out every
name one edit from a popular seed with under 1% of its traffic. Two defects:

- **In-sample.** Measuring the guard on that customer's inventory measured the
  table on its own training data, and the export's pseudonymised
  `internal-<hash>` names were sent to the registries as lookups.
- **Rail 3 held out exactly the packages the table exists for** — `jsonp`
  (json5), `pegjs` (pngjs), `is-blob` (is-glob), `js-logger` (bs-logger),
  `has-own` (hasown). It was needed while a table row cleared SILENTLY for
  any version; once a row can only warn on anything but an exact build-time
  pin, the age-and-downloads admission is the safer line.

## Sources (public only)

| eco | name list | per-candidate |
| --- | --- | --- |
| npm | `replicate.npmjs.com/_all_docs` ids (~4.5M, 10k/page, 2/s), held in memory only | `api.npmjs.org` last-week (unscoped: 128 per bulk request, first; scoped: one point call each, after the doc shows ≥2y); registry doc only for names at ≥ 1,000/week and scoped names |
| pypi | `pypi.org/simple/` (PEP 691 JSON) | ClickHouse's public PyPI download dataset (`sql-clickhouse.clickhouse.com`, demo user; two aggregate queries on the monthly table, no package name sent, `read_overflow_mode='throw'` so a truncated scan fails the run) decides who is worth more: a candidate under 500 a week there (last complete month × 7/30) gets no further call; the rest get `pypi.org/pypi/<name>/json` and, if a line can still admit it, `pypistats.org` recent (1/1.1s), which is what admission reads |
| cargo | `crates.io/api/v1/crates` seek pages (100/page, 1/s — the 2 GB db dump does not fit the release machine); the listing carries created date, 90-day downloads and version count, so no per-crate call | `index.crates.io` releases for admissible crates |
| pub | `pub.dev/api/package-names` | `/api/packages/<name>`; `/api/packages/<name>/score` if ≥2y |

The detector pass is CPU-bound (npm's 4.5M names: ~45 min on 8 cores);
downloads are checked before anything that needs a registry doc, so most of
the warn tier is refused without a per-name request.

Every request carries the descriptive User-Agent
(`chain305 established-table-gen (github.com/chain305/chainsaw)`), goes through
a per-host limiter, and backs off on 429/5xx honouring `Retry-After`. Downloads
are fetched only for candidates a line can still admit. The run ends
by printing upstream request counts per host.

**Never a customer inventory.** As a second guard, any `internal-<8 hex>` name
(the SBOM export's pseudonym shape) is dropped from every list before use;
`internal-slot` is a real npm package and stays.

## Rails

Any failure refuses the write and exits non-zero:

1. **Self-test** of the admission lines on synthetic rows: a pumped young
   package, an old quiet one (500/week), a 3-year-old one at 50k/week, a
   version-count-only one, a feed name and a placeholder are refused; a
   dormant old package with two versions and real traffic, and a 5-year-old
   one at 1,000/week, are admitted; a block-tier one at 14k/week is refused
   and one at 47k/week admitted.
2. **Sentinels** — measured false blocks that must be admitted (npm: `pug`,
   `jsonp`, `is-blob`; pub: `dartx`).
3. **Canaries** — the guard's canary squats (npm `lodahs`, `loadash`,
   `crossenv`, `expres`, `chalkk`; PyPI `reqeusts`, `beautifulsoup5`; cargo
   `proc-macro1`) must not be admitted.
4. **Churn** — a regeneration that loses more than 25% of the previous census's
   rows is refused (first census run: baseline).
5. **Feed** — `-malware-feed` (default: the `chainsaw guard update` cache)
   plus the embedded floor; an unreadable or empty feed refuses the run.

Every candidate's decision is written to `<cache>/<eco>_census_verdicts.jsonl`
for review.

## Usage

From `core/`. Keep the cache **outside the repo** (`core/cache` is a Go
package). npm's name list is never written; the other lists are cached during
a run and removed when it succeeds; delete the rest of the cache afterwards:

```sh
go run ./tools/established-table-gen -ecosystem pub   -cache /tmp/etg-cache -out cli/seeds/established_pub.tsv
go run ./tools/established-table-gen -ecosystem pypi  -cache /tmp/etg-cache -out cli/seeds/established_pypi.tsv
go run ./tools/established-table-gen -ecosystem npm   -cache /tmp/etg-cache -concurrency 8 -out cli/seeds/established_npm.tsv
go run ./tools/established-table-gen -ecosystem cargo -cache /tmp/etg-cache -out cli/seeds/established_cargo.tsv
rm -rf /tmp/etg-cache
```

Refresh monthly, alongside the popular seeds. The TSVs are data reviewed as a
PR (or carried by the signed intelligence bundle); the guard never fetches
them at install time. `go vet` must stay clean.

# established-table-gen

Generates the per-ecosystem **established tables** consumed by the install
guard's typosquat clear:

- `core/cli/seeds/established_npm.tsv`
- `core/cli/seeds/established_pypi.tsv`
- `core/cli/seeds/established_cargo.tsv`

Row format (TSV, qualifying rows only):

```
name <TAB> weekly_downloads (0 if unknown) <TAB> version_count <TAB> first_published (YYYY-MM-DD or empty) <TAB> last_published (YYYY-MM-DD or empty)
```

Names are keyed **exactly as the registry spells them**; the consumer
normalizes. Row order is weekly downloads descending (the churn rail reads
the top 100 rows as "the top 100").

## Why a table and not a popularity corpus

The previous design keyed the typosquat clear to corpus *rows* — a package
was established only if it appeared in a top-N popularity ranking. The
adversarial review rejected that: **establishment and popularity are
different properties**. A package with 20k weekly downloads, 8 years of
history and 60 versions is beyond any doubt not a typosquat — it has
outlived every squat registry moderation has ever removed — yet it will
never crack a top-10k ranking. Keying the clear to popularity made the
false-block rate a function of rank, and rank is exactly what a patient
attacker can buy.

This table instead keys **the clear lines themselves**, mirrored from
`core/risk/established.go` and `core/intelligence/typosquat_established.go`
(one definition, so the table, the runtime clear and the damper cannot
disagree). A name is in the table iff real registry data shows it meets ANY
line:

| line | npm / pypi | cargo |
| --- | --- | --- |
| downloads | >= 100,000 weekly | >= 75,000 **total** (see proxy note) |
| versions | >= 50 versions AND first published >= 2y ago | same |
| long-lived | first published >= 5y ago AND last published >= 1y ago | same |

If those constants move in `core/risk`, regenerate all three tables.

**Cargo proxy note:** crates.io publishes no weekly figure, only a 90-day
and an all-time count. v1 applies the >=75k/90d spirit to **total**
downloads, which is a strictly looser bar for an old crate than 75k per 90
days; the file header says so on every generation.

Rows with `weekly_downloads=0` (PyPI has no download data in v1) are fine:
they qualify through the version/age lines, which need no traffic data.

## Sources

**npm** — universe (candidates, ~8.4k distinct names):
`core/cli/seeds/npm_popular.txt` (5,000) ∪ `packages.csv` rows with
`ecosystem=npm` (~7.1k public SBOM names) ∪ the names in the cached
abbreviated docs `npm_docs.jsonl` (6,858) ∪ the canary pins below. Per name:
- full registry doc `https://registry.npmjs.org/<name>` — `time.created`,
  per-version times (last published = max excluding `created`/`modified`),
  `version_count = len(versions)`; npm's `0.0.x-security` holding
  placeholders are excluded from the age lines (their timestamps are removal
  artifacts);
- weekly downloads from `https://api.npmjs.org/downloads/point/last-week/…`
  — comma-joined batches of ~128 unscoped names per request, scoped names
  individually.

**pypi** — universe: `core/cli/seeds/pypi_popular.txt` (3,000) ∪
`packages.csv` pypi names (318). `https://pypi.org/pypi/<PEP503>/json`:
`version_count` = releases with files; first/last from `upload_time`.
Downloads are not fetched (pypistats skipped in v1) → `0`.

**cargo** — `https://crates.io/api/v1/crates?sort=downloads&per_page=100`
× 30 pages = top 3,000 crates. The listing itself carries `created_at`,
`updated_at`, total `downloads` and `num_versions` (no per-crate second
call needed). A descriptive User-Agent
(`chain305 established-table-gen (github.com/chain305/chainsaw)`) and a
modest page rate keep crates.io happy.

Every fetch is cached as JSONL under `-cache` (distilled records — a
full-doc cache would be gigabytes) and every run resumes from it; reruns are
cheap and idempotent until the caches are deleted. On the monthly refresh,
delete `npm_downloads.jsonl` from the cache (weekly figures go stale; the
doc-derived fields barely move). api.npmjs.org rate-limits hard: the tool
spaces requests through a shared limiter, sends unscoped names in bulk
batches of 128 first, and then walks scoped names one point call at a time
(the bulk endpoint rejects them outright) — budget ~1h for a cold-cache npm
run.

## Refresh cadence

**Monthly**, alongside the popular seeds (upstream download rankings refresh
monthly). The registry docs are effectively stable for established packages,
so the churn rail below makes monthly drift visible and bounded.

## Anti-poisoning rails

Following the refuse-don't-report-zero discipline of `popular-corpus-gen`
(any hard rail failure refuses the write and exits non-zero):

1. **Canary presence.** The npm canaries — `pug`, `jsdoc`, `uglify-es`,
   `flatten`, `lodash.set`, `charset`, `parseuri`, `clui`, `as-number`,
   `hable`, `crypto-es`, `crypto-ts`, `has-own`, `js-logger` — are measured
   false-blocks. Each must either appear in the table or be printed with the
   registry-data reason it does not qualify. A canary with no registry data
   is a hard failure (the table would silently lose its false-positive
   regression coverage). A canary legitimately failing to qualify is an
   expected, printed outcome — not a failure (2026-10-19: `crypto-es` at
   88k/wk and 29 versions). A third state exists and is also printed: a
   canary that QUALIFIES but is HELD OUT by rail 3 (`has-own` vs `hasown`,
   `crypto-ts` vs `crypto-js`, …) — d1 of a popular name with <1% of its
   traffic is squat-shaped even for a canary, so it stays out of the
   embedded table and clears at runtime through live metadata instead.
2. **Multi-signal floor.** A row qualified *only* by the downloads line must
   be >= 1y old or have >= 10 versions; violators are held out and printed.
   One hot week is not establishment — it is indistinguishable from a
   purchased-audience squat.
3. **d1 ratio watch.** Any row within edit distance 1 (scope-insensitive)
   of a `npm_popular.txt` name whose weekly downloads are < 1% of that seed
   name's is held out and the pair printed — squat-shaped regardless of how
   it qualified.
4. **Churn.** Against the previous table: top-100 turnover > 10% or total
   churn > 25% fails. First run prints `first-run baseline` instead.
5. **Patient-attacker self-test.** After generation, a synthetic probe
   (55 versions, 15 months old, 120k/wk — 0.01%-of-lodash traffic) is run
   through the same decision functions. Rail 2 deliberately passes that
   profile (a patient attacker satisfies the floor by waiting); the probe
   named `zz-squat-probe` is not actually one edit from `lodash`, so the
   test also runs an **armed** variant under `lodsh` (a true one-edit
   lookalike) and asserts the d1 ratio watch holds it. PASS requires the
   armed variant held by rail 3 and the non-lookalike not held.

Plus corpus-style floors: a table below a per-ecosystem row floor, or
missing flagship sentinels (react/lodash/express/typescript,
requests/numpy/boto3/urllib3, serde/tokio/libc/rand), refuses the write.

## Trust channel

The TSVs are **data, reviewed as a PR** — never generated at install time
and never fetched live by the guard. Between releases the signed
intelligence-bundle channel (content key `typosquat`) can carry an updated
table, exactly like the popular seeds. At install time the consumer reads
only the embedded/reviewed copy and normalizes names; live registry checks
remain a separate, fail-closed path.

## Usage

From `core/`:

```sh
go run ./tools/established-table-gen -ecosystem cargo -cache ./cache -out cli/seeds/established_cargo.tsv
go run ./tools/established-table-gen -ecosystem pypi -cache ./cache -out cli/seeds/established_pypi.tsv
go run ./tools/established-table-gen -ecosystem npm   -cache ./cache -concurrency 8 -out cli/seeds/established_npm.tsv
```

`-packages-csv` and `-npm-docs-jsonl` default to the research-dataset paths;
pass them explicitly when regenerating elsewhere. `go vet` must stay clean.

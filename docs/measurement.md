# Measured detection and false-positive rates

A catch rate without a false-positive rate is marketing. Both are published
here, with their scope stated, and the typosquat harnesses ship in this
repository.

**We do not claim zero false positives.** We published a 0.00% once, it did not
reproduce on a wider corpus, and we retired it.

## Name-level typosquat — the default install path

This is what the offline guard does on every install.

| | |
|---|---|
| **False-block rate** | **1.02%** (down from 1.87%) |
| **Corpus** | 24,206 real package names held **out** of the detector's own seed index (npm ranks 5,001+, PyPI ranks 3,001+); intersection with the shipped seed verified empty |
| **Still refused** | 247 of 24,206 |
| **Recall cost of that reduction** | 8.2% of the typosquat lane's blocks on the OpenSSF malicious-packages feed (92 of 1,122) |

Quoting either number without the other misrepresents the trade: the false-block
rate came down because the detector was narrowed, and narrowing it gave up real
detections.

The upstream lists are themselves popularity-ranked and reach npm rank 17,334
out of roughly 3M packages, so this samples the near tail. It is a lower bound,
not an estimate of the whole registry.

### What changed

A rune added to or dropped from an *end* of a popular name is how sibling
packages get named — `nan`→`nano`, `listr`→`listr2`, `attr`→`attrs` — not how
names get mistyped. That shape now **warns** rather than refuses.

One carve-out: an append or prepend against a household name (a target inside
the top 500) keeps refusing, because attackers lean on that shape heavily.
`lodashn`, `hdebug` and `pydantics` are all in the OpenSSF feed.

### Survivors

Legitimate packages still refused include `npm:jsdoc` (against `jsdom`),
`npm:stylus` (against `stylis`), `npm:tslint` (against `eslint`) and the whole
`pypi:nvidia-*-cu11` family (against `-cu12`). The class is narrower, not gone.

## Byte-level scanner — the opt-in deep mode

This is **not** the default install path. It requires `CHAINSAW_GUARD_DEEP=1` or
a staged artifact directory.

| | Real malware (597 samples) | Benign corpus (860 packages) |
|---|---|---|
| **Hard-block** | 46.2% | 0.81% false-block |
| **Any signal** (surfaces, does not block) | 69% | 5% |

**Caveats, before you quote these:**

- The 0.81% benign corpus is drawn from the same popularity seeds the typosquat
  detector uses as its target index, so every name is an exact match and is
  cleared before any distance check runs — it *cannot* produce a typosquat false
  block. It is a floor, not an estimate of what you will experience. The
  typosquat class is measured separately, at 1.02%, above.
- It is a composite: npm measured 0/600, PyPI 7/260 = 2.69%.
- The 597 malware samples are a deterministic first-N slice of a public dataset,
  not a random sample.
- Detector changes were made against this corpus and then re-measured on it.

## Reproducing

Both typosquat harnesses are in this repository:

- [`cli/guard_typosquat_fp_eval_test.go`](../cli/guard_typosquat_fp_eval_test.go)
- [`cli/guard_typosquat_recall_eval_test.go`](../cli/guard_typosquat_recall_eval_test.go)

They skip without a corpus, so they do not run in CI. The recall harness runs
against the feed `chainsaw guard update` caches.

The held-out corpus builder and the byte-level harness still live in the private
monorepo. Moving them across, so these numbers are independently reproducible by
anyone reading this, is tracked work and not yet done.

## Bypassability

The local guard wraps your package manager, and a determined developer can call
`/usr/local/bin/npm` directly. Our own test suite asserts this
([`cli/bypass_matrix_test.go`](../cli/bypass_matrix_test.go)) rather than
pretending otherwise.

Closing that is a registry-proxy and lockfile-pinning property — see
[policy.md](policy.md#registry-proxy). Treat the local guard as a seatbelt on
your own machine, not a control you can attest to an auditor.

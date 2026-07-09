# Test data provenance

These files are copied verbatim from the sigstore-go module
(github.com/sigstore/sigstore-go@v1.1.4, Apache-2.0) test corpus so that
our real `Verify()` crypto pipeline can be exercised OFFLINE against a
genuinely-signed bundle pinned to a snapshot trusted root.

| file | upstream path |
|------|---------------|
| `othername.sigstore.json`        | `pkg/testing/data/bundles/othername.sigstore.json` |
| `dsse.sigstore.json`             | `pkg/testing/data/bundles/dsse.sigstore.json`      |
| `scaffolding-trusted-root.json`  | `pkg/testing/data/trusted-roots/scaffolding.json`  |

`othername.sigstore.json` is a message-signature Sigstore bundle with a
Fulcio certificate and an integrated Rekor transparency-log entry. It
verifies against `scaffolding-trusted-root.json` for the artifact whose
SHA-256 is `bc103b4a84971ef6459b294a2b98568a2bfb72cded09d4acd1e16366a401f95b`.
The integrated tlog timestamp counts as an observer timestamp, so the
bundle satisfies our Verifier's WithObserverTimestamps(1) +
WithTransparencyLog(1) policy indefinitely (verification is anchored to
the log timestamp, not wall-clock).

Do not regenerate or mutate these bytes; the signature is real.

Upstream license: Apache-2.0 (see the sigstore-go LICENSE).

`dsse.sigstore.json` is a genuinely-signed **DSSE in-toto** Sigstore bundle
(a SLSA-provenance statement over `slsa-provenance-0.0.7.tgz`) with a Fulcio
certificate and an integrated Rekor transparency-log entry. Its Rekor log id
matches the **public-good** production root, so it verifies against
`public-good-trusted-root.json` (not scaffolding). It exists to exercise the
REAL crypto through the DSSE-envelope path — the same shape
`provenance.huggingfaceChecker.Check` consumes (BundleSubjects → Verify) —
rather than only the message-signature shape of `othername.sigstore.json`.

Its subject is bound by **sha512**, so `Verify()` (which pins a sha256
artifact-digest policy) fails at the final digest-match step *after* all crypto
passes. That is a deliberate, useful signal: the late failure proves the DSSE
cert/tlog/signature crypto ran. It also marks a boundary — see below.

Do not regenerate or mutate these bytes; the signatures are real.

`public-good-trusted-root.json` (upstream `pkg/testing/data/trusted-roots/public-good.json`)
is the production Sigstore root. It is used both as a negative control (a
scaffolding-signed bundle must NOT verify under it) and as the pinned root for
the genuinely-signed `dsse.sigstore.json` DSSE bundle.

## Boundary: sha256-anchored DSSE SUCCESS is not proven offline

`huggingfaceChecker.Check` anchors DSSE verification on a **sha256** subject
digest. No genuinely-signed DSSE bundle with a sha256-bound subject exists in
the offline sigstore-go corpus (every DSSE fixture is sha512-bound), so the
end-to-end `BundleSubjects → Verify(sha256-anchor) → SUCCESS` path cannot be
driven to a passing verdict with real bytes here. What IS proven with real
bytes: (1) the DSSE parse/subject-extraction path (`TestRealDSSEBundleSubjects…`),
(2) the DSSE cert/tlog/signature crypto executing end-to-end
(`TestRealDSSEVerifyRunsCryptoThenDigestMatch` — fails only at the post-crypto
digest match), and (3) DSSE signature tamper rejection in the crypto stage
(`TestRealDSSETamperedSignatureRejected`). The sha256-anchor SUCCESS verdict
itself remains covered only by the stubbed-crypto `Check()` tests until a
sha256-bound signed DSSE fixture is available.

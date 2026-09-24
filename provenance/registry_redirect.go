package provenance

// Following a registry's artifact-CDN redirect, without weakening the SSRF
// guard that refuses redirects everywhere else.
//
// httpclient's guarded constructor sets CheckRedirect to ErrUseLastResponse
// for every SSRF-guarded client, and the reasoning there is sound: "a silent
// 302 chain off a tenant-supplied URL is not something any of these callers
// want to follow." A provenance URL is only half tenant-supplied — the host
// comes from the checker's configured baseURL and only the path carries the
// coordinate — but a group ID containing "//evil.com" can still move the host,
// which is exactly what the guard is for.
//
// The cost of blanket refusal, measured in prod 2026-09-23: plugins.gradle.org
// answers every /m2 artifact with a 303 to plugins-artifacts.gradle.org, so
// 2,078 gradle attestations — 21% of every failed attestation in the corpus —
// recorded "HTTP 303" as a verification FAILURE. Reproduced directly:
//
//	GET  plugins.gradle.org/m2/.../kotlin-gradle-plugin-1.9.0.pom.asc  -> 303
//	     Location: plugins-artifacts.gradle.org/...
//	same, followed                                                     -> 200
//
// So this narrows the refusal instead of lifting it: a hop is followed only
// when its target host is on an explicit allowlist, and everything else still
// gets ErrUseLastResponse. Two properties are preserved by construction,
// because the derived client is a shallow copy that keeps the SAME Transport:
// the SSRF-safe dialer still blocks internal addresses on every hop (defence
// in depth — the allowlist is about not being used as a proxy to arbitrary
// EXTERNAL hosts, not about internal ones), and egress counting still sees
// every request.
//
// An explicit list, not a same-registrable-domain rule. The general rule is
// tempting and would cover HuggingFace's 307s too, but doing it correctly
// needs the public suffix list, and hand-rolling "same last two labels" is
// wrong for co.uk-shaped domains — not a thing to approximate inside a
// security control. The list is short and each entry is evidence-backed.

import (
	"errors"
	"net/http"
)

// registryRedirectHosts are artifact CDNs that registries on the provenance
// path redirect to. Add a host here only with a reproduced redirect.
var registryRedirectHosts = map[string]struct{}{
	// plugins.gradle.org/m2/... -> 303 (verified 2026-09-23)
	"plugins-artifacts.gradle.org": {},
	// huggingface.co -> huggingface.co, a SAME-HOST repo rename (verified
	// 2026-09-24). HF moved its canonical legacy models under organisations
	// and 307s the old paths: /api/models/gpt2 ->
	// /api/models/openai-community/gpt2, bert-base-uncased -> google-bert/...,
	// t5-base -> google-t5/... . Five production reports recorded "HTTP 307"
	// as a verification FAILURE for exactly those models.
	//
	// An earlier note in plan_signal_repair said HF could not use this
	// mechanism because its CDN host is region-dependent. That is true of the
	// LFS *download* redirect (us.aws.cdn.hf.co and siblings) and irrelevant
	// here — none of the corpus failures is that redirect. The hop that
	// actually fails is host-invariant.
	"huggingface.co": {},
}

// maxRegistryRedirects bounds a chain. Go's default is 10; one hop is all any
// known registry needs, and a low bound keeps a redirect loop cheap.
const maxRegistryRedirects = 4

// followRegistryRedirects derives a client that follows a redirect only to a
// host in allowed. The copy shares the original's Transport, so the SSRF-safe
// dialer and the egress counter both still apply to every hop.
//
// A nil base returns nil: callers construct the real client once at startup,
// and a nil here means a test built a checker without one.
func followRegistryRedirects(base *http.Client, allowed map[string]struct{}) *http.Client {
	if base == nil {
		return nil
	}
	derived := *base
	derived.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRegistryRedirects {
			return errors.New("too many redirects")
		}
		if _, ok := allowed[req.URL.Hostname()]; ok {
			return nil
		}
		// Unchanged from the guarded default: hand back the redirect
		// response itself rather than chasing it.
		return http.ErrUseLastResponse
	}
	return &derived
}

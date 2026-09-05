package cli

// doctor_orgslug.go — `chainsaw doctor` wrong-org-slug check (WS2 #10,
// plan_10of10_surfaces).
//
// The silent-insecure trap this closes: a client that routes installs
// through an org-scoped proxy URL (<server>/repository/@<slug>/<eco>/...)
// with the WRONG or MISSING org slug is rejected by the backend BEFORE any
// package coordinate is evaluated:
//
//   - missing @<slug> on an instance that requires one → CHW-4314 / HTTP 400
//     (errcodes.CodeOrgSlugRequired), and
//   - a wrong / typo'd @<slug> → CHW-1303 / HTTP 404
//     (errcodes.CodeUnknownOrganization).
//
// In both cases every `npm install` (etc.) 4xx's at the edge and the guard
// NEVER fires — but the client tool falls back to upstream and the install
// "works", so the operator sees no signal that their supply-chain firewall
// is dead on arrival. This is the worst failure class for a security tool:
// silently NOT protecting.
//
// The check probes the org-scoped repo path with the caller's resolved org
// slug and classifies the response:
//
//   OK        the org-scoped path is accepted (2xx / 401 / 403 / anything
//             that is neither the org-slug rejection nor a 404).
//             The slug routes; the guard would fire. Passes SILENTLY.
//   WRONGSLUG the probe came back CHW-4314 (400) or CHW-1303 (404 unknown
//             org). The slug is wrong/missing — LOUD failure + remediation,
//             non-zero exit.
//
// WHAT THIS PROBE CAN NO LONGER SEE. The server used to answer an unknown
// @<slug> with 404/CHW-1303 to anyone, which made the unauthenticated
// /repository/@<slug>/… path an org-enumeration oracle: a real slug 401'd,
// an invented one 404'd, so the internet could ask "does @acme exist?" for
// free. It now masks an unknown slug as the same 401 a real one returns
// unless the caller presents valid repository credentials
// (server_repo_pipeline.go, repositoryPreflight).
//
// This probe sends the user's session token, which is NOT a repository
// credential, so it is anonymous as far as that endpoint is concerned and
// its WRONGSLUG arm is now reachable only for the CHW-4314 missing-slug
// case. That is an acceptable trade because the slug this check probes
// always comes from /api/orgs — the caller's own slug, never a typed one —
// so a typo could not reach here anyway, and a client that IS misconfigured
// sends its own credentials and still gets the full CHW-1303 diagnostic on
// its first install. What the 401 branch must NOT do is keep claiming it
// verified the slug; see the reason string in probeOrgSlug.
//   UNROUTED  the probe came back 404 with no CHW envelope: nothing is
//             mounted at the repository path this client would use. Same
//             dead-on-arrival consequence as a wrong slug, different cause
//             and different fix — LOUD failure + remediation, non-zero exit.
//   SKIPPED   no server / no token / no resolvable slug — nothing to probe.
//             Not a failure (the free local guard needs no slug).
//   NETERR    the probe could not reach the server (DNS, connect, TLS,
//             timeout). We CANNOT conclude the slug is wrong, so we must
//             NOT emit the alarming WRONGSLUG verdict — a flaky network is
//             not a misconfiguration. Reported, exit 0.
//
// LOAD-BEARING (plan guardrail): fail CLOSED and LOUD on a genuine wrong
// slug, exit non-zero, and DISTINGUISH a 400/CHW-4314 (or 404/CHW-1303)
// from a transient network error so a timeout never produces a false
// "wrong slug".

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/cli/hook"
	"github.com/chain305/chainsaw-core/httpclient"
)

// orgSlugOutcome is the four-valued verdict of the org-slug probe.
type orgSlugOutcome string

const (
	orgSlugOK        orgSlugOutcome = "OK"
	orgSlugWrongSlug orgSlugOutcome = "WRONG_SLUG"
	// orgSlugUnrouted is a 404 that is NOT the unknown-org rejection: the
	// repository path a wired client would use isn't served at all. Split
	// out from WRONG_SLUG because the slug may be perfectly correct — the
	// base path is what's wrong — so the remediation differs.
	orgSlugUnrouted orgSlugOutcome = "PATH_NOT_ROUTED"
	orgSlugSkipped  orgSlugOutcome = "SKIPPED"
	orgSlugNetErr   orgSlugOutcome = "NET_ERROR"
)

// orgSlugResult is the structured result of the check. Stable JSON shape so
// CI can branch on Outcome without scraping text.
type orgSlugResult struct {
	Outcome   orgSlugOutcome `json:"outcome"`
	Slug      string         `json:"slug,omitempty"`
	ProbeURL  string         `json:"probe_url,omitempty"`
	ErrorCode string         `json:"error_code,omitempty"`
	Status    int            `json:"status,omitempty"`
	Reason    string         `json:"reason,omitempty"`
}

// orgSlugProbeEcosystem is the ecosystem whose org-scoped repo path we probe.
// "npmjs" is the seeded npm repo name (configs/seed.yaml) and the one
// install-hook npm actually writes, so the probe exercises a path a wired
// client really uses. Its base path (<server>/repository/@<slug>/npmjs/) is a
// cheap, side-effect-free GET — the org-slug guard fires on it BEFORE any
// package coordinate is resolved, which is exactly what we want to test.
//
// It used to be "npm", a repository name nothing registers. That was
// survivable only because the auth gate answers before repo resolution; now
// that a 404 is a failure verdict, the probe must name the real repo.
const orgSlugProbeEcosystem = "npmjs"

// orgSlugProbeTimeout bounds the single probe request. Short — this is a
// diagnostic, not a download — but long enough to absorb a slow TLS
// handshake on a cold connection.
const orgSlugProbeTimeout = 8 * time.Second

// runDoctorOrgSlugCheck resolves the caller's org slug, probes the
// org-scoped repo path, and reports the verdict. Returns a non-nil error
// ONLY on a genuine wrong/missing slug (so cobra's exit path yields a
// non-zero code); SKIPPED and NET_ERROR return nil. This is invoked from
// the standard `chainsaw doctor` run after the manager table so a
// misconfigured proxy slug always fails loud.
func runDoctorOrgSlugCheck(cmd *cobra.Command, jsonMode bool) error {
	res := probeOrgSlug(cmd.Context(), cfgServerURL(), cfgToken(), resolveDoctorOrgSlug(cmd))

	if !jsonMode {
		printOrgSlugResult(cmd, res)
	}

	// Telemetry: same nil-safe cliEmit seam the rest of doctor uses. Anonymous
	// dimensions only — outcome + error_code, never the slug itself.
	cliEmit(telemetryEventDoctorOrgSlug, map[string]any{
		"outcome":    string(res.Outcome),
		"error_code": res.ErrorCode,
	})

	if res.Outcome == orgSlugWrongSlug || res.Outcome == orgSlugUnrouted {
		// Fail CLOSED + LOUD: non-zero exit so CI gates catch the
		// dead-on-arrival config. Returning an error routes through cobra's
		// error path (renderError) and flushes the deferred telemetry, same
		// as the rest of the CLI — no os.Exit that would bypass either.
		return &orgSlugCheckError{res: res}
	}
	return nil
}

// telemetryEventDoctorOrgSlug is the event name for the org-slug probe
// outcome. Reuses the existing cli.doctor.* namespace; the emit rides the
// same cliEmit seam as EventCLIDoctorRun. Kept as a literal (not a
// registered telemetry const) because the CLI emit path drops unregistered
// names silently — until this is added to the events registry it is a
// best-effort local signal, not a shipped catalog event. Registering it is
// a follow-up owned by the telemetry catalog.
const telemetryEventDoctorOrgSlug = "cli.doctor.org_slug_check"

// orgSlugCheckError is the loud, exit-non-zero error returned on a genuine
// wrong-slug verdict. A distinct type so output formatters can recognise it
// and the human-readable remediation is printed by printOrgSlugResult
// (not by the generic error renderer, which would double-print).
type orgSlugCheckError struct {
	res orgSlugResult
}

func (e *orgSlugCheckError) Error() string {
	code := e.res.ErrorCode
	if code == "" {
		code = fmt.Sprintf("HTTP %d", e.res.Status)
	}
	if e.res.Outcome == orgSlugUnrouted {
		return fmt.Sprintf("org-scoped repository path is not served — the install guard did NOT fire (%s)", code)
	}
	return fmt.Sprintf("wrong org slug — the install guard did NOT fire (%s)", code)
}

// resolveDoctorOrgSlug resolves the org slug doctor should probe. It always
// goes through /api/orgs, and deliberately does NOT read a --org flag.
//
// It used to, guarded by `if f := cmd.Flags().Lookup("org"); f != nil` and a
// comment claiming "doctor has no --org flag today". That premise was wrong:
// cobra's mergePersistentFlags folds root's persistent flags into
// cmd.Flags(), so Lookup("org") finds root's --org — which is an org *ID*
// ("Org ID (overrides config)", and org.go actively teaches
// `chainsaw --org <id>`). resolveOrgSlug returns a flag value UNCHANGED as
// the slug, while the server resolves the probe path by slug only. So
// `chainsaw --org <uuid> doctor` on a correctly-wired multi-org machine
// probed a nonexistent slug, got CHW-1303, and printed the loudest failure
// doctor has — "WRONG ORG SLUG — the install guard did NOT fire ... A
// malicious or typosquatted package would sail through" — plus a
// remediation telling the user to re-wire something that was never broken.
//
// /api/orgs already resolves the caller's identity to the right slug
// (o.ID == me.OrgID → o.Slug), which is the ID→slug translation the flag
// path skipped. Returns "" when nothing resolves — the caller reports
// SKIPPED.
func resolveDoctorOrgSlug(cmd *cobra.Command) string {
	slug, err := resolveOrgSlug(cmd, cfgServerURL(), "")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(slug)
}

// probeOrgSlug issues ONE GET against the org-scoped repo path and classifies
// the result. Pure w.r.t. globals: server, token, and slug are passed in so
// the classifier is table-testable against an httptest server.
//
// Classification order (fail-closed):
//   - no server / no slug              → SKIPPED (nothing to probe; the
//     free local guard needs no slug)
//   - transport error (DNS/connect/TLS/timeout) → NET_ERROR (cannot conclude
//     the slug is wrong — must NOT false-positive)
//   - body/status carries CHW-4314 or CHW-1303 → WRONG_SLUG (loud fail)
//   - anything else (2xx, 401, 403, a plain 404 that is NOT the unknown-org
//     code, etc.)                      → OK (the slug routes; passes silently)
func probeOrgSlug(ctx context.Context, server, token, slug string) orgSlugResult {
	server = strings.TrimSpace(server)
	slug = strings.TrimSpace(slug)
	if server == "" {
		return orgSlugResult{Outcome: orgSlugSkipped, Reason: "no server configured (free local guard needs no org slug)"}
	}
	if slug == "" {
		return orgSlugResult{Outcome: orgSlugSkipped, Reason: "could not resolve an org slug (not authenticated, or no --org). Run `chainsaw auth login` to enable this check."}
	}

	probeURL := orgSlugProbeURL(server, slug)
	res := orgSlugResult{Slug: slug, ProbeURL: probeURL}

	reqCtx, cancel := context.WithTimeout(ctx, orgSlugProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, probeURL, nil)
	if err != nil {
		// A malformed URL is a config problem, but it is NOT the org-slug
		// rejection — report it as a network/setup error, never WRONG_SLUG.
		res.Outcome = orgSlugNetErr
		res.Reason = fmt.Sprintf("could not build probe request: %v", err)
		return res
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := httpclient.New(httpclient.WithTimeout(orgSlugProbeTimeout))
	resp, err := client.Do(req)
	if err != nil {
		// Transport failure — DNS, connect refused, TLS, or the context
		// deadline. We CANNOT prove the slug is wrong, so degrade to
		// NET_ERROR. This is the load-bearing guardrail: a timeout must
		// never masquerade as a wrong-slug finding.
		res.Outcome = orgSlugNetErr
		if errors.Is(err, context.DeadlineExceeded) {
			res.Reason = fmt.Sprintf("probe timed out after %s (server unreachable or slow) — cannot verify the org slug; this is NOT reported as a wrong slug", orgSlugProbeTimeout)
		} else {
			res.Reason = fmt.Sprintf("probe transport error (%v) — cannot verify the org slug; this is NOT reported as a wrong slug", err)
		}
		return res
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	res.Status = resp.StatusCode

	if code, isSlug := classifyOrgSlugRejection(resp.StatusCode, body); isSlug {
		res.Outcome = orgSlugWrongSlug
		res.ErrorCode = code
		res.Reason = "the proxy rejected the org-scoped repository path for this slug"
		return res
	}

	// A 404 that is not CHW-1303 means nothing answers at the repository
	// path — the router never matched it. It used to fall through to OK,
	// which is how `chainsaw doctor` certified a completely dead URL as
	// "the guard would fire for this slug" (B5): install-hook wrote a
	// hardcoded /chainproxy prefix that only exists as an OPTIONAL edge
	// mount, and doctor probed the same dead URL and passed on its 404.
	//
	// A proxy that serves this deployment answers the repository BASE path
	// with 401 (CHW-1001, client credentials required), 403, or a structured
	// CHW envelope — never a bare 404. So this is evidence of a real break,
	// not a nonexistent-package miss (the probe names no package).
	if resp.StatusCode == http.StatusNotFound {
		res.Outcome = orgSlugUnrouted
		res.Reason = "nothing is served at the org-scoped repository path; every install through this config would 404"
		return res
	}

	if resp.StatusCode == http.StatusUnauthorized {
		// A 401 proves the proxy serves this path, which is what rules out
		// the dead-on-arrival config this check exists for. It does NOT
		// prove the slug resolves: the server deliberately answers an
		// unknown slug with this same 401 so the endpoint cannot be used to
		// enumerate orgs. Say so rather than certifying "the guard would
		// fire", which is the overclaim that would let a real break pass.
		res.Outcome = orgSlugOK
		res.Reason = "org-scoped repository path is served (401, credentials required). Unknown slugs are masked as 401 too, so this does not by itself confirm the slug resolves — a wrong slug surfaces on the first real install, which sends credentials"
		return res
	}

	res.Outcome = orgSlugOK
	res.Reason = "org-scoped repository path accepted; the guard would fire for this slug"
	return res
}

// classifyOrgSlugRejection reports whether an HTTP response is the org-slug
// rejection (CHW-4314 missing slug / HTTP 400, or CHW-1303 unknown org /
// HTTP 404) and returns the matched CHW code. This is the SINGLE place the
// wrong-slug decision is made, so it is unit-testable in isolation.
//
// Detection is by structured error code FIRST (the reliable signal — the
// server always emits a {"code":"CHW-...."} envelope for these), with a
// status-code fallback ONLY when the code is present in the body. We do NOT
// treat a bare 400/404 with no CHW code as a slug rejection: a generic 404
// (e.g. a nonexistent package on a CORRECT slug) must classify as OK, not
// WRONG_SLUG, or every probe of an empty repo would false-positive.
func classifyOrgSlugRejection(status int, body []byte) (code string, isSlugRejection bool) {
	var env struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(body, &env)
	switch strings.TrimSpace(env.Code) {
	case "CHW-4314":
		return "CHW-4314", true
	case "CHW-1303":
		return "CHW-1303", true
	}
	// Defensive fallback: some edge proxies may re-wrap the body. If the raw
	// body carries the code string AND the status matches the documented
	// rejection status, honour it. Still requires the code substring so a
	// generic 400/404 with no CHW marker is NOT misread as a slug rejection.
	if status == http.StatusBadRequest && bodyContains(body, "CHW-4314") {
		return "CHW-4314", true
	}
	if status == http.StatusNotFound && bodyContains(body, "CHW-1303") {
		return "CHW-1303", true
	}
	return "", false
}

// bodyContains is a small case-sensitive substring check on the response
// body. CHW codes are upper-case ASCII so no folding is needed.
func bodyContains(body []byte, needle string) bool {
	return strings.Contains(string(body), needle)
}

// orgSlugProbeURL builds the org-scoped repo base path for the probe:
// <server>/repository/@<slug>/npmjs/. Uses the same helpers install-hook
// uses — normalizeHookServerURL for the base and hook.OrgScopedRepoPath for
// the path — so the probed URL is byte-identical to what a wired client
// requests. That identity is the whole point: if the probe and the emitted
// config can disagree, doctor can pass while every install 404s.
//
// The base path comes from the configured server URL and nowhere else (B5).
// This used to splice a hardcoded `chainproxy/` in and un-double it when the
// server URL already ended in one — which meant a root-mounted deployment
// (`--server http://localhost:8787`) was probed at a path the server does
// not route, always 404'd, and was then classified OK.
func orgSlugProbeURL(server, slug string) string {
	base := normalizeHookServerURL(server)
	return base + "/" + hook.OrgScopedRepoPath(slug, orgSlugProbeEcosystem) + "/"
}

// printOrgSlugResult renders the human-readable verdict. The LOUD wrong-slug
// path prints the explicit "block did NOT fire" message + remediation to
// stderr; OK passes silently (no output on the happy path — doctor already
// prints plenty); SKIPPED/NET_ERROR print a one-line note.
func printOrgSlugResult(cmd *cobra.Command, res orgSlugResult) {
	out := cmd.OutOrStdout()
	errOut := cmd.ErrOrStderr()
	switch res.Outcome {
	case orgSlugOK:
		// Silent on success per the plan's "on a valid slug pass silently".
	case orgSlugWrongSlug:
		fmt.Fprintln(errOut, "")
		fmt.Fprintf(errOut, "FAIL  org slug: WRONG ORG SLUG — the install guard did NOT fire.\n")
		fmt.Fprintf(errOut, "      The proxy rejected the org-scoped path %q with %s.\n", res.ProbeURL, orgSlugCodeLabel(res))
		fmt.Fprintln(errOut, "      Every install through this config 4xx's at the edge, the client")
		fmt.Fprintln(errOut, "      falls back to the public registry, and NOTHING is checked. A")
		fmt.Fprintln(errOut, "      malicious or typosquatted package would sail through.")
		fmt.Fprintln(errOut, "      Fix:")
		fmt.Fprintln(errOut, "        1. Copy the ready-made config (with your REAL org slug) from the")
		fmt.Fprintln(errOut, "           dashboard: Settings → Client Credentials → New, or run:")
		fmt.Fprintln(errOut, "             chainsaw install-hook <manager> --org <your-org-slug>")
		fmt.Fprintln(errOut, "        2. Re-run `chainsaw doctor` to confirm the slug now routes.")
		fmt.Fprintf(errOut, "      See https://docs.chain305.com/errors/%s\n", firstNonEmpty(res.ErrorCode, "CHW-4314"))
	case orgSlugUnrouted:
		fmt.Fprintln(errOut, "")
		fmt.Fprintf(errOut, "FAIL  org slug: REPOSITORY PATH NOT SERVED — the install guard did NOT fire.\n")
		fmt.Fprintf(errOut, "      %q returned HTTP 404 with no chainsaw error envelope, so\n", res.ProbeURL)
		fmt.Fprintln(errOut, "      nothing is mounted there. Every install through this config 4xx's,")
		fmt.Fprintln(errOut, "      the client falls back to the public registry, and NOTHING is")
		fmt.Fprintln(errOut, "      checked. A malicious or typosquatted package would sail through.")
		fmt.Fprintln(errOut, "      The org slug itself may be fine — this is about the URL's base path.")
		fmt.Fprintln(errOut, "      Fix:")
		fmt.Fprintln(errOut, "        1. Point --server at the base URL your proxy is actually served")
		fmt.Fprintln(errOut, "           on, INCLUDING any edge prefix. Behind an nginx/Traefik mount:")
		fmt.Fprintln(errOut, "             chainsaw --server https://chain305.com/chainproxy doctor")
		fmt.Fprintln(errOut, "           Served at the root (docker compose, port-forward, bare binary):")
		fmt.Fprintln(errOut, "             chainsaw --server http://localhost:8787 doctor")
		fmt.Fprintln(errOut, "        2. Re-run `chainsaw install-hook <manager>` so the wired config")
		fmt.Fprintln(errOut, "           picks up the corrected base, then `chainsaw doctor` to confirm.")
	case orgSlugSkipped:
		fmt.Fprintf(out, "org slug: skipped — %s\n", res.Reason)
	case orgSlugNetErr:
		fmt.Fprintf(errOut, "org slug: could not verify — %s\n", res.Reason)
	}
}

// orgSlugCodeLabel renders the CHW code + HTTP status for the failure line.
func orgSlugCodeLabel(res orgSlugResult) string {
	switch {
	case res.ErrorCode != "" && res.Status > 0:
		return fmt.Sprintf("%s (HTTP %d)", res.ErrorCode, res.Status)
	case res.ErrorCode != "":
		return res.ErrorCode
	case res.Status > 0:
		return fmt.Sprintf("HTTP %d", res.Status)
	default:
		return "an org-slug rejection"
	}
}

// orgSlugResultForJSON exposes the probe result for `chainsaw doctor --json`
// so the org-slug verdict rides in the JSON report alongside the manager
// table. Returns nil when the check was skipped with no server (keeps the
// JSON payload clean for the common free-local-guard case). Kept separate
// from the human path so JSON callers get the structured verdict without the
// multi-line remediation text.
func orgSlugResultForJSON(cmd *cobra.Command) *orgSlugResult {
	res := probeOrgSlug(cmd.Context(), cfgServerURL(), cfgToken(), resolveDoctorOrgSlug(cmd))
	if res.Outcome == orgSlugSkipped && strings.TrimSpace(cfgServerURL()) == "" {
		return nil
	}
	return &res
}

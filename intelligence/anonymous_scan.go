package intelligence

// AnonymousScanSafe reports whether a coordinate in this ecosystem may be
// scanned with an EMPTY orgID — i.e. by an unauthenticated public caller
// whose result is written to the shared, federated row.
//
// WHY THIS IS NOT SIMPLY "true" AFTER FEDERATION.
//
// Federation removed every org-derived value from the stored row for the
// ecosystems OSV covers: provider_cve.go gates the Trivy-backed cveProvider
// OFF the write path for them, so a scan carries no tenant data regardless of
// who asked for it.
//
// It is deliberately still ON for ecosystems that have a scanner advisory
// source — docker is the live case — because OSV does not cover them and
// dropping the lane would lose their vulnerability data entirely. That lane
// reads org-scoped `vulnerability_metadata` through
// `p.store.ForOrg(req.OrgID)`, and `tenancy.NormalizeOrgID("")` resolves the
// empty string to `org-default`, which is a REAL org with real private Trivy
// findings — not a null tenant.
//
// So an anonymous scan of a docker coordinate would read org-default's private
// CVE rows and merge them into a row every tenant and the public internet can
// then read. That is exactly the cross-tenant leak federation was built to
// close, surviving in the one lane federation deliberately left open.
//
// The public on-demand scan endpoint therefore refuses these ecosystems rather
// than scanning them with a tenant identity it has no right to. Cached rows for
// them still SERVE on the read path — reading what is already stored is
// unchanged — only anonymous WRITES are refused.
//
// If the docker lane ever gets an org-independent advisory source, delete this
// function rather than loosening it, and let the callers fall through to the
// federated path.
func AnonymousScanSafe(ecosystem string) bool {
	return !ecosystemHasScannerAdvisorySource(CanonicalKey(Key{Ecosystem: ecosystem}).Ecosystem)
}

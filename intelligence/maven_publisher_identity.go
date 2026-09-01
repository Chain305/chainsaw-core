package intelligence

import "strings"

// MavenDeveloperPublisherIDs resolves the publisher identity for a single
// Maven POM `<developer>` entry, in the precedence Maven itself treats as
// canonical: `<id>` first, then `<email>`, then `<name>`. It returns the
// raw (untrimmed-case) identifiers; callers lowercase/dedupe with their
// own normaliser.
//
// P8-70 (2026-09-02) — why this exists as ONE function.
//
// This precedence used to be duplicated in two places that disagreed:
//
//   - the INCOMING side (runMaven in provider_registrymetadata.go, which
//     populates Report.People.PublisherIDs) preferred `<email>`, then
//     `<name>`, and never read `<id>` at all;
//   - the BASELINE side (fetchMavenPublisherSet in
//     internal/server/package_metadata.go, which writes the persisted
//     package_metadata.publisher_set column) preferred `<id>`.
//
// For the ordinary Apache-style POM those two identifier spaces never
// intersect — `ggregory` on one side, `ggregory@apache.org` on the other
// — so the publisher-set diff in the metadiff provider saw a COMPLETE
// replacement on every maven/gradle package that had any prior version
// persisted, and fired sc.publisher_changed (SevHigh, weight -25,
// MaxImpact 40, and the -55 CompoundSCTakeoverSignature) on packages
// whose developer roster had not changed at all.
//
// Measured against prod on 2026-09-01, before this fix: all 30
// maven/gradle coordinates carrying publisherChanged=true had a
// ZERO-SIZE intersection between the incoming set and the baseline set —
// 30/30 were false positives produced by this mismatch rather than by
// any roster change. Nineteen of the 30 have byte-identical `<id>` sets
// across the two versions being compared (e.g. every
// org.apache.commons:commons-lang3 pair). The only maven rows that ever
// came back publisherChanged=false were org.apache.maven:maven-parent,
// forced false by the canonicalParentPOMs allowlist.
//
// `<id>` wins the precedence because it is the stable key. Emails move
// with employer (`ggregory@seagullsw.com` -> `ggregory@apache.org` between
// commons-lang 2.6 and commons-lang3) and are routinely obfuscated in
// Apache POMs (`ggregory at apache.org`, `rahul AT apache DOT org`), while
// display names change spelling (`Gary D. Gregory` -> `Gary Gregory`).
// None of those is a publisher change, and all three shapes were flipping
// a SevHigh signal.
//
// Both sides MUST route through this function. The guard test
// TestMavenPublisherIdentity_ExtractorsAgree pins that.
func MavenDeveloperPublisherIDs(id, email, name string) []string {
	if v := strings.TrimSpace(id); v != "" {
		return []string{v}
	}
	if emails := SplitMavenDeveloperEmails(email); len(emails) > 0 {
		return emails
	}
	if v := strings.TrimSpace(name); v != "" {
		return []string{v}
	}
	return nil
}

// SplitMavenDeveloperEmails pulls identifiers out of a POM `<email>`
// element. The element is nominally a single address but is in practice a
// free-form field: some POMs carry a comma-separated list, and some carry
// a `Name <addr>` render. Angle-wrapped chunks reduce to the address;
// everything else passes through verbatim so the normaliser downstream
// still has a stable string to compare on.
//
// Kept in core (rather than reusing internal/server's PyPI splitter) so
// the maven baseline and the maven incoming side cannot drift apart
// again — see MavenDeveloperPublisherIDs.
func SplitMavenDeveloperEmails(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	out := make([]string, 0, 2)
	for _, chunk := range strings.Split(raw, ",") {
		chunk = strings.TrimSpace(chunk)
		if chunk == "" {
			continue
		}
		if i := strings.Index(chunk, "<"); i >= 0 {
			if j := strings.Index(chunk[i+1:], ">"); j >= 0 {
				if inner := strings.TrimSpace(chunk[i+1 : i+1+j]); inner != "" {
					out = append(out, inner)
				}
				continue
			}
		}
		out = append(out, chunk)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

package intelligence

import "strings"

// UserAgent builds the User-Agent every intelligence-path HTTP request
// sends to an upstream registry.
//
// Three registries ask for a contact URL by name in their crawler
// policy — PyPI, crates.io and Sonatype (Maven Central) — and the
// difference between a UA they can reach someone at and a bare token is
// the difference between being throttled and being banned. Before this
// existed the intelligence path sent "chainsaw-intelligence/1" and five
// other hand-written variants, none of which carried a version or a
// contact, while two sites elsewhere in the tree
// (internal/server/public_artifact_fetch.go, package_metadata.go) had
// already settled on the right shape. This is that shape, in one place.
//
// The component names the caller so a registry operator reading their
// logs can tell a dependency walk from a download-count poll and rate
// the two differently, which is the whole reason the old strings
// carried suffixes at all.
//
//	UserAgent("deps")  →  "chainsaw-intelligence/<ver> (deps; +https://chain305.com)"
//	UserAgent("")      →  "chainsaw-intelligence/<ver> (+https://chain305.com)"
func UserAgent(component string) string {
	var b strings.Builder
	b.WriteString(userAgentProduct)
	b.WriteByte('/')
	b.WriteString(UserAgentVersion)
	b.WriteString(" (")
	if c := strings.TrimSpace(component); c != "" {
		b.WriteString(c)
		b.WriteString("; ")
	}
	b.WriteString("+")
	b.WriteString(userAgentContact)
	b.WriteByte(')')
	return b.String()
}

const (
	userAgentProduct = "chainsaw-intelligence"
	// userAgentContact must stay a URL a registry operator can actually
	// reach a human through. A mailto: or a docs page both work; an
	// unreachable one is worse than none, because it reads as an attempt
	// to look compliant.
	userAgentContact = "https://chain305.com"
)

// UserAgentVersion is the version the intelligence path reports.
//
// It is a var, not a const, so a build can stamp the real release over
// it with -ldflags. The default is deliberately not "1": a registry
// operator seeing an unchanging major for years cannot tell a current
// deployment from a three-year-old one, which is the thing the version
// in a UA is for.
var UserAgentVersion = "0.21"

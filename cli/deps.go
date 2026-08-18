package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// sbomDoc mirrors the CycloneDX BOM envelope returned by GET /api/sbom.
type sbomDoc struct {
	BOMFormat  string          `json:"bomFormat"`
	Components []sbomComponent `json:"components"`
}

// sbomComponent mirrors a CycloneDX component.
type sbomComponent struct {
	Name       string         `json:"name"`
	Version    string         `json:"version"`
	PURL       string         `json:"purl,omitempty"`
	Licenses   []sbomLicense  `json:"licenses,omitempty"`
	Properties []sbomProperty `json:"properties,omitempty"`
}

type sbomLicense struct {
	License struct {
		ID string `json:"id,omitempty"`
	} `json:"license"`
}

type sbomProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// --- Commands ---

var depsCmd = &cobra.Command{
	Use:     "deps",
	Short:   "Dependency commands",
	GroupID: GrpIntel,
}

var depsTreeCmd = &cobra.Command{
	Use:   "tree <package@version>",
	Short: "Show transitive dependency context for a package from org SBOM",
	Args:  cobra.ExactArgs(1),
	RunE:  runDepsTree,
}

func init() {
	depsTreeCmd.Flags().Bool("vulnerable", false, "Show only vulnerable packages")
	depsTreeCmd.Flags().Bool("json", false, "Output as JSON")
	depsCmd.AddCommand(depsTreeCmd)
	rootCmd.AddCommand(depsCmd)
}

func runDepsTree(cmd *cobra.Command, args []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}

	g := glyphs()

	pkgName, pkgVersion := splitPackageArg(args[0])
	if pkgName == "" {
		// errors.New, not fmt.Errorf: with the separator interpolated the
		// format string stops being a constant, and `go vet`'s printf check
		// rejects a non-constant format with no arguments (correctly — a stray
		// % in an interpolated glyph would become a verb).
		return errors.New("invalid argument " + g.dash + " expected name@version")
	}

	// Fetch the full org SBOM; filter client-side so we see the complete
	// picture. We intentionally do NOT push a package_name filter to the
	// server: deps tree's value is the same-ecosystem PEER packages, and a
	// server-side package filter would strip exactly those. Surface a
	// progress line on stderr since the unfiltered fetch can be large.
	fmt.Fprintln(os.Stderr, "fetching org SBOM"+g.ellipsis)
	var bom sbomDoc
	if err := client.Get("/api/sbom", &bom); err != nil {
		return err
	}

	vulnOnly, _ := cmd.Flags().GetBool("vulnerable")
	asJSON := useJSON(cmd)

	// Separate the requested root package from the rest.
	var root *sbomComponent
	peers := make([]sbomComponent, 0, len(bom.Components))

	for i := range bom.Components {
		c := &bom.Components[i]
		if strings.EqualFold(c.Name, pkgName) && (pkgVersion == "" || c.Version == pkgVersion) {
			cp := *c
			root = &cp
		} else {
			peers = append(peers, *c)
		}
	}

	// Filter peers to the same ecosystem as the root (derived from PURL type).
	if root != nil && root.PURL != "" {
		eco := purlEcosystem(root.PURL)
		if eco != "" {
			filtered := peers[:0]
			for _, p := range peers {
				if purlEcosystem(p.PURL) == eco {
					filtered = append(filtered, p)
				}
			}
			peers = filtered
		}
	}

	// Apply --vulnerable filter.
	if vulnOnly {
		filtered := peers[:0]
		for _, p := range peers {
			if componentCVEs(p) != "" {
				filtered = append(filtered, p)
			}
		}
		peers = filtered
	}

	if asJSON {
		type treeOutput struct {
			Root  *sbomComponent  `json:"root,omitempty"`
			Peers []sbomComponent `json:"peers"`
		}
		return PrintJSONTo(cmd, treeOutput{Root: root, Peers: peers})
	}

	// Tree output. Both the connectors and the CVE marker come from the glyph
	// set: the connectors so the fallback has no exception list (they are the
	// one CP437-safe part of the set), the marker because it is the whole
	// point — a boxed ⚠ makes a vulnerable peer indistinguishable from a clean
	// one, which is the same state collapse the doctor matrix suffered.
	rootLabel := args[0]
	if root != nil {
		rootLabel = root.Name + "@" + root.Version
		rootLabel += depsCVESuffix(g, componentCVEs(*root))
	}
	fmt.Println(rootLabel)

	if len(peers) == 0 {
		label := "(no peer packages in same ecosystem)"
		if vulnOnly {
			label = "(no vulnerable packages in same ecosystem)"
		} else if root == nil {
			label = "(package not found in SBOM)"
		}
		fmt.Println(g.treeEnd + " " + label)
		return nil
	}

	for i, c := range peers {
		fmt.Println(depsTreeLine(g, c, i == len(peers)-1))
	}

	if root == nil {
		fmt.Printf("\nNote: %q was not found in the org SBOM. Showing all same-ecosystem packages.\n", args[0])
	}
	return nil
}

// depsCVESuffix renders the vulnerability annotation appended to a tree line,
// or "" when the component is clean. Split out from runDepsTree (which needs a
// live /api/sbom to run at all) so the glyph behaviour is unit-testable
// without a server.
func depsCVESuffix(g glyphSet, cves string) string {
	if cves == "" {
		return ""
	}
	return "  " + g.warn + "  " + cves
}

// depsTreeLine renders one peer row: connector, coordinate, CVE annotation.
// last selects the closing connector.
func depsTreeLine(g glyphSet, c sbomComponent, last bool) string {
	prefix := g.treeTee
	if last {
		prefix = g.treeEnd
	}
	return fmt.Sprintf("%s %s@%s%s", prefix, c.Name, c.Version, depsCVESuffix(g, componentCVEs(c)))
}

// purlEcosystem extracts the package type from a PURL string (e.g. "pkg:npm/foo@1.0" → "npm").
func purlEcosystem(purl string) string {
	s := strings.TrimPrefix(purl, "pkg:")
	if idx := strings.IndexByte(s, '/'); idx >= 0 {
		return s[:idx]
	}
	return ""
}

// componentCVEs returns the CVE list string from a component's properties, or "".
func componentCVEs(c sbomComponent) string {
	for _, p := range c.Properties {
		if p.Name == "chainsaw:vuln:cves" && p.Value != "" {
			return p.Value
		}
	}
	return ""
}

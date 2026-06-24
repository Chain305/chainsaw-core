package cli

import (
	"fmt"
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
	Use:   "deps",
	Short: "Dependency commands",
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

	pkgName, pkgVersion := splitPackageArg(args[0])
	if pkgName == "" {
		return fmt.Errorf("invalid argument — expected name@version")
	}

	// Fetch the full org SBOM; filter client-side so we see the complete picture.
	var bom sbomDoc
	if err := client.Get("/api/sbom", &bom); err != nil {
		return err
	}

	vulnOnly, _ := cmd.Flags().GetBool("vulnerable")
	asJSON, _ := cmd.Flags().GetBool("json")

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
		return PrintJSON(treeOutput{Root: root, Peers: peers})
	}

	// ASCII tree output.
	rootLabel := args[0]
	if root != nil {
		rootLabel = root.Name + "@" + root.Version
		if cves := componentCVEs(*root); cves != "" {
			rootLabel += "  ⚠  " + cves
		}
	}
	fmt.Println(rootLabel)

	if len(peers) == 0 {
		label := "(no peer packages in same ecosystem)"
		if vulnOnly {
			label = "(no vulnerable packages in same ecosystem)"
		} else if root == nil {
			label = "(package not found in SBOM)"
		}
		fmt.Println("└── " + label)
		return nil
	}

	for i, c := range peers {
		prefix := "├──"
		if i == len(peers)-1 {
			prefix = "└──"
		}
		line := fmt.Sprintf("%s %s@%s", prefix, c.Name, c.Version)
		if cves := componentCVEs(c); cves != "" {
			line += "  ⚠  " + cves
		}
		fmt.Println(line)
	}

	if root == nil {
		fmt.Printf("\nNote: %q was not found in the org SBOM. Showing all same-ecosystem packages.\n", args[0])
	}
	return nil
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

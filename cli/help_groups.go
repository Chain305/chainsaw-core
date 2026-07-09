package cli

// help_groups.go — organize `chainsaw --help` so commands appear under
// task-oriented headers instead of one alphabetical wall of 40+ entries.
//
// Seven groups span the product surface (TARGET & SCAN, POLICY & ENFORCEMENT,
// INTELLIGENCE, GUARD, AUDIT & FINDINGS, CONFIG & AUTH, DEBUG & DIAGNOSTICS).
// The group IDs/titles are exported constants so any command file can set
// cmd.GroupID = GrpGuard (etc.) directly.
//
// Most command files don't set GroupID themselves; assignment happens by
// command name from one map (applied in Execute, after every package init()
// has registered its commands) so ~30 files don't each need a GroupID line.
// Commands that DO set GroupID at definition time (the guard wrappers in
// guard_install.go) keep their value — the map only fills in commands that are
// still ungrouped. Any command in neither falls under cobra's default
// "Additional Commands" heading.

import "github.com/spf13/cobra"

// Group IDs. Exported so other files can reference them when setting
// cmd.GroupID. The Title is what renders as the section header in help.
const (
	GrpScan   = "grp-scan"   // TARGET & SCAN
	GrpPolicy = "grp-policy" // POLICY & ENFORCEMENT
	GrpIntel  = "grp-intel"  // INTELLIGENCE
	GrpGuard  = "grp-guard"  // GUARD (install-time)
	GrpAudit  = "grp-audit"  // AUDIT & FINDINGS
	GrpConfig = "grp-config" // CONFIG & AUTH
	GrpDebug  = "grp-debug"  // DEBUG & DIAGNOSTICS
)

// helpGroups is the ordered set of groups registered on rootCmd. Order here is
// the order sections render in help.
var helpGroups = []*cobra.Group{
	{ID: GrpScan, Title: "TARGET & SCAN:"},
	{ID: GrpPolicy, Title: "POLICY & ENFORCEMENT:"},
	{ID: GrpIntel, Title: "INTELLIGENCE:"},
	{ID: GrpGuard, Title: "GUARD (install-time):"},
	{ID: GrpAudit, Title: "AUDIT & FINDINGS:"},
	{ID: GrpConfig, Title: "CONFIG & AUTH:"},
	{ID: GrpDebug, Title: "DEBUG & DIAGNOSTICS:"},
}

// commandGroupByName maps a command's Name() to its help group. Guard commands
// (npm/pip/go/cargo/gem) set GroupID at definition time in guard_install.go and
// are intentionally NOT listed here; assignCommandGroups only fills commands
// that are still ungrouped, so an explicit GroupID is never overwritten.
var commandGroupByName = map[string]string{
	// TARGET & SCAN — point chainsaw at code/artifacts and scan them.
	"scan": GrpScan, "scan-repo": GrpScan, "scan-remote": GrpScan,
	"scan-actions": GrpScan, "pr-scan": GrpScan, "sbom": GrpScan,
	"bundle": GrpScan, "verify": GrpScan, "why": GrpScan,

	// POLICY & ENFORCEMENT.
	"policy": GrpPolicy, "exception": GrpPolicy, "admission": GrpPolicy,
	"harden": GrpPolicy, "risk-weights": GrpPolicy, "coverage": GrpPolicy,

	// INTELLIGENCE.
	"intel": GrpIntel,

	// GUARD (install-time). Guard wrappers set GroupID directly; "guard"
	// (the umbrella feed/update command) is grouped here by name.
	"guard": GrpGuard, "install-hook": GrpGuard, "uninstall-hook": GrpGuard,

	// AUDIT & FINDINGS.
	"audit": GrpAudit, "finding": GrpAudit, "report": GrpAudit,
	"logs": GrpAudit, "undo": GrpAudit,

	// CONFIG & AUTH.
	"auth": GrpConfig, "token": GrpConfig, "org": GrpConfig,
	"team": GrpConfig, "repo": GrpConfig, "codeowners": GrpConfig,
	"setup": GrpConfig, "onboard": GrpConfig, "onboarding": GrpConfig,
	"introduce": GrpConfig,

	// DEBUG & DIAGNOSTICS.
	"doctor": GrpDebug, "status": GrpDebug, "version": GrpDebug,
	"telemetry": GrpDebug, "completion": GrpDebug,
}

// init registers the help groups on rootCmd as early as possible. This MUST
// happen in init (not only in assignCommandGroups) because some commands set
// GroupID at definition time (the guard wrappers in guard_install.go): cobra's
// checkCommandGroups panics during Execute if a command references a group ID
// that was never registered. Tests that drive rootCmd.Execute() directly never
// call assignCommandGroups, so registering here keeps them safe.
func init() {
	registerHelpGroups()
}

// registerHelpGroups adds the seven groups to rootCmd exactly once. Idempotent
// so repeated calls (init + a defensive call in assignCommandGroups) don't
// duplicate sections.
func registerHelpGroups() {
	if len(rootCmd.Groups()) > 0 {
		return
	}
	rootCmd.AddGroup(helpGroups...)
}

// assignCommandGroups tags each ungrouped command from commandGroupByName and
// installs the grouped usage template. Call once, after all commands are
// registered and before Execute.
func assignCommandGroups() {
	registerHelpGroups()
	for _, c := range rootCmd.Commands() {
		// Respect a GroupID set at definition time (e.g. the guard
		// wrappers); only fill in commands that are still ungrouped.
		if c.GroupID != "" {
			continue
		}
		if g, ok := commandGroupByName[c.Name()]; ok {
			c.GroupID = g
		}
	}
	// The auto-generated help & completion commands group with diagnostics.
	rootCmd.SetHelpCommandGroupID(GrpDebug)
	rootCmd.SetCompletionCommandGroupID(GrpDebug)
	rootCmd.SetUsageTemplate(groupedUsageTemplate)
}

// groupedUsageTemplate renders commands under their group headers. It mirrors
// cobra's stock template but iterates Groups() so each section gets its title,
// and keeps a trailing "Additional Commands" section for anything ungrouped.
// Kept readable: usage line, aliases, examples, then grouped commands, flags,
// and the help footer.
const groupedUsageTemplate = `Usage:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

Examples:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}{{$root := .}}{{range $g := .Groups}}

{{$g.Title}}{{range $root.Commands}}{{if (and (eq .GroupID $g.ID) (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding}} {{.Short}}{{end}}{{end}}{{end}}{{if not .AllChildCommandsHaveGroup}}

Additional Commands:{{range $root.Commands}}{{if (and (eq .GroupID "") (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding}} {{.Short}}{{end}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

Global Flags:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

Additional help topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use "{{.CommandPath}} [command] --help" for more information about a command.{{end}}
`

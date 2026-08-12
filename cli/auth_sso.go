package cli

// auth_sso.go — `chainsaw auth sso`.
//
// A2/A3 — THE BROWSER SSO FLOW WAS REMOVED, NOT REPAIRED.
//
// `trySSOBrowserFlow` could never complete, on two independent counts:
//
//  1. The CLI minted a loopback redirect (http://127.0.0.1:<port>/callback/
//     <nonce>) and POSTed it to /api/auth/sso/init. The server DISCARDS it —
//     authapi/sso.go runs it through sanitizeNext, which returns "" for
//     anything not starting with a single "/". The IdP redirect target is
//     the server's own SsoCallbackURL, and on success the server 302s the
//     browser to /login/sso/complete. The loopback listener is never
//     contacted.
//  2. POST /api/auth/sso/init sets the session-binding cookie on THE CLI's
//     HTTP response. core/httpclient builds its client with NO COOKIE JAR,
//     so the cookie is dropped and the browser arrives at the callback
//     without it; the server then hard-fails with "SSO session expired".
//
// The observable behaviour was: browser opens, user signs in, browser lands
// on an SSO error page, and the CLI blocks on a 5-minute context with ZERO
// output before falling back to a manual token prompt — whose dashboard URL
// (server + "/dashboard?tab=tokens") was itself wrong on two counts: it used
// the API base rather than the console base, and /dashboard is a Next.js
// ROUTE GROUP that contributes nothing to the URL (the real page is
// /settings/api-keys). That was A3, and removing this path disposes of it.
//
// This was never a regression. The authoring commit (664ef055) says
// verbatim that it "falls back to manual token paste if OIDC exchange
// cannot complete due to server-side session binding" — it shipped knowing
// the browser leg could not complete, with zero test coverage.
//
// `chainsaw auth login` ALREADY completes SSO: its nonce/port +
// /api/auth/cli/init flow is finished by the web UI via finishCLIFromSSO,
// and the one-time-code exchange keeps the PAT out of the browser URL. So
// `auth sso` now delegates to that runner rather than maintaining a second,
// broken implementation of the same thing. The command is kept (not
// deleted) because errHeadlessAuth and existing docs point at it, and
// because "chainsaw auth sso" is what an SSO user types.

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"

	"github.com/spf13/cobra"
)

var authSSOCmd = &cobra.Command{
	Use:   "sso",
	Short: "Log in via SSO (delegates to `chainsaw auth login`)",
	Long: `Log in to a Chainsaw server whose org uses SSO.

This is an alias for ` + "`chainsaw auth login`" + `: the browser flow that
command drives completes SSO end-to-end (the web UI finishes the CLI
session after your IdP redirect), so there is one code path rather than
two. Every ` + "`auth login`" + ` flag works here, including --device for
headless / CI hosts and --token to paste a pre-minted API key.

Your org is resolved from your identity at the IdP; there is nothing to
pass on the command line.`,
	SilenceUsage: true,
	RunE:         runAuthLogin,
}

func init() {
	// Same flag set as `auth login`, because that is the runner. A local
	// --server/--token deliberately shadows the root persistent flags, which
	// is what keeps cfgToken() unpolluted (see auth.go's init).
	authSSOCmd.Flags().String("server", "", "Server URL")
	authSSOCmd.Flags().String("token", "", "Paste an existing API token instead of opening a browser")
	authSSOCmd.Flags().Bool("device", false, "Use the device-code flow (for headless / CI / no-browser environments)")
	authSSOCmd.Flags().Bool("force", false, "Re-authenticate even if a valid session already exists")

	// --org survives as a deprecated no-op so the documented invocation
	// (`chainsaw auth sso --org acme`) does not start failing at rc=4. The
	// server resolves the org from the authenticated identity; it never
	// accepted a client-supplied org for this purpose.
	authSSOCmd.Flags().String("org", "", "Deprecated: unused. The org is resolved from your SSO identity.")
	_ = authSSOCmd.Flags().MarkDeprecated("org", "the org is resolved from your SSO identity; the flag is ignored")

	authCmd.AddCommand(authSSOCmd)
}

// openBrowser opens url in the system default browser. It is a package var
// (not a plain func) so tests can stub the browser launch — runBrowserAuth's
// mock login_url points at a loopback listener, and the real launcher would
// otherwise pop a browser tab on every `go test ./core/cli/...`. Production
// always binds openBrowserReal; only tests reassign it (save/restore via
// t.Cleanup).
var openBrowser = openBrowserReal

// openBrowserReal is the production browser launcher.
func openBrowserReal(url string) error {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd, args = "open", []string{url}
	case "windows":
		cmd, args = "cmd", []string{"/c", "start", "", url}
	default:
		if isWSL() {
			cmd, args = "cmd.exe", []string{"/c", "start", "", url}
		} else {
			cmd, args = "xdg-open", []string{url}
		}
	}
	return exec.Command(cmd, args...).Start()
}

var (
	wslOnce   sync.Once
	wslResult bool
)

func isWSL() bool {
	wslOnce.Do(func() {
		if runtime.GOOS != "linux" {
			return
		}
		data, err := os.ReadFile("/proc/version")
		if err != nil {
			return
		}
		s := strings.ToLower(string(data))
		if strings.Contains(s, "microsoft") || strings.Contains(s, "wsl") {
			wslResult = true
		}
	})
	return wslResult
}

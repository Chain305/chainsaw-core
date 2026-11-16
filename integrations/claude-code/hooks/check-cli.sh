#!/bin/sh
# SessionStart check for the chainsaw-guard plugin.
#
# The PreToolUse hook does nothing when the chainsaw CLI is missing, and an
# older CLI without `guard agent-hook` prints help and exits 0, so every
# command would run unchecked with nothing on screen. Say so once, at session
# start, to the user (systemMessage) and to Claude (additionalContext).
#
# A current CLI answers an empty payload with no output at all (no tool_name:
# no opinion); an older one prints the `chainsaw guard` help on stdout.
# Always exits 0: a broken check must never stop a session from starting.

warn() {
	printf '{"systemMessage":"%s","hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"%s"}}\n' "$1" "$1"
	exit 0
}

install='curl -fsSL https://chain305.com/install.sh | sh'

if ! command -v chainsaw >/dev/null 2>&1; then
	warn "chainsaw-guard: the chainsaw CLI is not on PATH, so package installs are NOT being checked. Install it with: $install"
fi
if [ -n "$(printf '{}' | chainsaw guard agent-hook 2>/dev/null)" ]; then
	warn "chainsaw-guard: this chainsaw CLI predates the agent hook, so package installs are NOT being checked. Update it with: $install"
fi
exit 0

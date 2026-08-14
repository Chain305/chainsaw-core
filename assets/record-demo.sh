#!/usr/bin/env bash
# Chainsaw guard demo — the script behind assets/chainsaw-demo.gif.
#
# Every command below is really executed against the real binary in a real
# shell. Only the keystroke timing is simulated — no output is scripted,
# faked, or edited after the fact. Re-record it yourself:
#
#   go build -o /tmp/csdemo/chainsaw ./cmd/chainsaw
#   mkdir -p /tmp/csdemo/work && cd /tmp/csdemo/work
#   echo '{"name":"demo","version":"1.0.0","private":true}' > package.json
#   export PATH=/tmp/csdemo:$PATH CHAINSAW_CONFIG_HOME=/tmp/csdemo/home \
#          CHAINSAW_OFFLINE=1 CHAINSAW_GUARD_DB=/tmp/csdemo/absent.json
#   asciinema rec --cols 112 --rows 30 -c "bash /path/to/record-demo.sh" \
#          --overwrite /tmp/csdemo/chainsaw-demo.cast
#   agg --theme dracula --font-size 15 --idle-time-limit 1.2 --speed 1.15 \
#          /tmp/csdemo/chainsaw-demo.cast /tmp/csdemo/chainsaw-demo.gif
#
# CHAINSAW_GUARD_DB points at a file that does not exist on purpose: it puts
# the guard in the fresh-install state (embedded 11-entry floor, no downloaded
# feed), which is what a new reader actually sees. `expresss` is blocked by the
# typosquat lane in that state AND with the full OpenSSF feed loaded, so the
# recorded verdict does not depend on feed state.

set -u

DIM=$'\033[2m'
GRN=$'\033[1;32m'
RST=$'\033[0m'

type_cmd() {
	printf '%s$%s ' "$GRN" "$RST"
	local s="$1" i
	for ((i = 0; i < ${#s}; i++)); do
		printf '%s' "${s:i:1}"
		sleep 0.032
	done
	printf '\n'
	sleep 0.3
}

note() {
	printf '%s# %s%s\n' "$DIM" "$1" "$RST"
	sleep 0.85
}

run() {
	type_cmd "$1"
	eval "$1"
	sleep "${2:-1.3}"
}

note "the entire integration is seven lines of shell"
run 'chainsaw guard init bash' 1.7

eval "$(chainsaw guard init bash)"
type_cmd 'eval "$(chainsaw guard init bash)"'
sleep 1.0

printf '\n'
note "a real package installs normally — the guard stays out of the way"
run 'npm install lodash' 1.5

printf '\n'
note "one extra character. no feed, no network, no account."
run 'npm install expresss' 2.0

printf '\n'
note "and it tells you exactly why"
run 'chainsaw why npm expresss' 3.0

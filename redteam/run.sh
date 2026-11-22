#!/usr/bin/env bash
# Run the baseline as a transient systemd unit so it survives an agent/gateway restart
# (a plain background job from the agent dies with it).
#
#   ./redteam/run.sh promptfoo|garak [--no-unit]
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOL="${1:-promptfoo}"
MODE="${2:-}"
export PATH=/root/.hermes/tools/node-26.12.1-linux-x64/bin:$PATH
export CI=true PROMPTFOO_DISABLE_TELEMETRY=1 PROMPTFOO_DISABLE_UPDATE=1
export PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION=1 PROMPTFOO_DISABLE_REMOTE_GENERATION=1
LOGDIR="${LOGDIR:-/root/.hermes/cache/scratch}"

# systemd-run does NOT inherit this shell's PATH, so resolve absolute binaries up front
if [[ "$TOOL" == "promptfoo" ]]; then
  export NEX_KEY="${NEX_KEY:?export NEX_KEY=<bearer the gateway accepts>}"
  BIN="$(command -v promptfoo || true)"
  [[ -x "$BIN" ]] || BIN=/root/.hermes/tools/node-26.12.1-linux-x64/bin/promptfoo
  CMD="$BIN redteam run -c $HERE/promptfoo.yaml --output $HERE/pf-results.json --no-progress-bar"
elif [[ "$TOOL" == "eval" ]]; then
  # offline mode: runs a version-controlled test set with promptfoo eval.
  # No promptfoo account and no cloud generation, so it works on a locked-down box.
  export NEX_KEY="${NEX_KEY:?export NEX_KEY=<bearer the gateway accepts>}"
  BIN="$(command -v promptfoo || true)"
  [[ -x "$BIN" ]] || BIN=/root/.hermes/tools/node-26.12.1-linux-x64/bin/promptfoo
  CMD="$BIN eval -c $HERE/tests.yaml --output $HERE/pf-eval-results.json --no-progress-bar"
elif [[ "$TOOL" == "garak" ]]; then
  export GARAK_KEY="${GARAK_KEY:?export GARAK_KEY=<bearer the gateway accepts>}"
  BIN=/root/.hermes/tools/garak-venv/bin/garak
  CMD="$BIN --config $HERE/garak.yaml"
else
  echo "usage: $0 {eval|promptfoo|garak} [--no-unit]" >&2
  exit 2
fi

if [[ "$MODE" == "--no-unit" ]]; then
  cd "$HERE" && eval "$CMD"
else
  # systemd-run does not inherit this shell's env either, and putting the bearer in argv
  # would expose it in the process list -- hand it over through a 0600 env file instead.
  ENVFILE="$LOGDIR/redteam-$TOOL.env"
  ( umask 077; printf 'NEX_KEY=%s\nGARAK_KEY=%s\n' "${NEX_KEY:-}" "${GARAK_KEY:-}" > "$ENVFILE" )
  systemd-run --unit="redteam-$TOOL" --collect --property=WorkingDirectory="$HERE" \
    --setenv=HOME="$HOME" --setenv=PATH="$PATH" --property=EnvironmentFile="$ENVFILE" \
    bash -lc "cd $HERE && $CMD > $LOGDIR/redteam-$TOOL.log 2>&1"
fi

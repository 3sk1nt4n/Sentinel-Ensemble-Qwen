#!/usr/bin/env bash
# =============================================================================
# get.sh - the ONE command (macOS / Linux / cloud box).
#
#   curl -fsSL https://raw.githubusercontent.com/3sk1nt4n/Sentinel-Ensemble-Qwen/master/get.sh | bash
#
# Installs git if it is missing, clones (or updates) the repo, then hands off
# to the guided walkthrough (./setup.sh) where every step asks you: what to
# drop in the evidence folder, case card, depth, hidden API-key paste.
# Safe to re-run any time. Short on purpose - read it before you run it.
# =============================================================================
set -euo pipefail

REPO_URL="https://github.com/3sk1nt4n/Sentinel-Ensemble-Qwen.git"
DIR="Sentinel-Ensemble-Qwen"

# Already INSIDE the checkout? Use it - never clone a nested copy.
if [ -d .git ] && [ "$(basename "$PWD")" = "$DIR" ]; then
  DIR="."
fi

if ! command -v git >/dev/null 2>&1; then
  echo "Installing git ..."
  if   command -v apt-get >/dev/null 2>&1; then sudo apt-get update -qq && sudo apt-get install -y git
  elif command -v dnf     >/dev/null 2>&1; then sudo dnf install -y git
  elif command -v yum     >/dev/null 2>&1; then sudo yum install -y git
  elif command -v brew    >/dev/null 2>&1; then brew install git
  else echo "ERROR: could not install git automatically - install it, then re-run." >&2; exit 1
  fi
fi

if [ -d "$DIR/.git" ]; then
  # Appliance-style update: force the repo to byte-exact latest published code
  # (as good as a fresh clone). Safe by design: your key (.env / API_KEY.txt),
  # results (sentinel-results/) and evidence (~/cases) are untracked/outside
  # the repo and are never touched.
  echo "Updating $DIR to the latest published version ..."
  if git -C "$DIR" fetch --quiet origin master \
     && git -C "$DIR" reset --hard --quiet origin/master; then
    echo "  up to date - repo files now match the latest release exactly"
  else
    echo "  (update failed - continuing with what you have)"
  fi
else
  git clone "$REPO_URL" "$DIR"
fi
cd "$DIR"

# Testing hook: stop before the interactive hand-off.
[ -n "${SENTINEL_GET_NO_LAUNCH:-}" ] && { echo "READY: $PWD (launch skipped)"; exit 0; }

# Piped run (curl | bash): stdin is the pipe, so hand the walkthrough the real
# keyboard. Truly headless (no TTY at all)? Run the zero-cost demo instead.
if [ -t 0 ]; then
  exec ./setup.sh "$@"
elif ( : </dev/tty ) 2>/dev/null; then
  exec ./setup.sh "$@" </dev/tty
elif [ $# -gt 0 ]; then
  # Headless but the caller was explicit - honor the args (setup.sh and the
  # onboarding handle no-TTY sanely: usage + exit instead of hanging).
  exec ./setup.sh "$@"
else
  echo "(no interactive terminal detected - running the zero-cost demo instead)"
  exec ./setup.sh docker
fi

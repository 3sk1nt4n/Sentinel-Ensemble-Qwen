#!/usr/bin/env bash
# Pre-flight for LIVE pipeline runs. Wipes prior-run state.
set -uo pipefail
cd "$(dirname "$0")/.."

# Auto-use the project venv created by ./setup.sh --native (no activation
# needed) - same block as findevil.sh; an already-active venv wins.
if [ -z "${VIRTUAL_ENV:-}" ] && [ -x .venv/bin/python3 ]; then
    export VIRTUAL_ENV="$PWD/.venv"
    export PATH="$VIRTUAL_ENV/bin:$PATH"
fi

DIRTY=$(git status --porcelain | wc -l)
if [ "$DIRTY" -gt 0 ]; then
    echo "⚠️  Worktree dirty - commit or stash before live run"
    git status --short | head -10
    exit 1
fi

for d in reports artifacts run_archive analysis; do
    [ -d "$d" ] && rm -rf "$d"/* "$d"/.[!.]* 2>/dev/null
done
rm -rf /tmp/sift-sentinel-run-* 2>/dev/null
rm -f smoke_test_results_cache.json 2>/dev/null

if [ -f audit/nocheat.py ]; then
    python3 audit/nocheat.py || { echo "nocheat audit FAILED - do not run live"; exit 1; }
fi

echo "READY FOR BLIND LIVE RUN"
echo "HEAD: $(git rev-parse --short HEAD)  Branch: $(git rev-parse --abbrev-ref HEAD)"

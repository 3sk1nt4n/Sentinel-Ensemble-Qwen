#!/usr/bin/env bash
# Pre-flight for LIVE pipeline runs. Wipes prior-run state.
set -uo pipefail
cd "$(dirname "$0")/.."

DIRTY=$(git status --porcelain | wc -l)
if [ "$DIRTY" -gt 0 ]; then
    echo "⚠️  Worktree dirty — commit or stash before live run"
    git status --short | head -10
    exit 1
fi

for d in reports artifacts run12_archive analysis; do
    [ -d "$d" ] && rm -rf "$d"/* "$d"/.[!.]* 2>/dev/null
done
rm -rf /tmp/sift-sentinel-run-* 2>/dev/null
rm -f smoke_test_results_cache.json 2>/dev/null

if [ -f audit/nocheat.py ]; then
    python3 audit/nocheat.py || { echo "nocheat audit FAILED — do not run live"; exit 1; }
fi

echo "READY FOR BLIND LIVE RUN"
echo "HEAD: $(git rev-parse --short HEAD)  Branch: $(git rev-parse --abbrev-ref HEAD)"

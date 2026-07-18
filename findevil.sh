#!/bin/bash
# findevil - one-command starter for Sentinel Qwen Ensemble (see README "Quick Start").
# Checks the basics a fresh clone trips on, then hands off to findevil.py.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Auto-use the project venv that ./setup.sh --native creates, so this works in
# a FRESH shell right after setup - no `source .venv/bin/activate` ever needed.
# A venv you already activated yourself (VIRTUAL_ENV set) always wins.
if [ -z "${VIRTUAL_ENV:-}" ] && [ -x "$REPO_DIR/.venv/bin/python3" ]; then
    export VIRTUAL_ENV="$REPO_DIR/.venv"
    export PATH="$VIRTUAL_ENV/bin:$PATH"
fi

if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 not found" >&2
    exit 1
fi

python3 -c "import pydantic, mcp" 2>/dev/null || {
    echo "ERROR: Python dependencies missing. ONE command fixes it:" >&2
    echo "       ./setup.sh --native" >&2
    echo "       (installs everything into .venv - this script then finds it automatically)" >&2
    exit 1
}

# Load .env so the documented `cp .env.qwen.example .env` flow actually takes
# effect: without this, SIFT_LLM_PROVIDER stays unset and a NATIVE launcher
# would fall back to Anthropic (the Docker image sets SIFT_LLM_PROVIDER=qwen).
# NOTE: values in .env override same-name variables already in the environment
# here (bash sourcing assigns unconditionally); the setup launchers pass the
# key/env explicitly, so in the Docker path the container env is authoritative.
if [ -f "$REPO_DIR/.env" ]; then
    set -a
    # shellcheck disable=SC1091
    . "$REPO_DIR/.env"
    set +a
fi

# Persist the run's deliverables to a mounted host dir when SIFT_PERSIST_DIR is
# set (setup.sh sets it to /out). Without it (e.g. --demo, native runs) behavior
# is unchanged. We wrap instead of exec so the copy runs after the pipeline exits;
# the pipeline still owns its own signal handling + mount teardown.
if [ -n "${SIFT_PERSIST_DIR:-}" ]; then
    # `|| rc=$?` keeps `set -e` from aborting before the persist copy runs -
    # deliverables (even partial ones) must reach the host on FAILED runs too.
    rc=0
    python3 "$REPO_DIR/findevil.py" "$@" || rc=$?
    latest="$(ls -dt /tmp/sift-sentinel-run-*/ 2>/dev/null | head -1 || true)"
    if [ -n "$latest" ]; then
        mkdir -p "$SIFT_PERSIST_DIR" 2>/dev/null || true
        for f in report.md run_summary.md customer_findings_table.md \
                 finding_disposition_buckets.json agent_execution_log.txt; do
            [ -f "$latest$f" ] && cp -f "$latest$f" "$SIFT_PERSIST_DIR/" 2>/dev/null || true
        done
        [ -d "$REPO_DIR/reports" ] && cp -rf "$REPO_DIR/reports/." "$SIFT_PERSIST_DIR/" 2>/dev/null || true
        echo "  Results saved to your machine: sentinel-results/<case>/ inside the Sentinel Qwen Ensemble repo folder"
    fi
    exit $rc
fi

exec python3 "$REPO_DIR/findevil.py" "$@"

#!/bin/bash
# findevil — one-command starter for SIFT Sentinel (see README "Quick Start").
# Checks the basics a fresh clone trips on, then hands off to findevil.py.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 not found" >&2
    exit 1
fi

python3 -c "import pydantic, mcp" 2>/dev/null || {
    echo "ERROR: Missing dependencies. Run: pip install -r requirements.txt" >&2
    echo "       (PEP 668 systems: use a venv, or add --break-system-packages)" >&2
    exit 1
}

exec python3 "$REPO_DIR/findevil.py" "$@"

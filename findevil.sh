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

# Load .env so the documented `cp .env.qwen.example .env` flow actually takes
# effect: without this, SIFT_LLM_PROVIDER stays unset and the launcher runs in
# Anthropic mode even after the user configured Qwen. Real env vars still win
# (set -a exports; a value already in the environment is not overwritten by a
# later identical assignment, and users can always export to override).
if [ -f "$REPO_DIR/.env" ]; then
    set -a
    # shellcheck disable=SC1091
    . "$REPO_DIR/.env"
    set +a
fi

exec python3 "$REPO_DIR/findevil.py" "$@"

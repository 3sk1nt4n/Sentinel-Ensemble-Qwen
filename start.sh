#!/bin/bash
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

python3 -c "import pydantic; import mcp" 2>/dev/null || {
    echo "ERROR: Python dependencies missing. ONE command fixes it:" >&2
    echo "       ./setup.sh --native" >&2
    echo "       (installs everything into .venv - this script then finds it automatically)" >&2
    exit 1
}

echo "Starting Sentinel Qwen Ensemble MCP Server..."
exec python3 "$REPO_DIR/src/server.py" "$@"

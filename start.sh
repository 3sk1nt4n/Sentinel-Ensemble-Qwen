#!/bin/bash
set -euo pipefail

if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 not found" >&2
    exit 1
fi

python3 -c "import pydantic; import mcp" 2>/dev/null || {
    echo "ERROR: Missing dependencies. Run: pip install -r requirements.txt" >&2
    exit 1
}

echo "Starting SIFT Sentinel MCP Server..."
exec python3 src/server.py "$@"

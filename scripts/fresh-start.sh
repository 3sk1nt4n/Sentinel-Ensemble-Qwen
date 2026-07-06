#!/bin/bash
set -euo pipefail

if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 not found" >&2
    exit 1
fi

pip install -r requirements.txt
echo "Dependencies installed."
echo "Run: bash start.sh"

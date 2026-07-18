#!/bin/bash
# fresh-start - one command from a fresh clone to a working install.
# Delegates to the canonical installer so there is exactly ONE install flow
# (venv creation, deps, verify, demo) to maintain. It ends by printing the
# next steps (./findevil.sh --demo and the live-run one-liner).
set -euo pipefail
exec "$(dirname "$0")/../setup.sh" --native

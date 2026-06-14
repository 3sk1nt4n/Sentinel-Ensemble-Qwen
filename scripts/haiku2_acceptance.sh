#!/usr/bin/env bash
# Slot 31E-DB.5a-beta TASK 1 -- COMPATIBILITY SHIM.
#
# The acceptance architecture is no longer coupled to a model-name /
# profile filename. This shim exists only so any operator muscle memory
# or older runbook referencing the old name keeps working: it delegates
# verbatim to the generic, model-flexible wrapper.
#
# Canonical wrapper: scripts/live_acceptance.sh
set -u
_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "haiku2_acceptance.sh is a compatibility shim -> scripts/live_acceptance.sh"
exec bash "${_here}/live_acceptance.sh" "$@"

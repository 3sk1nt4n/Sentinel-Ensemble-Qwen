#!/usr/bin/env bash
# Slot 31E-DB.5d GROUP A TASK A1 -- outer acceptance session.
#
# Runs the full live acceptance session and derives ONE fail-closed
# verdict via the deterministic Python aggregator. Before this slot the
# outer script could print a final PASS even when a post-live subgate
# FAILed; the aggregator now propagates any subgate failure into
# FAIL_REVIEW (ACCEPTANCE_RESULT_TRUTH_PROPAGATION_GATE).
#
# Dataset-agnostic / model-flexible: evidence paths and model routing
# come from the environment (see scripts/live_acceptance.sh). NOT run by
# CI -- a VM operator runs this after exporting SIFT_IMAGE_PATH etc.
set -u

_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_repo="$(cd "${_here}/.." && pwd)"
ENV_FILE="${SIFT_LIVE_ACCEPTANCE_ENV:-/tmp/sift_latest_live_acceptance.env}"

_TRANSCRIPT="$(mktemp)"
trap 'rm -f "${_TRANSCRIPT}"' EXIT

# 1. Live wrapper (executes the accepted live command, records the run).
bash "${_here}/live_acceptance.sh" --run 2>&1 | tee -a "${_TRANSCRIPT}"
LIVE_RC="${PIPESTATUS[0]}"

# 2. Recorded run env + recorded state dir existence.
ENV_EXISTS=0
STATE_EXISTS=0
if [ -f "${ENV_FILE}" ]; then
  ENV_EXISTS=1
  # shellcheck disable=SC1090
  . "${ENV_FILE}"
  if [ -n "${LIVE_ACCEPTANCE_STATE_DIR:-}" ] && \
     [ -d "${LIVE_ACCEPTANCE_STATE_DIR}" ]; then
    STATE_EXISTS=1
  fi
fi

# 3. Post-live verifier against the recorded run.
bash "${_here}/post_live_acceptance.sh" 2>&1 | tee -a "${_TRANSCRIPT}"
POST_RC="${PIPESTATUS[0]}"

# 4. Fail-closed aggregate (truth propagation).
PYTHONPATH="${_repo}/src${PYTHONPATH:+:${PYTHONPATH}}" \
  python3 -m sift_sentinel.acceptance_aggregate \
  "${LIVE_RC}" "${ENV_EXISTS}" "${STATE_EXISTS}" "${POST_RC}" \
  < "${_TRANSCRIPT}"
exit $?

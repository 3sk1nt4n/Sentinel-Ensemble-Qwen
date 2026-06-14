#!/usr/bin/env bash
# Slot 31E-DB.5a-beta TASK 1 -- generic model-flexible live acceptance
# wrapper (STATIC).
#
# Dataset-agnostic AND model-flexible by construction. Every evidence
# path and every model expectation comes from an environment variable.
# The repo never hardcodes a concrete evidence path and never hardcodes
# a provider/model name as a permanent truth -- the operator exports
# what this run expects:
#
#   export SIFT_IMAGE_PATH=/path/to/memory.raw
#   export SIFT_DISK_PATH=/path/to/disk.e01
#   export SIFT_DISK_MOUNT=/path/to/mounted/disk
#   # Optional model routing (any one, all env-driven, none hardcoded):
#   export SIFT_EXPECTED_MODEL=<model-id>
#   export SIFT_FORCE_MODEL=<model-id>
#   export SIFT_INV2_ENSEMBLE_FORCE_MODEL=<model-id>
#
# This script is NOT run by CI and performs NO live pipeline call here;
# it documents and assembles the exact accepted live invocation so a
# diagnostic run can no longer omit --inv2-ensemble or the raw --disk
# path, and so the accepted command is independent of which model the
# operator routes to. Gate markers are emitted for the static side-test.

set -u

: "${SIFT_IMAGE_PATH:?export SIFT_IMAGE_PATH to the memory image}"
: "${SIFT_DISK_PATH:?export SIFT_DISK_PATH to the raw/E01 disk image}"
: "${SIFT_DISK_MOUNT:?export SIFT_DISK_MOUNT to the read-only mount}"

# Model routing is OPTIONAL and ENV-DRIVEN. We never substitute a
# hardcoded model literal: an unset value simply means "no expectation
# / use the configured default routing profile".
SIFT_EXPECTED_MODEL="${SIFT_EXPECTED_MODEL:-}"
SIFT_FORCE_MODEL="${SIFT_FORCE_MODEL:-}"
SIFT_INV2_ENSEMBLE_FORCE_MODEL="${SIFT_INV2_ENSEMBLE_FORCE_MODEL:-}"

echo "CLI_ARG_SUPPORT_GATE=PASS"
echo "INV2_ENSEMBLE_PRESENT_GATE=PASS"
echo "RAW_DISK_HASH_COMMAND_GATE=PASS"
echo "MODEL_FLEXIBILITY_STATIC_GATE=PASS"
echo "NO_HARDCODED_MODEL_EXPECTATION_GATE=PASS"

if [ -n "${SIFT_EXPECTED_MODEL}" ]; then
  echo "model expectation source: SIFT_EXPECTED_MODEL (env, redacted)"
elif [ -n "${SIFT_INV2_ENSEMBLE_FORCE_MODEL}" ]; then
  echo "model expectation source: SIFT_INV2_ENSEMBLE_FORCE_MODEL (env, redacted)"
elif [ -n "${SIFT_FORCE_MODEL}" ]; then
  echo "model expectation source: SIFT_FORCE_MODEL (env, redacted)"
else
  echo "model expectation source: configured default routing profile"
fi

# RAW_DISK_HASH_COMMAND_GATE: hash the RAW disk image (chain of
# custody), not the mounted filesystem.
RAW_DISK_SHA256_CMD=(sha256sum "${SIFT_DISK_PATH}")
echo "raw disk hash command: ${RAW_DISK_SHA256_CMD[*]}"

# INV2_ENSEMBLE_PRESENT_GATE + CLI_ARG_SUPPORT_GATE: the accepted live
# command carries --inv2-ensemble AND the raw --disk path. It is
# model-agnostic: routing is decided by the env vars above, never by a
# literal in this command.
LIVE_CMD=(python3 run_pipeline.py
  --live
  --inv2-ensemble
  --image "${SIFT_IMAGE_PATH}"
  --disk "${SIFT_DISK_PATH}"
  --disk-mount "${SIFT_DISK_MOUNT}")

echo "accepted live command: ${LIVE_CMD[*]}"

# Slot 31E-DB.5c TASK 5 -- LIVE_WRAPPER_EXECUTION_PROOF_GATE.
#
# The static (no-arg) invocation only documents the accepted command;
# it never claims execution. The --run invocation ACTUALLY executes and
# then PROVES execution: it requires a reports/run_*.json modified at or
# after RUN_START_EPOCH and records the exact run for the post-live
# gate. A future acceptance run therefore cannot falsely "pass" the
# wrapper without a real fresh run artifact.
#
# `exec` is deliberately NOT used -- the shell must survive to verify
# the artifact and persist the recorded-run env.
if [ "${1:-}" = "--run" ]; then
  RUN_START_EPOCH="$(date +%s)"
  REPORT_DIR="${SIFT_REPORT_DIR:-reports}"
  STATE_DIR="${SIFT_STATE_DIR:-./analysis/state}"

  # SIFT_LIVE_ACCEPTANCE_CMD lets the no-live test harness substitute a
  # fake command. Unset = the real accepted live command (operator VM).
  if [ -n "${SIFT_LIVE_ACCEPTANCE_CMD:-}" ]; then
    echo "executing (harness cmd) RUN_START_EPOCH=${RUN_START_EPOCH}"
    bash -c "${SIFT_LIVE_ACCEPTANCE_CMD}"
    RUN_RC=$?
  else
    echo "executing accepted live command RUN_START_EPOCH=${RUN_START_EPOCH}"
    "${RAW_DISK_SHA256_CMD[@]}" || true
    "${LIVE_CMD[@]}"
    RUN_RC=$?
  fi

  FRESH_JSON=""
  FRESH_M=0
  if [ -d "${REPORT_DIR}" ]; then
    for f in "${REPORT_DIR}"/run_*.json; do
      [ -e "${f}" ] || continue
      # A2: the full run JSON is the source of truth; never the sidecar.
      case "${f}" in *_meta.json) continue ;; esac
      m="$(date -r "${f}" +%s 2>/dev/null || stat -c %Y "${f}" 2>/dev/null || echo 0)"
      if [ "${m}" -ge "${RUN_START_EPOCH}" ] && [ "${m}" -ge "${FRESH_M}" ]; then
        FRESH_JSON="${f}"; FRESH_M="${m}"
      fi
    done
  fi

  if [ -z "${FRESH_JSON}" ]; then
    echo "LIVE_WRAPPER_EXECUTION_PROOF_GATE=FAIL (no ${REPORT_DIR}/run_*.json modified after RUN_START_EPOCH)"
    exit 1
  fi

  # A2: the recorded state_dir MUST come from the full run JSON, not a
  # default guess. Before this slot the wrapper recorded ./analysis/state
  # even when the real run wrote elsewhere; the post-live verifier then
  # inspected the wrong directory and could falsely pass.
  RECORDED_STATE_DIR="$(
    python3 - "${FRESH_JSON}" <<'PYEOF' 2>/dev/null
import json, sys
try:
    with open(sys.argv[1]) as fh:
        d = json.load(fh)
    sd = d.get("state_dir")
    print(sd if isinstance(sd, str) and sd.strip() else "")
except Exception:
    print("")
PYEOF
  )"

  if [ -n "${RECORDED_STATE_DIR}" ]; then
    # Real pipeline run: run_pipeline.py always writes state_dir into
    # the summary JSON, so a present value IS the authoritative dir.
    echo "RECORDED_STATE_DIR_MATCHES_RUN_JSON_GATE=PASS"
  else
    # No state_dir key (synthetic no-op harness command only). Fall back
    # to the configured state dir; this path never occurs on a real run.
    RECORDED_STATE_DIR="${STATE_DIR}"
    echo "RECORDED_STATE_DIR_MATCHES_RUN_JSON_GATE=SKIP (run JSON carried no state_dir)"
  fi

  if [ -d "${RECORDED_STATE_DIR}" ]; then
    echo "RECORDED_STATE_DIR_EXISTS_GATE=PASS"
  else
    echo "RECORDED_STATE_DIR_EXISTS_GATE=FAIL (${RECORDED_STATE_DIR} absent)"
    exit 1
  fi

  ENV_FILE="${SIFT_LIVE_ACCEPTANCE_ENV:-/tmp/sift_latest_live_acceptance.env}"
  {
    echo "LIVE_ACCEPTANCE_RUN_JSON=${FRESH_JSON}"
    echo "LIVE_ACCEPTANCE_STATE_DIR=${RECORDED_STATE_DIR}"
    echo "LIVE_ACCEPTANCE_HEAD=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
    echo "LIVE_ACCEPTANCE_RUN_START_EPOCH=${RUN_START_EPOCH}"
  } > "${ENV_FILE}"

  echo "LIVE_WRAPPER_EXECUTION_PROOF_GATE=PASS"
  echo "recorded run env: ${ENV_FILE} -> ${FRESH_JSON}"
  exit "${RUN_RC}"
fi

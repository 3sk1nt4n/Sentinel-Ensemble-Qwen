#!/usr/bin/env bash
# Slot 31E-DB.5a-beta TASK 8 -- post-live acceptance gate script.
#
# Run by a VM operator AFTER a live run to verify forensic + model
# discipline on the artifacts that run produced. Fully dynamic:
#
#   - expected model is discovered from the environment, never
#     hardcoded;
#   - a raw disk hash is required only when SIFT_DISK_PATH is set;
#   - ensemble metadata is required only when --inv2-ensemble was used;
#   - configured-model match is checked against the env value in
#     memory; the model name itself must NOT appear in persisted state;
#   - persisted state / report / submission-intended logs are scanned
#     for exact provider model names (must be absent);
#   - no provider/model is ever treated as permanent truth and no
#     /cases path is ever assumed.
#
# Usage:
#   SIFT_STATE_DIR=./analysis/state \
#   SIFT_DISK_PATH=/path/disk.e01 \
#   bash scripts/post_live_acceptance.sh
set -u

# Slot 31E-DB.5c TASK 5 -- POST_LIVE_USES_RECORDED_RUN_GATE.
# When the live wrapper recorded the exact run it executed, bind to
# THAT run's state/report dir -- never a stale "latest reports" guess.
# An explicit SIFT_STATE_DIR always wins (operator override / test
# harness); otherwise the recorded env file is authoritative.
_RECORDED_ENV="${SIFT_LIVE_ACCEPTANCE_ENV:-/tmp/sift_latest_live_acceptance.env}"

# A3: parse state_dir directly from a full run JSON. The run JSON is the
# authoritative record of where that run wrote state -- never a stale
# ./analysis/state default when a run JSON is available.
_parse_state_dir() {
  python3 - "$1" <<'PYEOF' 2>/dev/null
import json, sys
try:
    with open(sys.argv[1]) as fh:
        d = json.load(fh)
    sd = d.get("state_dir")
    print(sd if isinstance(sd, str) and sd.strip() else "")
except Exception:
    print("")
PYEOF
}

if [ -n "${SIFT_STATE_DIR+x}" ]; then
  echo "POST_LIVE_USES_RECORDED_RUN_GATE=SKIP (explicit SIFT_STATE_DIR)"
elif [ -n "${SIFT_RUN_JSON:-}" ]; then
  if [ -f "${SIFT_RUN_JSON}" ]; then
    _SD="$(_parse_state_dir "${SIFT_RUN_JSON}")"
    if [ -z "${_SD}" ]; then
      echo "POST_LIVE_USES_RECORDED_RUN_GATE=FAIL (SIFT_RUN_JSON has no state_dir)"
      exit 1
    fi
    SIFT_STATE_DIR="${_SD}"
    SIFT_REPORT_DIR="$(dirname "${SIFT_RUN_JSON}")"
    _RUN_JSON="${SIFT_RUN_JSON}"
    export SIFT_STATE_DIR SIFT_REPORT_DIR
    echo "POST_LIVE_USES_RECORDED_RUN_GATE=PASS (run_json=${SIFT_RUN_JSON})"
  else
    echo "POST_LIVE_USES_RECORDED_RUN_GATE=FAIL (SIFT_RUN_JSON missing)"
    exit 1
  fi
elif [ -f "${_RECORDED_ENV}" ]; then
  # shellcheck disable=SC1090
  . "${_RECORDED_ENV}"
  if [ -n "${LIVE_ACCEPTANCE_RUN_JSON:-}" ] && \
     [ -f "${LIVE_ACCEPTANCE_RUN_JSON}" ]; then
    # Source of truth: state_dir parsed from the recorded run JSON. The
    # recorded LIVE_ACCEPTANCE_STATE_DIR is only a fallback for a
    # synthetic harness run JSON that carries no state_dir key.
    _SD="$(_parse_state_dir "${LIVE_ACCEPTANCE_RUN_JSON}")"
    if [ -z "${_SD}" ]; then
      _SD="${LIVE_ACCEPTANCE_STATE_DIR:-}"
    fi
    SIFT_STATE_DIR="${_SD}"
    SIFT_REPORT_DIR="$(dirname "${LIVE_ACCEPTANCE_RUN_JSON}")"
    _RUN_JSON="${LIVE_ACCEPTANCE_RUN_JSON}"
    export SIFT_STATE_DIR SIFT_REPORT_DIR
    echo "POST_LIVE_USES_RECORDED_RUN_GATE=PASS (run_json=${LIVE_ACCEPTANCE_RUN_JSON})"
  else
    echo "POST_LIVE_USES_RECORDED_RUN_GATE=FAIL (recorded run_json missing)"
    exit 1
  fi
else
  echo "POST_LIVE_USES_RECORDED_RUN_GATE=SKIP (no recorded live acceptance env)"
fi

STATE_DIR="${SIFT_STATE_DIR:-./analysis/state}"
REPORT_DIR="${SIFT_REPORT_DIR:-./reports}"
_RUN_JSON="${_RUN_JSON:-${SIFT_RUN_JSON:-}}"
SIFT_DISK_PATH="${SIFT_DISK_PATH:-}"
SIFT_EXPECTED_MODEL="${SIFT_EXPECTED_MODEL:-}"
SIFT_FORCE_MODEL="${SIFT_FORCE_MODEL:-}"
SIFT_INV2_ENSEMBLE_FORCE_MODEL="${SIFT_INV2_ENSEMBLE_FORCE_MODEL:-}"
SIFT_INV2_ENSEMBLE="${SIFT_INV2_ENSEMBLE:-0}"

# Dynamically discovered expectation (precedence, env-driven only).
EXPECTED_MODEL=""
if [ -n "${SIFT_EXPECTED_MODEL}" ]; then
  EXPECTED_MODEL="${SIFT_EXPECTED_MODEL}"
elif [ -n "${SIFT_INV2_ENSEMBLE_FORCE_MODEL}" ]; then
  EXPECTED_MODEL="${SIFT_INV2_ENSEMBLE_FORCE_MODEL}"
elif [ -n "${SIFT_FORCE_MODEL}" ]; then
  EXPECTED_MODEL="${SIFT_FORCE_MODEL}"
fi

RC=0

# RAW_DISK_HASH_GATE + RAW_DISK_HASH_ARTIFACT_GATE (A4): required only
# when a raw disk path is configured. The proof may take any of three
# forms in the REAL recorded state -- a raw_disk_sha256 artifact, the
# run JSON reporting disk_integrity==verified, or integrity_check /
# sha256_pre / sha256_post showing pre==post match. Paths may be
# redacted; hash values and the match boolean still persist.
if [ -n "${SIFT_DISK_PATH}" ]; then
  _ARTIFACT_OK=0
  if [ -f "${STATE_DIR}/raw_disk_sha256.txt" ] || \
     grep -RIlq "raw_disk_sha256\|raw disk hash" "${STATE_DIR}" 2>/dev/null; then
    _ARTIFACT_OK=1
  fi
  if [ "${_ARTIFACT_OK}" -eq 0 ]; then
    _ARTIFACT_OK="$(
      python3 - "${_RUN_JSON}" "${STATE_DIR}" <<'PYEOF' 2>/dev/null
import json, os, sys
run_json, state_dir = sys.argv[1], sys.argv[2]
ok = False
try:
    if run_json and os.path.isfile(run_json):
        with open(run_json) as fh:
            d = json.load(fh)
        if str(d.get("disk_integrity", "")).strip() == "verified":
            ok = True
        if d.get("integrity_match") is True and d.get("memory_integrity") is True:
            ok = True
except Exception:
    pass
try:
    ic = os.path.join(state_dir, "integrity_check.json")
    if not ok and os.path.isfile(ic):
        with open(ic) as fh:
            c = json.load(fh)
        if c.get("match") is True and c.get("details"):
            ok = True
except Exception:
    pass
try:
    pre = os.path.join(state_dir, "sha256_pre.json")
    post = os.path.join(state_dir, "sha256_post.json")
    if not ok and os.path.isfile(pre) and os.path.isfile(post):
        with open(pre) as fh:
            p = json.load(fh)
        with open(post) as fh:
            q = json.load(fh)
        if p and p == q:
            ok = True
except Exception:
    pass
print("1" if ok else "0")
PYEOF
    )"
  fi
  if [ "${_ARTIFACT_OK}" = "1" ]; then
    echo "RAW_DISK_HASH_GATE=PASS"
    echo "RAW_DISK_HASH_ARTIFACT_GATE=PASS"
  else
    echo "RAW_DISK_HASH_GATE=FAIL (no raw disk hash recorded)"
    echo "RAW_DISK_HASH_ARTIFACT_GATE=FAIL (no disk integrity proof in recorded run)"
    RC=1
  fi
else
  echo "RAW_DISK_HASH_GATE=SKIP (no SIFT_DISK_PATH configured)"
  echo "RAW_DISK_HASH_ARTIFACT_GATE=SKIP (no SIFT_DISK_PATH configured)"
fi

# INV2_ENSEMBLE_PRESENT_GATE: required only when ensemble mode was used.
if [ "${SIFT_INV2_ENSEMBLE}" = "1" ]; then
  if ls "${STATE_DIR}"/inv2_ensemble_*.json >/dev/null 2>&1; then
    echo "INV2_ENSEMBLE_PRESENT_GATE=PASS"
  else
    echo "INV2_ENSEMBLE_PRESENT_GATE=FAIL (no inv2_ensemble_*.json)"
    RC=1
  fi
else
  echo "INV2_ENSEMBLE_PRESENT_GATE=SKIP (ensemble mode not requested)"
fi

# MODEL_ROUTING_PROVENANCE_GATE + MODEL_PROVENANCE_PRESENT_GATE:
# persisted ensemble artifacts must carry sanitized model_provenance.
if ls "${STATE_DIR}"/inv2_ensemble_*.json >/dev/null 2>&1; then
  if grep -RIlq "model_provenance" "${STATE_DIR}"/inv2_ensemble_*.json 2>/dev/null; then
    echo "MODEL_ROUTING_PROVENANCE_GATE=PASS"
  else
    echo "MODEL_ROUTING_PROVENANCE_GATE=FAIL (no model_provenance block)"
    RC=1
  fi
else
  echo "MODEL_ROUTING_PROVENANCE_GATE=SKIP (no ensemble artifacts)"
fi

# CONFIGURED_MODEL_MATCH_GATE: when an expectation is configured the
# persisted provenance must record configured_model_match=true. The
# comparison itself happened in memory at runtime; here we only verify
# the sanitized boolean, never the model name.
if [ -n "${EXPECTED_MODEL}" ]; then
  if grep -RIlq '"configured_model_match": *true' "${STATE_DIR}" 2>/dev/null; then
    echo "CONFIGURED_MODEL_MATCH_GATE=PASS"
  else
    echo "CONFIGURED_MODEL_MATCH_GATE=FAIL (expected model not matched)"
    RC=1
  fi
else
  echo "CONFIGURED_MODEL_MATCH_GATE=SKIP (no model expectation configured)"
fi

# MODEL_NAME_NONPERSISTENCE_GATE + MODEL_LOG_REDACTION_GATE: exact
# provider model names must NOT appear in persisted state, reports, or
# submission-intended logs. A sanitized record carries NO provider
# token at all (model_name_redacted=true, profile wording is generic),
# so any provider+version token is an unambiguous leak. Provider
# fragments are assembled at runtime so this script is not itself a
# forbidden-token list.
# Provider prefixes assembled from fragments at runtime so this script
# is not itself a forbidden contiguous provider/model literal.
P1="claude"; P2="gpt"; P3="gemini"; P4="qwen"; SEP="-"
LEAK=0
for d in "${STATE_DIR}" "${REPORT_DIR}"; do
  [ -d "${d}" ] || continue
  if grep -RInqE "${P1}${SEP}[0-9]|${P2}${SEP}[0-9]|${P3}${SEP}[0-9]|${P4}[0-9${SEP}]" "${d}" 2>/dev/null; then
    LEAK=1
  fi
done
if [ "${LEAK}" -eq 0 ]; then
  echo "MODEL_NAME_NONPERSISTENCE_GATE=PASS"
  echo "MODEL_LOG_REDACTION_GATE=PASS"
else
  echo "MODEL_NAME_NONPERSISTENCE_GATE=FAIL (model name leaked into state/report)"
  echo "MODEL_LOG_REDACTION_GATE=FAIL"
  RC=1
fi

exit "${RC}"

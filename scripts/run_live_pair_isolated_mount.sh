#!/usr/bin/env bash
set -Eeuo pipefail

# Dataset-agnostic live runner.
#
# Guarantees:
# - Never reuses /mnt/windows_mount.
# - Creates one fresh EWF mount dir and one fresh NTFS mount dir per run.
# - Passes that isolated mount to run_pipeline.py.
# - Records run metadata outside source logic only.
# - Does not cache tool outputs.
#
# Required env/args:
#   MEMORY_IMAGE=/path/to/memory.img
#   DISK_IMAGE=/path/to/disk.E01
#   CASE_LABEL=some-label
#
# Optional:
#   MODEL=claude-haiku-4-5-20251001
#   ART_ROOT=logs

MEMORY_IMAGE="${MEMORY_IMAGE:-}"
DISK_IMAGE="${DISK_IMAGE:-}"
CASE_LABEL="${CASE_LABEL:-case}"
MODEL="${MODEL:-claude-haiku-4-5-20251001}"
ART_ROOT="${ART_ROOT:-logs}"

if [ -z "$MEMORY_IMAGE" ] || [ -z "$DISK_IMAGE" ]; then
  echo "usage: MEMORY_IMAGE=/path/mem.img DISK_IMAGE=/path/disk.E01 CASE_LABEL=name $0"
  exit 2
fi

if [ ! -f "$MEMORY_IMAGE" ]; then
  echo "FAIL: memory image not found: $MEMORY_IMAGE"
  exit 2
fi

if [ ! -f "$DISK_IMAGE" ]; then
  echo "FAIL: disk image not found: $DISK_IMAGE"
  exit 2
fi

export PYTHONPATH=src:. PAGER=cat PYTHONDONTWRITEBYTECODE=1

echo "Paste sk-ant- key (hidden), press Enter:"
read -rs ANTHROPIC_API_KEY
export ANTHROPIC_API_KEY="$(printf '%s' "$ANTHROPIC_API_KEY" | tr -d '[:space:]')"
echo "  key set ($(printf '%s' "$ANTHROPIC_API_KEY" | wc -c) chars, sha256-12=$(printf '%s' "$ANTHROPIC_API_KEY" | sha256sum | cut -c1-12))"

RUN_ID="$(date +%Y%m%d-%H%M%S)-$$"
MOUNT_ROOT="/tmp/sift-isolated-mount-${CASE_LABEL}-${RUN_ID}"
EWF_DIR="${MOUNT_ROOT}/ewf"
NTFS_DIR="${MOUNT_ROOT}/ntfs"
ART="${ART_ROOT}/${CASE_LABEL}-haiku-ens4-${RUN_ID}"

mkdir -p "$EWF_DIR" "$NTFS_DIR" "$ART"

cleanup() {
  set +e
  sudo umount "$NTFS_DIR" 2>/dev/null || sudo umount -l "$NTFS_DIR" 2>/dev/null || true
  sudo umount "$EWF_DIR" 2>/dev/null || sudo umount -l "$EWF_DIR" 2>/dev/null || true
}
trap cleanup EXIT

echo "== isolated mount =="
echo "mount_root=$MOUNT_ROOT"
echo "ewf_dir=$EWF_DIR"
echo "ntfs_dir=$NTFS_DIR"

# RUN17_ISOLATED_EWF_ALLOW_OTHER_V4
# Mount EWF into this run's private directory. We need the exposed ewf image
# to be visible to root because the NTFS loop mount is performed with sudo.
# Prefer allow_other; otherwise fail closed with diagnostics.
EWF_LOG="$ART/ewfmount.log"
: > "$EWF_LOG"

_unmount_ewf_layer() {
  fusermount -u "$EWF_DIR" 2>/dev/null || fusermount3 -u "$EWF_DIR" 2>/dev/null || true
  sudo umount "$EWF_DIR" 2>/dev/null || sudo umount -l "$EWF_DIR" 2>/dev/null || true
}

_probe_ewf_image() {
  EWF_IMAGE=""
  for _i in $(seq 1 20); do
    if [ -e "$EWF_DIR/ewf1" ]; then
      EWF_IMAGE="$EWF_DIR/ewf1"
    elif sudo test -e "$EWF_DIR/ewf1" 2>/dev/null; then
      EWF_IMAGE="$EWF_DIR/ewf1"
    else
      _candidate="$(find "$EWF_DIR" -maxdepth 1 -name 'ewf*' 2>/dev/null | sort | head -1 || true)"
      if [ -z "$_candidate" ]; then
        _candidate="$(sudo find "$EWF_DIR" -maxdepth 1 -name 'ewf*' 2>/dev/null | sort | head -1 || true)"
      fi
      if [ -n "$_candidate" ]; then
        EWF_IMAGE="$_candidate"
      fi
    fi

    if [ -n "$EWF_IMAGE" ]; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

_try_ewfmount() {
  _label="$1"
  shift
  echo "attempt=$_label" >> "$EWF_LOG"
  set +e
  "$@" >> "$EWF_LOG" 2>&1
  EWF_RC=$?
  set -e
  echo "attempt_rc=$EWF_RC" >> "$EWF_LOG"

  if [ "$EWF_RC" -ne 0 ]; then
    _unmount_ewf_layer
    return 1
  fi

  if _probe_ewf_image; then
    return 0
  fi

  _unmount_ewf_layer
  return 1
}

EWF_RC=1
EWF_IMAGE=""

_try_ewfmount "ewfmount -X allow_other" ewfmount -X allow_other "$DISK_IMAGE" "$EWF_DIR" \
  || _try_ewfmount "sudo ewfmount -X allow_other" sudo ewfmount -X allow_other "$DISK_IMAGE" "$EWF_DIR" \
  || _try_ewfmount "ewfmount default" ewfmount "$DISK_IMAGE" "$EWF_DIR" \
  || _try_ewfmount "sudo ewfmount default" sudo ewfmount "$DISK_IMAGE" "$EWF_DIR" \
  || true

cat "$EWF_LOG" || true
echo "ewfmount_rc=${EWF_RC:-unknown}"
findmnt "$EWF_DIR" || true
ls -la "$EWF_DIR" 2>/dev/null || true
sudo ls -la "$EWF_DIR" 2>/dev/null || true

if [ -z "$EWF_IMAGE" ] || ! sudo test -e "$EWF_IMAGE" 2>/dev/null; then
  echo "FAIL: EWF mount did not expose a root-visible ewf image under isolated EWF dir"
  echo "disk_image=$DISK_IMAGE"
  echo "ewf_dir=$EWF_DIR"
  echo "ewf_image=${EWF_IMAGE:-}"
  echo "-- ewfmount log --"
  cat "$EWF_LOG" || true
  echo "-- findmnt --"
  findmnt "$EWF_DIR" || true
  echo "-- user dir listing --"
  ls -la "$EWF_DIR" 2>/dev/null || true
  echo "-- sudo dir listing --"
  sudo ls -la "$EWF_DIR" 2>/dev/null || true
  echo "HINT: if allow_other is rejected, check /etc/fuse.conf for user_allow_other or run the runner with a root-visible EWF mount path."
  exit 1
fi

echo "ewf_image=$EWF_IMAGE"

mapfile -t OFFSET_CANDIDATES < <(sudo mmls "$EWF_IMAGE" 2>/dev/null | awk 'tolower($0) ~ /ntfs|basic data/ {gsub(/[^0-9]/, "", $3); if ($3 + 0 > 0) print $3}' | sort -nu || true)
echo "mmls_offsets=${OFFSET_CANDIDATES[*]:-none}"

NTFS_MOUNTED=0
OFFSET=""
MOUNT_MODE="none"

_try_ntfs_mount_and_accept() {
  local mode="$1"
  local opts="$2"
  echo "ntfs_mount_attempt=$mode"
  sudo umount "$NTFS_DIR" 2>/dev/null || true
  if sudo mount -v -o "$opts" "$EWF_IMAGE" "$NTFS_DIR"; then
    if [ -d "$NTFS_DIR/Windows" ]; then
      NTFS_MOUNTED=1
      MOUNT_MODE="$mode"
      echo "ntfs_mount_accept=$mode"
      return 0
    fi
    echo "ntfs_mount_reject=$mode reason=Windows_directory_missing"
    sudo umount "$NTFS_DIR" 2>/dev/null || true
  else
    local rc=$?
    echo "ntfs_mount_rc=$rc mode=$mode"
  fi
  return 1
}

for cand in "${OFFSET_CANDIDATES[@]}"; do
  if [ -n "$cand" ] && [ "$cand" -gt 0 ] 2>/dev/null; then
    OFFSET="$cand"
    _try_ntfs_mount_and_accept "offset_${cand}" "ro,loop,offset=$((cand*512)),uid=$(id -u),gid=$(id -g),umask=022,show_sys_files,streams_interface=windows,force" && break
  fi
done

if [ "$NTFS_MOUNTED" -ne 1 ]; then
  OFFSET=""
  _try_ntfs_mount_and_accept "raw_ntfs_volume" "ro,loop,uid=$(id -u),gid=$(id -g),umask=022,show_sys_files,streams_interface=windows,force" || true
fi

if [ "$NTFS_MOUNTED" -ne 1 ]; then
  echo "FAIL: isolated NTFS mount failed or no mounted candidate contained Windows/"
  echo "disk_image=$DISK_IMAGE"
  echo "ewf_image=$EWF_IMAGE"
  echo "ntfs_dir=$NTFS_DIR"
  echo "offset_candidates=${OFFSET_CANDIDATES[*]:-none}"
  exit 4
fi

echo "ntfs_mount_mode=$MOUNT_MODE"

if [ "$NTFS_DIR" = "/mnt/windows_mount" ]; then
  echo "FAIL: isolated runner attempted to use global /mnt/windows_mount"
  exit 5
fi

{
  echo "case_label=$CASE_LABEL"
  echo "memory_image=$MEMORY_IMAGE"
  echo "disk_image=$DISK_IMAGE"
  echo "mount_root=$MOUNT_ROOT"
  echo "ewf_dir=$EWF_DIR"
  echo "ntfs_dir=$NTFS_DIR"
  echo "offset=${OFFSET:-none}"
  echo "mount_mode=${MOUNT_MODE:-unknown}"
  echo "evtx_count=$(find "$NTFS_DIR/Windows/System32/winevt/Logs" -maxdepth 1 -iname '*.evtx' 2>/dev/null | wc -l || true)"
  echo "prefetch_count=$(find "$NTFS_DIR/Windows/Prefetch" -maxdepth 1 -iname '*.pf' 2>/dev/null | wc -l || true)"
  echo "lnk_count_users_depth4=$(find "$NTFS_DIR/Users" "$NTFS_DIR/Documents and Settings" -maxdepth 4 -iname '*.lnk' 2>/dev/null | wc -l || true)"
  findmnt "$NTFS_DIR" || true
} | tee "$ART/mount_identity.txt"

export SIFT_FORCE_MODEL="$MODEL"
export SIFT_DEFAULT_MODEL="$MODEL"
export SIFT_MODEL_INV1_PRIMARY="$MODEL"
export SIFT_MODEL_INV1_RETRY="$MODEL"
export SIFT_ENSEMBLE_MODELS="$MODEL,$MODEL,$MODEL,$MODEL"
export SIFT_INV2_ENSEMBLE_MODELS="$MODEL,$MODEL,$MODEL,$MODEL"
export SIFT_INV2_ENSEMBLE_FORCE_MODEL="$MODEL"
export SIFT_FORCE_COLOR="${SIFT_FORCE_COLOR:-1}"

env | grep '^SIFT_' | sort > "$ART/env.txt"

echo "== run =="
echo "artifact_dir=$ART"

python3 -u run_pipeline.py \
  --live \
  --inv2-ensemble \
  --image "$MEMORY_IMAGE" \
  --disk "$DISK_IMAGE" \
  --disk-mount "$NTFS_DIR" \
  2>&1 | tee "$ART/run.log"

echo "== post-run markers =="
grep -nE 'ZERO_RECORD_REASON_GATE|CANDIDATE_READY_CEILING|Candidate observations:|Step 10 typed-validator telemetry|VERIFIED:|NEEDS PROOF|PIPELINE SUMMARY|FP_FIDELITY|CUSTOMER_FINDINGS_TABLE' "$ART/run.log" || true

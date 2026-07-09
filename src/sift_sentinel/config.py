"""
Sentinel Qwen Ensemble - Configuration constants.
"""

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
EVIDENCE_DIR = Path("/evidence")
DISK_MOUNT_PATH = "/mnt/windows_mount"

VOL_CMD = ["vol"]

# Model ids are NOT hardcoded here. Stage models resolve at runtime from
# operator/env config via sift_sentinel.model_roles.resolve_model().
MAX_PIPELINE_TIME = 420
MAX_CORRECTION_ATTEMPTS = 3

LOG_FORMAT = "JSONL"
LOG_PATH = PROJECT_ROOT / "analysis" / "forensic_audit.jsonl"

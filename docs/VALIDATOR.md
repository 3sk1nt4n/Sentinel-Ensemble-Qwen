# Validator Design (historical pre-build notes)

> **Historical pre-build design notes**, kept for design provenance. The
> as-built validator lives in `src/sift_sentinel/validation/` (`validator.py`,
> `typed_validator.py`, `reference_set.py`) - see [`ARCHITECTURE.md`](../ARCHITECTURE.md).

### [paired values - not flat set]

**WRONG (flat set - cannot catch cross-contamination):**
```python
reference_set = {
    "a3f2c8d1e5b94f7260e8d3a1c9b47f52d6e81a30",  # SHA1 exists
    "payload.exe",                                   # filename exists
    "ransom.exe",                                   # filename exists
    # flat check PASSES: both values exist, but linking them wrong
}
```

**CORRECT (paired values):**
### Advanced scenario coverage in validator (NOT optional):

```python
# dkom_check() - runs after ALL tools complete, before model analysis
def dkom_check(pstree_output: dict, psscan_output: dict) -> list[dict]:
    """DKOM detection: find processes in psscan with no pstree entry.
    Deterministic Python. Not AI. Must be in Layer 2, not left to model.
    Returns list of hidden processes that are DKOM candidates."""
    pstree_pids = {p["pid"] for p in pstree_output["processes"]}
    orphaned = []
    for p in psscan_output["processes"]:
        if p["pid"] not in pstree_pids and p.get("name", "").endswith(".exe"):
            orphaned.append({
                "pid": p["pid"],
                "name": p.get("name"),
                "offset": p.get("offset"),
                "finding": "DKOM_CANDIDATE",
                "confidence": "MEDIUM",  # single source
                "note": "process in psscan with no pstree entry - EPROCESS unlinked"
            })
    return orphaned
    # TESTED: logic is correct. INFERRED: real Volatility output format matches.
    # Must verify field names against actual vol.py output in Task 0.
    #
    # PSSCAN UPGRADE (NotebookLM D, April 3 2026):
    # Current design: filescan-vs-pstree diff. Standard but not optimal.
    # Better: psscan-vs-pstree diff. psscan scans pool tags, finds unlinked/exited
    # processes that pstree (EPROCESS walk) misses. More standard DKOM detection.
    # DECISION REQUIRED in Task 0: run both vol.py windows.pstree and windows.psscan,
    # compare outputs. If psscan finds processes pstree doesn't, add vol_psscan as
    # Tool 1b OR fold psscan into dkom_check() as primary comparison source.

# MFT parser - SI and FN stored SEPARATELY
# WRONG (flat): {"timestamp": "2024-11-14T02:31:07", "path": "payload.exe"}
# CORRECT (separate):
# {
#   "path": "payload.exe",
#   "si_created":  "2018-03-15T00:00:00",  # $STANDARD_INFORMATION - user-writable
#   "fn_created":  "2024-11-14T02:31:07",  # $FILE_NAME - kernel-written
#   "timestomped": True,   # abs(si - fn) > 24h threshold
#   "real_created": "2024-11-14T02:31:07"  # fn_created is authoritative NTFS source
# }
# If timestomped=True: validator flags any model claim using si_created as HIGH.

# DLL known-good baseline - must exist before validator can check paths
# Source: clean Windows 10 build 16299 installation, same version as target evidence
# Location: (planned; never shipped - superseded by the structural/behavioral
#            checks in src/sift_sentinel/validation/)
# IMPORTANT: Path comparison MUST be case-insensitive (Gap 5 - semantic drift)
# "C:\Windows\System32" == "C:\Windows\system32" for baseline matching
# Flag: process name matches known-good BUT path differs by MORE than case = malicious
# Format: {"wbemcomn.dll": ["C:\Windows\System32\wbem\wbemcomn.dll"], ...}
# GUESSING: whether public practice-case evidence (see docs/DATASET.md) matches Windows 10 16299 DLL paths.
# Task 0: extract DLL baseline from a clean Windows VM matching target OS version.
```

**CORRECT (paired values):**
```python
reference_set = {
    "hashes": {
        "a3f2c8d1e5b94f7260e8d3a1c9b47f52d6e81a30": "payload.exe",  # hash -> filename
        "d4e1f2a3b5c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2": "ransom.exe",
    },
    "pid_to_process": {
        4012: "svchost.exe",
        9005: "payload.exe",
    },
    "timestamps_per_artifact": {
        "payload.exe": ["2024-11-14T02:31:07Z", "2024-11-14T02:31:22Z"],
        "ransom.exe": ["2024-11-14T04:47:13Z"],
    },
    "bytes_per_app": {
        "payload.exe": 2147483,  # from SRUM
    },
    "event_id_per_log": {
        ("4624", "Security"): [...],  # (event_id, log_source) pairs
    }
}
```

Cross-contamination catch: "SHA1:a3f2c8...belongs to ransom.exe" - validator checks reference_set["hashes"]["a3f2c8..."] == "payload.exe", mismatch = BLOCKED.

---

#!/usr/bin/env python3
"""
SIFT Sentinel -- Self-Correction Demo (Pipeline Step 12)
Proves the Ralph Wiggum loop works with 3 distinct strategies:
  Attempt 1: TARGETED_FIX   -- fix the exact failing claim
  Attempt 2: DIFFERENT_EVIDENCE -- drop failing claim, use different tools
  Attempt 3: MINIMAL_CLAIM  -- one claim or null (honest)

Three scenarios:
  F001: wrong hash  -> TARGETED_FIX fixes it    -> MATCH (attempt 1)
  F002: fake PID    -> TARGETED_FIX fails,
                       DIFFERENT_EVIDENCE uses connection -> MATCH (attempt 2)
  F003: no evidence -> all 3 strategies fail     -> UNRESOLVED (honest)

No API calls. No API key needed. Uses mock correctors with real validator.
Every printed result comes from actual code execution, not hardcoded strings.

Usage:
    python3 demo_self_correction.py
"""

from __future__ import annotations

import sys
import time
from datetime import datetime, timezone

from sift_sentinel.correction.self_correct import self_correct, STRATEGIES
from sift_sentinel.validation.reference_set import build_reference_set
from sift_sentinel.validation.validator import validate_finding


# ── ANSI colors ────────────────────────────────────────────────────────

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
DIM = "\033[2m"
RESET = "\033[0m"
BOLD = "\033[1m"


def ts() -> str:
    """UTC timestamp matching run_pipeline.py format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def log(step: str, msg: str, color: str = "") -> None:
    """Timestamped log line."""
    c = color or DIM
    print(f"{DIM}[{ts()}]{RESET} {c}{step}{RESET} {msg}")


# ── Tool outputs (mock evidence -- same shape as real cached_outputs) ──

TOOL_OUTPUTS = {
    "vol_pstree": {
        "output": [
            {"PID": 9001, "ImageFileName": "sample_payload.exe",
             "CreateTime": "2018-04-11T14:22:07Z"},
            {"PID": 4, "ImageFileName": "System"},
            {"PID": 1234, "ImageFileName": "svchost.exe"},
            {"PID": 6672, "ImageFileName": "rundll32.exe"},
        ],
    },
    "get_amcache": {
        "output": [
            {"sha1": "a3f2c8d1e5b94f7260e8d3a1c9b47f52d6e81a30",
             "path": r"C:\Windows\Temp\sample_payload.exe",
             "first_run": "2018-04-11 14:22:07"},
        ],
    },
    "vol_netscan": {
        "output": [
            {"PID": 9001, "LocalAddr": "192.0.2.111", "LocalPort": 49234,
             "ForeignAddr": "192.0.2.129", "ForeignPort": 443,
             "Owner": "sample_payload.exe"},
        ],
    },
}


def main() -> int:
    print(f"\n{BOLD}{CYAN}{'=' * 64}{RESET}")
    print(f"{BOLD}{CYAN}  SIFT Sentinel -- Self-Correction Demo (Step 12){RESET}")
    print(f"{BOLD}{CYAN}  3 Strategies: TARGETED_FIX / DIFFERENT_EVIDENCE / MINIMAL_CLAIM{RESET}")
    print(f"{BOLD}{CYAN}  No API calls. Real validator. Mock correctors.{RESET}")
    print(f"{BOLD}{CYAN}{'=' * 64}{RESET}\n")

    # ── Step 7: Build reference set from tool outputs ──────────────────
    log("Step 7:", "Building paired reference set from tool outputs...")
    ref_set = build_reference_set(TOOL_OUTPUTS)
    pid_count = len(ref_set["pid_to_process"])
    hash_count = len(ref_set["hashes"])
    conn_count = len(ref_set["connections"])
    log("Step 7:", f"Reference set ready: {pid_count} PIDs, "
        f"{hash_count} hashes, {conn_count} connections", GREEN)
    print()

    # ════════════════════════════════════════════════════════════════════
    # F001: Wrong hash -> TARGETED_FIX -> corrects hash -> MATCH
    # ════════════════════════════════════════════════════════════════════
    print(f"{BOLD}  Scenario 1: Wrong hash -> TARGETED_FIX -> MATCH{RESET}\n")

    f001 = {
        "finding_id": "F001",
        "artifact": "sample_payload.exe",
        "confidence_level": "HIGH",
        "claims": [
            {"type": "hash", "sha1": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
             "filename": "sample_payload.exe"},
        ],
    }

    log("Step 10:", f"Validating {BOLD}F001{RESET} against reference set")
    v1 = validate_finding(f001, ref_set)
    claim1 = f001["claims"][0]
    log("", f"  F001 CLAIM: sha1={claim1['sha1'][:12]}..., "
        f"file={claim1['filename']}")
    log("", f"  F001 RESULT: {RED}{v1['status']}{RESET} -- {v1['detail']}")
    print()

    def corrector_f001(raw_data, error):
        """Attempt 1 TARGETED_FIX: reads amcache, returns correct hash."""
        log("Step 12:", f"Strategy: {YELLOW}TARGETED_FIX{RESET}", YELLOW)
        log("", f"  PROMPT: {error[:80]}...", DIM)
        amcache = raw_data.get("get_amcache", {}).get("output", [])
        if amcache:
            entry = amcache[0]
            log("", f"  CORRECTOR: Found hash {entry['sha1'][:12]}... "
                f"in amcache", GREEN)
        return {
            "finding_id": "F001",
            "artifact": "sample_payload.exe",
            "confidence_level": "HIGH",
            "claims": [
                {"type": "hash",
                 "sha1": "a3f2c8d1e5b94f7260e8d3a1c9b47f52d6e81a30",
                 "filename": "sample_payload.exe"},
            ],
        }

    result_f001 = self_correct(
        finding=f001, error=v1["detail"], raw_data=TOOL_OUTPUTS,
        ref_set=ref_set, corrector_fn=corrector_f001,
    )

    _print_result("F001", result_f001)
    print()

    # ════════════════════════════════════════════════════════════════════
    # F002: Fabricated PID -> TARGETED_FIX fails -> DIFFERENT_EVIDENCE
    #       uses connection claim -> MATCH
    # ════════════════════════════════════════════════════════════════════
    print(f"{BOLD}  Scenario 2: Fabricated PID -> DIFFERENT_EVIDENCE -> MATCH{RESET}\n")

    f002 = {
        "finding_id": "F002",
        "artifact": "sample_payload.exe",
        "confidence_level": "HIGH",
        "claims": [
            {"type": "pid", "pid": 9999, "process": "fake.exe"},
        ],
    }

    log("Step 10:", f"Validating {BOLD}F002{RESET} against reference set")
    v2 = validate_finding(f002, ref_set)
    claim2 = f002["claims"][0]
    log("", f"  F002 CLAIM: pid={claim2['pid']}, process={claim2['process']}")
    log("", f"  F002 RESULT: {RED}{v2['status']}{RESET} -- {v2['detail']}")
    print()

    f002_attempt = [0]

    def corrector_f002(raw_data, error):
        """Attempt 1: still wrong PID. Attempt 2: switch to connection."""
        f002_attempt[0] += 1
        att = f002_attempt[0]
        strategy = STRATEGIES.get(min(att, 3), STRATEGIES[3])["name"]
        log("Step 12:", f"Strategy: {YELLOW}{strategy}{RESET}", YELLOW)

        if att == 1:
            log("", f"  CORRECTOR: Trying different PID (still wrong)...", YELLOW)
            return {
                "finding_id": "F002",
                "artifact": "sample_payload.exe",
                "confidence_level": "HIGH",
                "claims": [
                    {"type": "pid", "pid": 7777, "process": "sample_payload.exe"},
                ],
            }

        # Attempt 2: DIFFERENT_EVIDENCE -- use connection claim
        netscan = raw_data.get("vol_netscan", {}).get("output", [])
        if netscan:
            conn = netscan[0]
            log("", f"  CORRECTOR: Dropping PID claim, using netscan "
                f"connection instead", GREEN)
            log("", f"  CORRECTOR: PID {conn['PID']} -> "
                f"{conn['ForeignAddr']}:{conn['ForeignPort']}", GREEN)
        return {
            "finding_id": "F002",
            "artifact": "sample_payload.exe",
            "confidence_level": "HIGH",
            "claims": [
                {"type": "connection", "pid": 9001,
                 "foreign_addr": "192.0.2.129",
                 "process": "sample_payload.exe"},
            ],
        }

    result_f002 = self_correct(
        finding=f002, error=v2["detail"], raw_data=TOOL_OUTPUTS,
        ref_set=ref_set, corrector_fn=corrector_f002,
    )

    _print_result("F002", result_f002)
    print()

    # ════════════════════════════════════════════════════════════════════
    # F003: No valid claims -> All 3 strategies fail -> UNRESOLVED
    # ════════════════════════════════════════════════════════════════════
    print(f"{BOLD}  Scenario 3: No valid claims -> 3 strategies -> UNRESOLVED{RESET}\n")

    f003 = {
        "finding_id": "F003",
        "artifact": "ghost.dll",
        "confidence_level": "MEDIUM",
        "claims": [
            {"type": "hash", "sha1": "abc123abc123abc123abc123abc123abc123abc1",
             "filename": "ghost.dll"},
        ],
    }

    log("Step 10:", f"Validating {BOLD}F003{RESET} against reference set")
    v3 = validate_finding(f003, ref_set)
    claim3 = f003["claims"][0]
    log("", f"  F003 CLAIM: sha1={claim3['sha1'][:12]}..., "
        f"file={claim3['filename']}")
    log("", f"  F003 RESULT: {RED}{v3['status']}{RESET} -- {v3['detail']}")
    print()

    fake_hashes = [
        "def456def456def456def456def456def456def4",
        "789abc789abc789abc789abc789abc789abc789a",
        "111222111222111222111222111222111222111222",
    ]
    f003_attempt = [0]

    def corrector_f003(raw_data, error):
        """All 3 attempts produce wrong hashes."""
        f003_attempt[0] += 1
        att = f003_attempt[0]
        idx = min(att - 1, len(fake_hashes) - 1)
        strategy = STRATEGIES.get(min(att, 3), STRATEGIES[3])["name"]
        log("Step 12:", f"Strategy: {YELLOW}{strategy}{RESET}", YELLOW)
        log("", f"  CORRECTOR: Produced hash {fake_hashes[idx][:12]}...", YELLOW)
        return {
            "finding_id": "F003",
            "artifact": "ghost.dll",
            "confidence_level": "MEDIUM",
            "claims": [
                {"type": "hash", "sha1": fake_hashes[idx],
                 "filename": "ghost.dll"},
            ],
        }

    result_f003 = self_correct(
        finding=f003, error=v3["detail"], raw_data=TOOL_OUTPUTS,
        ref_set=ref_set, corrector_fn=corrector_f003,
    )

    # Print each attempt's strategy and result
    for att in result_f003["attempts"]:
        att_status = att["status"]
        strategy = att.get("strategy", "?")
        color = GREEN if att_status == "MATCH" else RED
        log("", f"  Attempt {att['attempt']} ({strategy}): "
            f"{color}{att_status}{RESET} -- {att.get('detail', '')}")

    _print_result("F003", result_f003)
    print()

    # ── Summary ────────────────────────────────────────────────────────
    print(f"{BOLD}{CYAN}{'=' * 64}{RESET}")
    print(f"{BOLD}{CYAN}  Self-Correction Summary{RESET}")
    print(f"{BOLD}{CYAN}{'=' * 64}{RESET}")

    scenarios = [
        ("F001", result_f001, "TARGETED_FIX"),
        ("F002", result_f002, "DIFFERENT_EVIDENCE"),
        ("F003", result_f003, "all 3 strategies"),
    ]

    corrected_count = 0
    total_count = len(scenarios)

    for fid, result, winning_strategy in scenarios:
        status = result["status"]
        attempts = result["attempt_count"]
        if status == "CORRECTED":
            corrected_count += 1
            color = GREEN
            label = (f"MISMATCH -> MATCH via {winning_strategy} "
                     f"({attempts} attempt{'s' if attempts > 1 else ''})")
        else:
            color = RED
            label = (f"MISMATCH -> UNRESOLVED after {winning_strategy} "
                     f"({attempts} attempts, honest failure)")
        print(f"  {color}{fid}: {label}{RESET}")

    rate = corrected_count / total_count * 100
    color = GREEN if corrected_count > 0 else RED
    print(f"  {color}Correction rate: "
          f"{corrected_count}/{total_count} ({rate:.0f}%){RESET}")

    # ── Integrity assertions (prove this ran real code) ────────────────
    print(f"\n{DIM}  Integrity checks:{RESET}")
    checks = [
        ("ref_set built from build_reference_set()",
         9001 in ref_set["pid_to_process"]),
        ("F001 blocked by validator (wrong hash)",
         v1["status"] == "MISMATCH"),
        ("F001 corrected via TARGETED_FIX (attempt 1)",
         result_f001["status"] == "CORRECTED"
         and result_f001["attempt_count"] == 1),
        ("F001 attempt 1 strategy is TARGETED_FIX",
         result_f001["attempts"][0].get("strategy") == "TARGETED_FIX"),
        ("F002 blocked by validator (fake PID)",
         v2["status"] == "MISMATCH"),
        ("F002 corrected via DIFFERENT_EVIDENCE (attempt 2)",
         result_f002["status"] == "CORRECTED"
         and result_f002["attempt_count"] == 2),
        ("F002 attempt 1 strategy is TARGETED_FIX",
         result_f002["attempts"][0].get("strategy") == "TARGETED_FIX"),
        ("F002 attempt 2 strategy is DIFFERENT_EVIDENCE",
         result_f002["attempts"][1].get("strategy") == "DIFFERENT_EVIDENCE"),
        ("F003 blocked by validator (no matching hash)",
         v3["status"] == "MISMATCH"),
        ("F003 UNRESOLVED after 3 attempts (honest failure)",
         result_f003["status"] == "UNRESOLVED"
         and result_f003["attempt_count"] == 3),
        ("F003 used all 3 strategies",
         [a.get("strategy") for a in result_f003["attempts"]]
         == ["TARGETED_FIX", "DIFFERENT_EVIDENCE", "MINIMAL_CLAIM"]),
        ("F003 score=0 (honest unknown)",
         result_f003["finding"].get("score") == 0),
    ]

    all_ok = True
    for label, ok in checks:
        icon = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
        print(f"    [{icon}] {label}")
        if not ok:
            all_ok = False

    print()
    if all_ok:
        log("", f"{GREEN}{BOLD}Demo complete. All assertions passed.{RESET}")
    else:
        log("", f"{RED}{BOLD}Demo FAILED. See above.{RESET}")

    return 0 if all_ok else 1


def _print_result(fid: str, result: dict) -> None:
    """Print the final status for a finding."""
    status = result["status"]
    attempts = result["attempt_count"]
    if status == "CORRECTED":
        winning = result["attempts"][-1].get("strategy", "?")
        log("", f"  {GREEN}{BOLD}{fid}: MISMATCH -> MATCH via {winning} "
            f"({attempts} attempt{'s' if attempts > 1 else ''}){RESET}")
    else:
        log("", f"  {RED}{BOLD}{fid}: UNRESOLVED after "
            f"{attempts} attempts (honest: cannot verify){RESET}")


if __name__ == "__main__":
    sys.exit(main())

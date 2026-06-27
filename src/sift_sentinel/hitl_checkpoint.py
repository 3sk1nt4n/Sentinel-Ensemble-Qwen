"""Human-in-the-loop checkpoint at the critical decision point (Track-4).

Opt-in (`SIFT_HITL_CHECKPOINT=1`) and TTY-gated: after the deterministic
disposition is finalized but BEFORE the incident report is written, pause and let
the analyst APPROVE the verdicts or OVERRIDE a single finding's bucket. This is
the explicit "human-in-the-loop checkpoint at a critical decision point" Track-4
asks for -- the agent still never auto-confirms without atomic proof; this adds a
human approval gate on top of the deterministic gates.

Default OFF -> the autonomous pipeline is byte-identical (no prompt, no pause).
Also a no-op when stdin is not a TTY (e.g. nohup/CI), so non-interactive runs are
unaffected. The override logic is a PURE function (unit-tested); the interactive
driver is a thin shell around it. Universal: keys on bucket names only, never on
case data.
"""
from __future__ import annotations

import copy
import os
import sys

# Canonical disposition buckets (mirror analysis.disposition).
BUCKETS = (
    "confirmed_malicious_atomic",
    "suspicious_needs_review",
    "benign_or_false_positive",
    "inconclusive_unresolved",
    "synthesis_narrative",
)
# Friendly aliases an analyst can type at the prompt.
_ALIAS = {
    "confirmed": "confirmed_malicious_atomic", "malicious": "confirmed_malicious_atomic",
    "review": "suspicious_needs_review", "needs-review": "suspicious_needs_review",
    "needs_review": "suspicious_needs_review", "suspicious": "suspicious_needs_review",
    "benign": "benign_or_false_positive", "fp": "benign_or_false_positive",
    "false-positive": "benign_or_false_positive",
    "inconclusive": "inconclusive_unresolved",
}


def checkpoint_enabled() -> bool:
    return os.environ.get("SIFT_HITL_CHECKPOINT", "").strip().lower() in (
        "1", "true", "yes", "on")


def _fid_of(f) -> str:
    if isinstance(f, dict):
        return str(f.get("finding_id") or f.get("id") or "")
    return str(f)


def _label_of(f) -> str:
    if isinstance(f, dict):
        return str(f.get("artifact") or f.get("title") or f.get("summary") or "")[:80]
    return ""


def resolve_bucket(name: str) -> str | None:
    n = (name or "").strip().lower()
    n = _ALIAS.get(n, n)
    return n if n in BUCKETS else None


def apply_override(buckets: dict, fid: str, dest: str):
    """Move finding ``fid`` to bucket ``dest``. PURE: returns (new_buckets, ok, msg).
    Never mutates the input. Unknown bucket / missing finding -> (buckets, False, msg)."""
    d = resolve_bucket(dest)
    if d is None:
        return buckets, False, f"unknown bucket '{dest}' (use: {', '.join(BUCKETS)})"
    b = copy.deepcopy(buckets)
    moved = None
    for items in b.values():
        if not isinstance(items, list):
            continue
        for it in list(items):
            if _fid_of(it) == str(fid):
                moved = it
                items.remove(it)
                break
        if moved is not None:
            break
    if moved is None:
        return buckets, False, f"finding '{fid}' not found"
    b.setdefault(d, []).append(moved)
    return b, True, f"{fid} -> {d}"


def run_checkpoint(buckets: dict, findings_final=None):
    """Interactive analyst approval gate. Returns (buckets, overrode: bool).
    No-op (returns unchanged) when stdin is not a TTY."""
    if not sys.stdin.isatty():
        return buckets, False

    def _show():
        conf = buckets.get("confirmed_malicious_atomic") or []
        rev = buckets.get("suspicious_needs_review") or []
        print("\n" + "=" * 64)
        print("  HUMAN-IN-THE-LOOP CHECKPOINT  (critical decision point)")
        print("  The code has dispositioned every finding. Review before the report.")
        print("=" * 64)
        print(f"  CONFIRMED malicious ({len(conf)}) -- will drive the incident report:")
        for f in conf:
            print(f"    [{_fid_of(f)}] {_label_of(f)}")
        print(f"  NEEDS REVIEW ({len(rev)}) -- escalated to you, not asserted:")
        for f in rev[:12]:
            print(f"    [{_fid_of(f)}] {_label_of(f)}")
        if len(rev) > 12:
            print(f"    ... +{len(rev) - 12} more")
        print("-" * 64)
        print("  [Enter]=approve & continue   o <FID> <bucket>=override   q=abort")
        print(f"  buckets: {', '.join(BUCKETS)}")

    overrode = False
    _show()
    while True:
        try:
            line = input("  checkpoint> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  (no input -- approving as-is)")
            return buckets, overrode
        if line == "" or line.lower() in ("a", "approve", "y", "yes", "c", "continue"):
            print("  approved -- proceeding to report.")
            return buckets, overrode
        if line.lower() in ("q", "quit", "abort"):
            raise SystemExit("HITL checkpoint: analyst aborted the run before report.")
        parts = line.split()
        if len(parts) == 3 and parts[0].lower() == "o":
            buckets, ok, msg = apply_override(buckets, parts[1], parts[2])
            print("  " + ("OK: " if ok else "rejected: ") + msg)
            if ok:
                overrode = True
                _show()
        else:
            print("  usage: <Enter> | o <FID> <bucket> | q")

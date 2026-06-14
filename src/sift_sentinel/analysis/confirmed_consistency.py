"""Exec-summary / confirmed-bucket consistency -- deterministic, additive.

The report writer (Inv4) free-writes prose and may label a finding
'confirmed' that the disposition pipeline did NOT put in the confirmed
bucket. The structured sections render from the bucket, so the reader sees
a direct contradiction. This module closes it deterministically at the
report-write chokepoint: every F-id named on a positive confirm-context
line that is not in the confirmed bucket gets its TRUE bucket appended
right after the id. Model prose is never deleted or reworded -- the
annotation only states bucket truth, so a rare context misread still
prints only facts.

Universal: keyed on bucket membership + the word-stem 'confirm'; no case
data. Idempotent (the annotation marker is the guard). Fail-safe (returns
input unchanged on any error). Kill-switch SIFT_CONFIRMED_CONSISTENCY=0.
"""
from __future__ import annotations

import os
import re

# Live ids are F034-shaped; legacy schema used F-034. Accept both.
_ID_RE = re.compile(r"\bF-?\d{3}\b")

# 'confirmed benign', 'confirm ... as a false positive' assert the BENIGN
# verdict; 'not confirmed' / 'unconfirmed' / 'could not be confirmed' negate
# it. Both are removed from the line COPY before testing for confirm-context
# so they never count as a malicious-confirm claim.
_NON_MALICIOUS_CONFIRM_RE = re.compile(
    r"(?:\bun|\bnot\s+|\bnever\s+|\bcannot\s+be\s+|\bcould\s*(?:n't|\s+not)\s+be\s+)?"
    r"confirm\w*(?:\s+\S+){0,3}?\s+(?:as\s+)?(?:a\s+)?"
    r"(?:benign|false[- ]?positives?|legitimate|clean|safe)\b"
    r"|(?:\bun|\bnot\s+|\bno\s+|\bnever\s+|\bcannot\s+be\s+"
    r"|\bcould\s*(?:n't|\s+not)(?:\s+be)?\s+)confirm\w*",
    re.IGNORECASE,
)
_CONFIRM_RE = re.compile(r"\bconfirm\w*", re.IGNORECASE)

_MARKER = "(status:"

_BUCKET_LABEL = {
    "suspicious_needs_review": "needs review",
    "benign_or_false_positive": "benign/false positive",
    "inconclusive_unresolved": "inconclusive",
    "synthesis_narrative": "context/synthesis",
}

_CONFIRMED_BUCKET = "confirmed_malicious_atomic"


def _id_to_bucket(buckets: dict) -> dict:
    out: dict[str, str] = {}
    for bname, items in (buckets or {}).items():
        for f in items or []:
            if isinstance(f, dict):
                fid = str(f.get("finding_id") or f.get("id") or "").strip()
                if fid:
                    out[fid] = bname
    return out


def _norm(fid: str) -> str:
    return fid.replace("-", "")


def _is_malicious_confirm_line(line: str) -> bool:
    stripped = _NON_MALICIOUS_CONFIRM_RE.sub("", line)
    return bool(_CONFIRM_RE.search(stripped))


def scan_confirmed_contradictions(report_md, confirmed_ids) -> list[dict]:
    """Pure scan: ids labeled confirmed in prose but not in confirmed_ids.

    Returns [{"finding_id", "line_no", "line"}] -- no rewriting. Shared by
    the report-write reconcile and the validate_report telemetry warning.
    """
    hits: list[dict] = []
    if not isinstance(report_md, str) or not report_md:
        return hits
    norm_confirmed = {_norm(str(c)) for c in (confirmed_ids or set())}
    for i, line in enumerate(report_md.splitlines(), 1):
        if not _is_malicious_confirm_line(line):
            continue
        for m in _ID_RE.finditer(line):
            fid = m.group(0)
            if _norm(fid) in norm_confirmed:
                continue
            # idempotency / redundancy guard: already annotated
            if line[m.end():].lstrip().startswith(_MARKER):
                continue
            hits.append({"finding_id": fid, "line_no": i, "line": line})
    return hits


def reconcile_confirmed_mentions(report_md, buckets):
    """Annotate non-confirmed ids on confirm-context lines with bucket truth.

    Returns (report_md, n_annotations). Additive only; idempotent; fail-safe.
    """
    if not isinstance(report_md, str) or not report_md or not isinstance(buckets, dict):
        return report_md, 0
    if os.environ.get("SIFT_CONFIRMED_CONSISTENCY", "1").strip().lower() in (
            "0", "false", "no", "off"):
        return report_md, 0
    try:
        id_bucket = _id_to_bucket(buckets)
        confirmed = {fid for fid, b in id_bucket.items() if b == _CONFIRMED_BUCKET}
        hits = scan_confirmed_contradictions(report_md, confirmed)
        if not hits:
            return report_md, 0
        norm_bucket = {_norm(k): v for k, v in id_bucket.items()}
        lines = report_md.splitlines(keepends=True)
        n = 0
        by_line: dict[int, list[dict]] = {}
        for h in hits:
            by_line.setdefault(h["line_no"], []).append(h)
        for line_no, line_hits in by_line.items():
            line = lines[line_no - 1]
            seen: set[str] = set()
            for h in line_hits:
                fid = h["finding_id"]
                if fid in seen:
                    continue
                seen.add(fid)
                bucket = norm_bucket.get(_norm(fid))
                label = _BUCKET_LABEL.get(
                    bucket, "not a finding id from this run" if bucket is None else bucket)
                if bucket is None:
                    note = f"{fid} (status: {label})"
                else:
                    note = f"{fid} (status: {label} -- NOT in the confirmed set)"
                # replace only bare mentions (not already-annotated ones)
                line = re.sub(
                    re.escape(fid) + r"\b(?!\s*\(status:)", note, line)
                n += 1
            lines[line_no - 1] = line
        return "".join(lines), n
    except Exception:
        return report_md, 0

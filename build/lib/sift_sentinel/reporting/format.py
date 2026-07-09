"""Finding ID display formatter.

Judges read the terminal/HTML report. "FNNN" reads as a technical code;
"Finding 1" is cleaner. This helper is display-only -- the canonical
``finding_id`` string is unchanged in JSON outputs, state files,
validator internals, and operational log lines.
"""
from __future__ import annotations


def display_finding_id(finding_id: str, total: int | None = None) -> str:
    """Convert canonical ``FNNN`` -> ``Finding 1``.

    P0-E: the previous "Finding N of T" form created a false-precision bug
    when blocked findings caused finding_id gaps (a later id displayed with a
    smaller running total read as "Finding N of M" with N > M). The numeric
    rank derived from the canonical id is sufficient; `total` is accepted for
    signature compatibility and ignored.

    Parameters
    ----------
    finding_id : str
        Canonical finding identifier, typically ``F`` followed by digits.
    total : int | None
        Ignored. Retained for backwards compatibility with existing callers.

    Returns
    -------
    str
        Human-readable label. Malformed input is returned unchanged so
        unexpected upstream values do not disappear from the report.

    Examples
    --------
    >>> display_finding_id("FNNN")
    'Finding 1'
    >>> display_finding_id("FNNN", total=7)
    'Finding 3'
    >>> display_finding_id("X999")
    'X999'
    """
    del total  # P0-E: argument accepted but no longer rendered
    if not finding_id or not isinstance(finding_id, str):
        return finding_id or ""
    if not finding_id.startswith("F"):
        return finding_id
    try:
        n = int(finding_id[1:])
    except ValueError:
        return finding_id
    return f"Finding {n}"

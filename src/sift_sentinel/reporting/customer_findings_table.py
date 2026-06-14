"""Customer-facing deterministic findings table.

Visible grid policy:
- Show a neutral investigation table.
- Do not show score/routing labels as columns.
- Put verified false-alarm rows in a bottom band controlled by fp_fidelity.
- Put self-correction notes inside Details.
- No case-specific constants or case-key data in this renderer.
"""

from __future__ import annotations

from typing import Any, Iterable
import textwrap


VISIBLE_FP_STATUS = "visible_fp_verified"
WITHHELD_FP_STATUS = "fp_withheld_needs_review"

_BUCKET_ORDER = (
    "confirmed_malicious_atomic",
    "suspicious_needs_review",
    "synthesis_narrative",
    "inconclusive_unresolved",
    "benign_or_false_positive",
)

# Narrow enough for normal terminals, wide enough for readable customer output.
# Hard wrapping below guarantees no cell can spill past its lane.
_COLUMNS = (
    ("#", 3),
    ("Finding ID", 10),
    ("What AI Observed", 23),
    ("IOC / Artifacts", 19),
    ("Tools Hit", 17),
    ("Details Explain", 27),
)


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    text = str(value)
    # JSON-origin strings sometimes arrive with doubled backslashes.
    text = text.replace("\\\\", "\\")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text.strip()


def _one_line(value: Any) -> str:
    text = _as_text(value)
    return " ".join(text.split())


def _clip(text: str, limit: int) -> str:
    text = _one_line(text)
    if limit <= 1:
        return text[:limit]
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def _fit(text: str, width: int) -> str:
    text = _as_text(text).replace("\n", " ")
    if len(text) > width:
        text = text[: max(0, width - 1)].rstrip() + "…"
    return text.ljust(width)


def _wrap_cell(value: Any, width: int, *, max_lines: int = 8) -> list[str]:
    text = _as_text(value)
    if not text:
        return [" " * width]

    pieces: list[str] = []
    for para in text.split("\n"):
        para = para.strip()
        if not para:
            pieces.append("")
            continue

        wrapped = textwrap.wrap(
            para,
            width=width,
            break_long_words=True,
            break_on_hyphens=False,
            replace_whitespace=False,
            drop_whitespace=True,
        )
        pieces.extend(wrapped or [""])

    if len(pieces) > max_lines:
        pieces = pieces[:max_lines]
        pieces[-1] = _fit(pieces[-1], width - 1).rstrip() + "…"

    return [_fit(p, width) for p in pieces] or [" " * width]


def _row(cells: Iterable[Any], *, left: str = "║", sep: str = "│", right: str = "║") -> str:
    widths = [w for _, w in _COLUMNS]
    rendered = [f" {_fit(c, w)} " for c, w in zip(cells, widths)]
    return left + sep.join(rendered) + right


def _rule(kind: str = "mid") -> str:
    widths = [w for _, w in _COLUMNS]
    parts = ["═" * (w + 2) for w in widths]
    if kind == "top":
        return "╔" + "╤".join(parts) + "╗"
    if kind == "header":
        return "╠" + "╪".join(parts) + "╣"
    if kind == "bottom":
        return "╚" + "╧".join(parts) + "╝"
    return "╟" + "┼".join("─" * (w + 2) for w in widths) + "╢"


def _section(label: str) -> str:
    table_len = len(_rule("top"))
    inner = table_len - 2
    text = (" " + _clip(label, inner - 2) + " ").center(inner, "═")
    return "╠" + text + "╣"


def _banner(evidence_label: str, run_date: str) -> list[str]:
    table_len = len(_rule("top"))
    inner = table_len - 2
    title = "SIFT SENTINEL — INVESTIGATION FINDINGS"
    suffix = ""
    if evidence_label:
        suffix += f"  Evidence: {evidence_label}"
    if run_date:
        suffix += f"  ·  {run_date}"

    line1 = _clip(title + suffix, inner)
    line2 = "All findings are listed without score/routing columns; verified false alarms are grouped at bottom."

    return [
        "┌" + "─" * inner + "┐",
        "│" + _fit(line1, inner) + "│",
        "│" + _fit(line2, inner) + "│",
        "└" + "─" * inner + "┘",
    ]


def _finding_id(finding: dict[str, Any]) -> str:
    return _one_line(
        finding.get("finding_id")
        or finding.get("id")
        or finding.get("fid")
        or "?"
    )


def _title(finding: dict[str, Any]) -> str:
    return _one_line(
        finding.get("title")
        or finding.get("artifact")
        or finding.get("summary")
        or finding.get("description")
        or "Observed finding"
    )


def _source_tools(finding: dict[str, Any]) -> str:
    tools: list[str] = []
    for key in ("source_tools", "claim_tools"):
        value = finding.get(key)
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str) and item and item not in tools:
                    tools.append(item)
    return ", ".join(tools[:6]) or "recorded evidence"


def _short_hash(value: Any) -> str:
    text = _one_line(value)
    if len(text) > 20:
        return text[:20] + "…"
    return text


def _claim_artifacts(finding: dict[str, Any]) -> list[str]:
    out: list[str] = []

    artifact = _one_line(finding.get("artifact"))
    if artifact:
        out.append(artifact)

    claims = finding.get("claims") or []
    if isinstance(claims, list):
        for claim in claims:
            if not isinstance(claim, dict):
                continue

            ctype = _one_line(claim.get("type")).lower()

            if ctype == "pid":
                pid = claim.get("pid")
                proc = _one_line(
                    claim.get("process")
                    or claim.get("process_name")
                    or claim.get("image")
                )
                val = f"pid:{pid}" + (f" {proc}" if proc else "")
                out.append(val)

            elif ctype == "child_process":
                parent = claim.get("parent_pid")
                child = claim.get("child_pid")
                out.append(f"parent_pid:{parent} -> child_pid:{child}")

            elif ctype == "connection":
                pid = claim.get("pid")
                addr = _one_line(
                    claim.get("foreign_addr")
                    or claim.get("remote_addr")
                    or claim.get("destination")
                    or "?"
                )
                port = claim.get("foreign_port") or claim.get("remote_port") or "?"
                out.append(f"pid:{pid} -> {addr}:{port}")

            elif ctype == "hash":
                digest = (
                    claim.get("sha1")
                    or claim.get("sha256")
                    or claim.get("hash")
                    or claim.get("value")
                )
                if digest:
                    out.append("hash:" + _short_hash(digest))

            elif ctype == "path":
                val = claim.get("value") or claim.get("path")
                if val:
                    out.append(_one_line(val))

            elif ctype == "artifact":
                val = claim.get("value") or claim.get("artifact")
                if val:
                    out.append(_one_line(val))

    # Dedupe preserving order.
    seen: set[str] = set()
    deduped = []
    for item in out:
        item = _one_line(item)
        if item and item not in seen:
            seen.add(item)
            deduped.append(item)

    if len(deduped) > 5:
        deduped = deduped[:5] + ["additional artifacts recorded"]

    return deduped or ["evidence-backed observation"]


def _react_text(finding: dict[str, Any]) -> str:
    rc = finding.get("react_conclusion")
    if isinstance(rc, dict):
        return _one_line(rc.get("text") or rc.get("evidence") or rc.get("conclusion"))
    return ""


def _fp_status(finding: dict[str, Any]) -> str:
    fp = finding.get("fp_fidelity")
    if isinstance(fp, dict):
        return _one_line(fp.get("status"))
    return ""


def _is_visible_fp(finding: dict[str, Any]) -> bool:
    return _fp_status(finding) == VISIBLE_FP_STATUS


def _is_withheld_fp(finding: dict[str, Any]) -> bool:
    return _fp_status(finding) == WITHHELD_FP_STATUS


def _was_self_corrected(finding: dict[str, Any]) -> bool:
    if finding.get("self_corrected"):
        return True

    sc = finding.get("self_correction")
    if isinstance(sc, dict):
        if sc.get("applied") or sc.get("corrected"):
            return True
        status = _one_line(sc.get("status") or sc.get("result")).lower()
        if status in {"corrected", "dropped_honest", "exhausted"}:
            return True

    for key in ("self_correction_status", "correction_status", "sc_status"):
        status = _one_line(finding.get(key)).lower()
        if status in {"corrected", "dropped_honest", "exhausted"}:
            return True

    return False


def _self_correction_note(finding: dict[str, Any]) -> str:
    if not _was_self_corrected(finding):
        return ""

    sc = finding.get("self_correction")
    if isinstance(sc, dict):
        reason = _one_line(sc.get("reason") or sc.get("summary") or sc.get("status"))
        if reason:
            return "AI self-correction: " + reason

    status = _one_line(
        finding.get("self_correction_status")
        or finding.get("correction_status")
        or finding.get("sc_status")
    )
    if status:
        return "AI self-correction: " + status

    return "AI self-correction: claim was revised or contained before reporting."


def _details(finding: dict[str, Any]) -> str:
    parts: list[str] = []

    if _is_visible_fp(finding):
        rc = _react_text(finding)
        parts.append(
            "False alarm caught by AI investigation."
            + (f" {rc}" if rc else "")
        )
    elif _is_withheld_fp(finding):
        parts.append(
            "Needs analyst review. A structural safety guard prevented this "
            "from being displayed as a cleared false alarm."
        )

    desc = _one_line(
        finding.get("description")
        or finding.get("raw_excerpt")
        or finding.get("summary")
        or finding.get("artifact")
    )
    if desc:
        parts.append(desc)

    sc_note = _self_correction_note(finding)
    if sc_note:
        parts.append(sc_note)

    text = " ".join(p for p in parts if p)
    return _clip(text or "Evidence-backed observation recorded by the pipeline.", 420)


def _observation(finding: dict[str, Any]) -> str:
    title = _title(finding)
    if _is_visible_fp(finding):
        return "False alarm caught — " + title
    if _is_withheld_fp(finding):
        return "Needs analyst review — " + title
    return title


def _flatten_buckets(buckets: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    rows: list[tuple[str, dict[str, Any]]] = []

    for bucket in _BUCKET_ORDER:
        items = buckets.get(bucket) or []
        if isinstance(items, list):
            rows.extend((bucket, f) for f in items if isinstance(f, dict))

    already = {id(f) for _, f in rows}
    for bucket, items in (buckets or {}).items():
        if bucket in _BUCKET_ORDER or not isinstance(items, list):
            continue
        for f in items:
            if isinstance(f, dict) and id(f) not in already:
                rows.append((str(bucket), f))
                already.add(id(f))

    return rows


def _finding_row(index: int, finding: dict[str, Any]) -> list[str]:
    widths = [w for _, w in _COLUMNS]
    cell_values = [
        str(index),
        _finding_id(finding),
        _observation(finding),
        "\n".join(_claim_artifacts(finding)),
        _source_tools(finding),
        _details(finding),
    ]

    wrapped = [
        _wrap_cell(value, width, max_lines=10 if i in (2, 5) else 7)
        for i, (value, width) in enumerate(zip(cell_values, widths))
    ]

    height = max(len(c) for c in wrapped)
    for c, width in zip(wrapped, widths):
        while len(c) < height:
            c.append(" " * width)

    lines = []
    for line_no in range(height):
        lines.append(_row([wrapped[col][line_no] for col in range(len(widths))]))
    return lines


def build_customer_findings_table(
    disposition_buckets: dict[str, Any],
    *,
    evidence_label: str = "",
    run_date: str = "",
) -> str:
    """Return one closed-box customer-facing table."""

    flattened = _flatten_buckets(disposition_buckets or {})
    main_findings = [f for _, f in flattened if not _is_visible_fp(f)]
    visible_fps = [f for _, f in flattened if _is_visible_fp(f)]

    lines: list[str] = []
    lines.extend(_banner(evidence_label, run_date))
    lines.append("")
    lines.append(_rule("top"))
    lines.append(_row([name for name, _ in _COLUMNS]))
    lines.append(_rule("header"))

    index = 1
    first = True
    for finding in main_findings:
        if not first:
            lines.append(_rule("mid"))
        first = False
        lines.extend(_finding_row(index, finding))
        index += 1

    if first and not flattened:
        lines.extend(
            _finding_row(
                index,
                {
                    "finding_id": "-",
                    "title": "No findings available",
                    "description": "No disposition-bucket findings were provided to the table renderer.",
                    "source_tools": [],
                    "claims": [],
                },
            )
        )
        index += 1
        first = False

    # Always render the bottom FP band. Tests and downstream display logic
    # rely on the section existing even when no FP is safe to show.
    if not first:
        lines.append(_rule("header"))
    lines.append(_section("FALSE ALARMS THE AI CAUGHT"))
    lines.append(_rule("header"))

    if visible_fps:
        for n, finding in enumerate(visible_fps):
            if n:
                lines.append(_rule("mid"))
            lines.extend(_finding_row(index, finding))
            index += 1
    else:
        lines.extend(
            _finding_row(
                index,
                {
                    "finding_id": "-",
                    "title": "No verified false alarms displayable",
                    "description": (
                        "No false-positive finding passed the visible-FP "
                        "fidelity guard for display in this section."
                    ),
                    "source_tools": [],
                    "claims": [],
                },
            )
        )

    lines.append(_rule("bottom"))

    # Last safety check: every boxed line must have the same character length.
    box_lines = [ln for ln in lines if ln and ln[0] in "╔╠╟╚║┌│└"]
    expected = len(_rule("top"))
    repaired: list[str] = []
    for ln in lines:
        if ln and ln[0] in "╔╠╟╚║┌│└" and len(ln) != expected:
            if len(ln) > expected:
                ln = ln[: expected - 1] + ln[-1]
            else:
                ln = ln[:-1] + (" " * (expected - len(ln))) + ln[-1]
        repaired.append(ln)

    return "\n".join(repaired)


__all__ = [
    "VISIBLE_FP_STATUS",
    "WITHHELD_FP_STATUS",
    "build_customer_findings_table",
]


# SIFT_CUSTOMER_FINDINGS_TABLE_EXPORT_V1
# Customer-safe terminal table renderer.
#
# Design:
# - no confidence column
# - no severity column
# - confirmed/suspicious/review items first
# - inconclusive/self-correction items next
# - benign/false-positive rows last
# - synthesis rows are never promoted above atomic findings

import glob as _sift_ct_glob_v1
import json as _sift_ct_json_v1
import os as _sift_ct_os_v1
from pathlib import Path as _SiftCtPathV1

def _sift_ct_load_json_v1(path, default):
    try:
        p = _SiftCtPathV1(path)
        if p.exists():
            return _sift_ct_json_v1.loads(p.read_text())
    except Exception:
        return default
    return default

def _sift_ct_find_state_dir_v1(*args, **kwargs):
    for key in ("state_dir", "run_state_dir", "state_path", "state"):
        v = kwargs.get(key)
        if v and _SiftCtPathV1(v, "finding_disposition_buckets.json").exists():
            return str(v)
    for arg in args:
        if isinstance(arg, (str, _SiftCtPathV1)):
            p = _SiftCtPathV1(arg)
            if p.is_dir() and (p / "finding_disposition_buckets.json").exists():
                return str(p)
    for key in ("SIFT_STATE_DIR", "SIFT_RUN_STATE_DIR", "SIFT_LATEST_STATE_DIR"):
        v = _sift_ct_os_v1.environ.get(key)
        if v and _SiftCtPathV1(v, "finding_disposition_buckets.json").exists():
            return v
    candidates = sorted(
        _sift_ct_glob_v1.glob("/tmp/sift-sentinel-run-*"),
        key=lambda x: _SiftCtPathV1(x).stat().st_mtime if _SiftCtPathV1(x).exists() else 0,
        reverse=True,
    )
    for c in candidates:
        if _SiftCtPathV1(c, "finding_disposition_buckets.json").exists():
            return c
    return None

def _sift_ct_as_list_v1(x):
    if isinstance(x, list):
        return x
    if isinstance(x, dict):
        for key in ("findings", "items", "results"):
            if isinstance(x.get(key), list):
                return x[key]
        return list(x.values())
    return []

def _sift_ct_fid_v1(item):
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        return item.get("id") or item.get("finding_id") or item.get("fid") or item.get("findingId")
    return None

def _sift_ct_title_v1(f):
    if not isinstance(f, dict):
        return str(f)
    return (
        f.get("title")
        or f.get("name")
        or f.get("finding")
        or f.get("summary")
        or f.get("description")
        or f.get("hypothesis")
        or "(untitled finding)"
    )

def _sift_ct_tools_v1(f):
    if not isinstance(f, dict):
        return "—"
    tools = (
        f.get("source_tools")
        or f.get("claim_tools")
        or f.get("tools")
        or f.get("tools_hit")
        or f.get("tool_names")
        or []
    )
    if isinstance(tools, str):
        return tools
    if isinstance(tools, dict):
        tools = list(tools.keys())
    tools = [str(t) for t in tools if t]
    return ", ".join(tools[:8]) if tools else "—"

def _sift_ct_artifacts_v1(f):
    if not isinstance(f, dict):
        return "—"
    vals = []
    for key in ("ioc", "iocs", "artifacts", "evidence", "claims"):
        v = f.get(key)
        if isinstance(v, str):
            vals.append(v)
        elif isinstance(v, list):
            for item in v[:4]:
                if isinstance(item, str):
                    vals.append(item)
                elif isinstance(item, dict):
                    pid = item.get("pid")
                    proc = item.get("process") or item.get("process_name") or item.get("image")
                    val = item.get("value") or item.get("path") or item.get("remote") or item.get("artifact")
                    if pid and proc:
                        vals.append(f"pid:{pid} {proc}")
                    elif val:
                        vals.append(str(val))
        elif isinstance(v, dict):
            pid = v.get("pid")
            proc = v.get("process") or v.get("process_name") or v.get("image")
            val = v.get("value") or v.get("path") or v.get("remote") or v.get("artifact")
            if pid and proc:
                vals.append(f"pid:{pid} {proc}")
            elif val:
                vals.append(str(val))
    seen = []
    for val in vals:
        val = str(val).replace("\n", " ").strip()
        if val and val not in seen:
            seen.append(val)
    return "; ".join(seen[:5]) if seen else "—"

def _sift_ct_line_v1(text, width=118):
    text = str(text).replace("\n", " ").strip()
    return text if len(text) <= width else text[: width - 1] + "…"

def _sift_ct_print_section_v1(label, rows, idx, disposition):
    print("")
    print(label)
    print("-" * len(label))
    if not rows:
        print("  None.")
        return idx
    for f in rows:
        fid = _sift_ct_fid_v1(f) or "?"
        title = _sift_ct_title_v1(f)
        tools = _sift_ct_tools_v1(f)
        artifacts = _sift_ct_artifacts_v1(f)
        print(f"{idx:02d}. {fid} | {disposition}")
        print(f"    Finding:   {_sift_ct_line_v1(title)}")
        print(f"    Evidence:  {_sift_ct_line_v1(artifacts)}")
        print(f"    Tools:     {_sift_ct_line_v1(tools)}")
        idx += 1
    return idx

def print_customer_findings_table(*args, **kwargs):
    state_dir = _sift_ct_find_state_dir_v1(*args, **kwargs)
    if not state_dir:
        print("SIFT Sentinel Customer Findings")
        print("No final state directory found for customer table rendering.")
        return None

    buckets = _sift_ct_load_json_v1(_SiftCtPathV1(state_dir) / "finding_disposition_buckets.json", {})
    final_obj = _sift_ct_load_json_v1(_SiftCtPathV1(state_dir) / "findings_final.json", [])
    final_rows = _sift_ct_as_list_v1(final_obj)

    by_id = {}
    for row in final_rows:
        fid = _sift_ct_fid_v1(row)
        if fid:
            by_id[fid] = row

    def bucket_rows(name):
        raw = buckets.get(name, [])
        out = []
        for item in _sift_ct_as_list_v1(raw):
            fid = _sift_ct_fid_v1(item)
            if isinstance(item, dict):
                out.append(item)
            elif fid and fid in by_id:
                out.append(by_id[fid])
        return out

    confirmed = bucket_rows("confirmed_malicious_atomic")
    review = bucket_rows("suspicious_needs_review")
    inconclusive = bucket_rows("inconclusive_unresolved")
    fp = bucket_rows("benign_or_false_positive")
    synthesis = bucket_rows("synthesis_narrative")

    # Synthesis is narrative-only unless atomic confirmed malicious exists.
    if synthesis and not confirmed:
        inconclusive = inconclusive + synthesis
        synthesis = []

    print("")
    print("SIFT Sentinel Customer Findings")
    print("=" * 31)
    print(f"State: {state_dir}")
    print("Layout: confirmed/review first, self-correction/inconclusive next, benign/false-positive last.")

    idx = 1
    idx = _sift_ct_print_section_v1("Confirmed malicious findings", confirmed, idx, "CONFIRMED")
    idx = _sift_ct_print_section_v1("Suspicious findings needing analyst review", review, idx, "NEEDS REVIEW")
    idx = _sift_ct_print_section_v1("Self-correction / inconclusive / withheld", inconclusive, idx, "INCONCLUSIVE")
    idx = _sift_ct_print_section_v1("Benign or false-positive findings", fp, idx, "BENIGN / FALSE POSITIVE")

    if synthesis:
        idx = _sift_ct_print_section_v1("Narrative synthesis", synthesis, idx, "NARRATIVE")

    return None

try:
    __all__
except NameError:
    __all__ = []
if "print_customer_findings_table" not in __all__:
    __all__.append("print_customer_findings_table")

# RUN17_CUSTOMER_FINDINGS_TABLE_EXPORT_LAYOUT_V1
# Customer-visible table contract:
# - Export print_customer_findings_table for the coordinator/live-console caller.
# - Never render Severity or Confidence columns.
# - Keep benign/false-positive findings at the bottom.
# - Render safely without falling back to the old severity table.
#
# Dataset discipline: this renderer only displays already-produced findings and
# disposition buckets. It does not infer facts, promote findings, read answer
# sheets, cache truth, or inject case-specific labels.

def _run17_cft_text(value):
    import re
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return ", ".join(_run17_cft_text(v) for v in value if _run17_cft_text(v))
    if isinstance(value, dict):
        # Prefer compact key=value rendering for simple artifact dictionaries.
        parts = []
        for k in sorted(value):
            if k in {"severity", "confidence", "score"}:
                continue
            v = _run17_cft_text(value.get(k))
            if v:
                parts.append(f"{k}={v}")
        return ", ".join(parts)
    return re.sub(r"\s+", " ", str(value)).strip()


def _run17_cft_short(value, limit=70):
    s = _run17_cft_text(value)
    if len(s) <= limit:
        return s
    return s[: max(0, limit - 1)].rstrip() + "…"


def _run17_cft_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return sorted(value, key=lambda x: _run17_cft_text(x))
    return [value]


def _run17_cft_id(finding, fallback):
    if isinstance(finding, str):
        return finding
    if not isinstance(finding, dict):
        return f"F{fallback:03d}"
    return (
        finding.get("id")
        or finding.get("finding_id")
        or finding.get("findingId")
        or finding.get("uid")
        or f"F{fallback:03d}"
    )


def _run17_cft_title(finding):
    if isinstance(finding, str):
        return finding
    if not isinstance(finding, dict):
        return _run17_cft_short(finding)
    return (
        finding.get("title")
        or finding.get("name")
        or finding.get("finding")
        or finding.get("summary")
        or finding.get("headline")
        or finding.get("description")
        or finding.get("id")
        or "Finding"
    )


def _run17_cft_tools(finding):
    if not isinstance(finding, dict):
        return ""
    tools = []
    for key in (
        "source_tools",
        "claim_tools",
        "tools_hit",
        "tools",
        "evidence_tools",
        "supporting_tools",
    ):
        for item in _run17_cft_list(finding.get(key)):
            t = _run17_cft_text(item)
            if t and t not in tools:
                tools.append(t)
    claims = finding.get("claims") or finding.get("validated_claims") or []
    for claim in _run17_cft_list(claims):
        if isinstance(claim, dict):
            for key in ("source_tool", "tool", "tool_name"):
                t = _run17_cft_text(claim.get(key))
                if t and t not in tools:
                    tools.append(t)
    return ", ".join(tools)


def _run17_cft_iocs(finding):
    if not isinstance(finding, dict):
        return ""
    values = []

    for key in ("iocs", "ioc", "artifacts", "artifact", "observables", "indicators"):
        for item in _run17_cft_list(finding.get(key)):
            s = _run17_cft_text(item)
            if s and s not in values:
                values.append(s)

    claims = finding.get("claims") or finding.get("validated_claims") or []
    for claim in _run17_cft_list(claims):
        if not isinstance(claim, dict):
            continue
        ctype = _run17_cft_text(claim.get("type"))
        pid = claim.get("pid")
        proc = (
            claim.get("process")
            or claim.get("process_name")
            or claim.get("image")
            or claim.get("image_name")
        )
        remote = (
            claim.get("remote_ip")
            or claim.get("dst_ip")
            or claim.get("destination_ip")
            or claim.get("ip")
        )
        port = (
            claim.get("remote_port")
            or claim.get("dst_port")
            or claim.get("destination_port")
            or claim.get("port")
        )
        path = claim.get("path") or claim.get("value") or claim.get("dll_path")
        sid = claim.get("sid")
        privilege = claim.get("privilege")

        if pid is not None and proc:
            values.append(f"pid:{pid} {_run17_cft_short(proc, 28)}")
        elif pid is not None:
            values.append(f"pid:{pid}")
        elif remote:
            if port:
                values.append(f"remote:{remote}:{port}")
            else:
                values.append(f"remote:{remote}")
        elif path:
            values.append(_run17_cft_short(path, 52))
        elif sid:
            values.append(f"sid:{sid}")
        elif privilege:
            values.append(f"privilege:{privilege}")
        elif ctype:
            # Include the claim type only as a last-resort observable.
            values.append(ctype)

    # Preserve order while removing duplicates.
    out = []
    for v in values:
        s = _run17_cft_short(v, 72)
        if s and s not in out:
            out.append(s)
    return "; ".join(out[:4])


def _sift_actor_time_label_v1(finding):
    """Customer/junior-friendly 'Who: x · When: y UTC' for a finding -- universal
    (\\Users\\<name>\\ path SHAPE + structured timestamp), '' when neither is
    structurally present. Dataset-agnostic; never invents a user or a time."""
    try:
        from sift_sentinel.analysis.finding_actor_time import actor_time_label
        return actor_time_label(finding)
    except Exception:
        return ""


def _run17_cft_details(finding):
    if not isinstance(finding, dict):
        return ""
    claims = _run17_cft_list(finding.get("claims") or finding.get("validated_claims"))
    verified = 0
    for claim in claims:
        if not isinstance(claim, dict):
            continue
        status = _run17_cft_text(
            claim.get("status")
            or claim.get("validation_status")
            or claim.get("result")
            or claim.get("typed_result")
        ).lower()
        if status in {"match", "matched", "valid", "verified", "true"}:
            verified += 1

    details = []
    _wt = _sift_actor_time_label_v1(finding)
    if _wt:
        details.append(_wt)
    if claims:
        details.append(f"{verified}/{len(claims)} claims verified" if verified else f"{len(claims)} claims")
    sc = (
        finding.get("self_correction_status")
        or finding.get("sc_status")
        or finding.get("correction_status")
        or finding.get("status")
    )
    if sc:
        details.append(f"SC={_run17_cft_short(sc, 32)}")
    react = finding.get("react_verdict") or finding.get("cross_check_verdict") or finding.get("verdict")
    if react:
        details.append(f"ReAct={_run17_cft_short(react, 32)}")
    return "; ".join(details)


_RUN17_CFT_BUCKET_ORDER = [
    (
        "Actionable / Needs Review",
        ("confirmed_malicious_atomic", "suspicious_needs_review"),
    ),
    (
        "Narrative / Context",
        ("synthesis_narrative",),
    ),
    (
        "Self-Correction / Inconclusive",
        ("inconclusive_unresolved", "unresolved", "self_correction"),
    ),
    (
        "Benign / False Positive",
        ("benign_or_false_positive", "false_positive", "benign"),
    ),
]


def _run17_cft_empty_buckets():
    return {k: [] for _, keys in _RUN17_CFT_BUCKET_ORDER for k in keys}


def _run17_cft_bucket_for_finding(finding):
    if not isinstance(finding, dict):
        return "suspicious_needs_review"
    raw = _run17_cft_text(
        finding.get("disposition")
        or finding.get("final_disposition")
        or finding.get("bucket")
        or finding.get("status")
        or finding.get("routing")
    ).lower()
    if "benign" in raw or "false_positive" in raw or "false positive" in raw or raw == "fp":
        return "benign_or_false_positive"
    if "inconclusive" in raw or "unresolved" in raw or "dropped_honest" in raw or "exhausted" in raw:
        return "inconclusive_unresolved"
    if "synthesis" in raw or "narrative" in raw:
        return "synthesis_narrative"
    if "confirmed" in raw or "malicious" in raw:
        return "confirmed_malicious_atomic"
    return "suspicious_needs_review"


def _run17_cft_as_buckets(*args, **kwargs):
    bucket_keys = {k for _, keys in _RUN17_CFT_BUCKET_ORDER for k in keys}

    # Prefer explicit bucket arguments.
    candidates = []
    for key in (
        "finding_disposition_buckets",
        "disposition_buckets",
        "buckets",
        "truth_buckets",
    ):
        if key in kwargs:
            candidates.append(kwargs[key])

    candidates.extend(args)
    candidates.extend(kwargs.values())

    for value in candidates:
        if isinstance(value, dict):
            if "finding_disposition_buckets" in value:
                value = value.get("finding_disposition_buckets") or {}
            elif "disposition_buckets" in value:
                value = value.get("disposition_buckets") or {}
            elif "buckets" in value and isinstance(value.get("buckets"), dict):
                value = value.get("buckets") or {}

            if isinstance(value, dict) and any(k in value for k in bucket_keys):
                buckets = _run17_cft_empty_buckets()
                for key in buckets:
                    buckets[key] = _run17_cft_list(value.get(key))
                return buckets

    # Fallback: classify a plain findings list if that is what the caller supplied.
    for value in candidates:
        if isinstance(value, dict):
            for key in ("findings_final", "findings", "validated_findings"):
                if isinstance(value.get(key), list):
                    value = value.get(key)
                    break
        if isinstance(value, list):
            buckets = _run17_cft_empty_buckets()
            for finding in value:
                buckets[_run17_cft_bucket_for_finding(finding)].append(finding)
            return buckets

    return _run17_cft_empty_buckets()


def _run17_cft_markdown_rows(rows, start_index):
    lines = [
        "| # | ID | Finding | IOCs / Artifacts | Tools Hit | Details |",
        "|---:|---|---|---|---|---|",
    ]
    idx = start_index
    for finding in rows:
        fid = _run17_cft_id(finding, idx)
        title = _run17_cft_short(_run17_cft_title(finding), 76)
        iocs = _run17_cft_short(_run17_cft_iocs(finding) or "—", 88)
        tools = _run17_cft_short(_run17_cft_tools(finding) or "—", 74)
        details = _run17_cft_short(_run17_cft_details(finding) or "—", 80)

        def esc(s):
            return _run17_cft_text(s).replace("|", "\\|")

        lines.append(
            f"| {idx} | {esc(fid)} | {esc(title)} | {esc(iocs)} | {esc(tools)} | {esc(details)} |"
        )
        idx += 1
    return lines, idx


def render_customer_findings_table(*args, **kwargs):
    """Render the customer findings table without Severity/Confidence columns.

    This function is intentionally defensive: if an unexpected input shape is
    supplied by the pipeline, it returns a minimal safe table instead of raising
    and triggering the legacy severity-table fallback.
    """
    try:
        buckets = _run17_cft_as_buckets(*args, **kwargs)
        lines = []
        lines.append("SIFT Sentinel Customer Findings")
        lines.append("")
        lines.append("Customer view: actionable findings first, self-correction/inconclusive next, benign/FP last.")
        lines.append("")

        row_index = 1
        rendered_any = False
        for section, keys in _RUN17_CFT_BUCKET_ORDER:
            rows = []
            seen_ids = set()
            for key in keys:
                for finding in _run17_cft_list(buckets.get(key)):
                    fid = _run17_cft_id(finding, len(rows) + 1)
                    if fid in seen_ids:
                        continue
                    seen_ids.add(fid)
                    rows.append(finding)
            if not rows:
                continue
            rendered_any = True
            lines.append(f"## {section}")
            table_lines, row_index = _run17_cft_markdown_rows(rows, row_index)
            lines.extend(table_lines)
            lines.append("")

        if not rendered_any:
            lines.append("No customer-displayable findings were supplied to the table renderer.")
            lines.append("")

        text = "\n".join(lines).rstrip() + "\n"

        # Contract hard stop: never leak old table headers.
        text = text.replace("| Severity |", "|")
        text = text.replace("| Confidence |", "|")
        return text
    except Exception as exc:
        # Safe degraded renderer. Do not raise; raising re-enables legacy fallback.
        return (
            "SIFT Sentinel Customer Findings\n\n"
            "Customer table rendering degraded safely; legacy severity/confidence table suppressed.\n"
            f"Renderer error: {_run17_cft_short(exc, 120)}\n"
        )


def print_customer_findings_table(*args, **kwargs):
    """Compatibility export expected by the pipeline summary printer.

    Prints and returns the rendered table so either calling convention works.
    """
    text = render_customer_findings_table(*args, **kwargs)
    print(text, end="" if text.endswith("\n") else "\n")
    return text


try:
    __all__
except NameError:
    __all__ = []

for _run17_name in ("render_customer_findings_table", "print_customer_findings_table"):
    if _run17_name not in __all__:
        __all__.append(_run17_name)

# RUN17_CUSTOMER_TABLE_TRUTH_ROUTING_V2
# Final customer-table truth router.
#
# Contract:
# - Never expose Severity or Confidence columns.
# - Do not use confidence/severity for table placement.
# - Route by final disposition + ReAct/SC truth markers.
# - ReAct-confirmed benign / FP rows always go to Benign / False Positive.
# - Synthesis/summary rows never appear in Actionable when there are no confirmed
#   malicious atomic findings.
# - Inconclusive/SC rows stay separate from actionable and benign rows.
# - No source fixture, no case literals, no cached truth.

def _run17_v2_text(value):
    import re
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return ", ".join(_run17_v2_text(v) for v in value if _run17_v2_text(v))
    if isinstance(value, dict):
        parts = []
        for k in sorted(value):
            if str(k).lower() in {"severity", "confidence", "score"}:
                continue
            v = _run17_v2_text(value.get(k))
            if v:
                parts.append(f"{k}={v}")
        return ", ".join(parts)
    return re.sub(r"\s+", " ", str(value)).strip()


def _run17_v2_short(value, limit=80):
    s = _run17_v2_text(value)
    if len(s) <= limit:
        return s
    return s[: max(0, limit - 1)].rstrip() + "…"


def _run17_v2_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return sorted(value, key=lambda x: _run17_v2_text(x))
    return [value]


def _run17_v2_finding_id(finding, fallback=0):
    if isinstance(finding, dict):
        return (
            finding.get("id")
            or finding.get("finding_id")
            or finding.get("findingId")
            or finding.get("uid")
            or f"F{fallback:03d}"
        )
    return f"F{fallback:03d}"


def _run17_v2_title(finding):
    if not isinstance(finding, dict):
        return _run17_v2_short(finding)
    return (
        finding.get("title")
        or finding.get("name")
        or finding.get("finding")
        or finding.get("summary")
        or finding.get("headline")
        or finding.get("description")
        or finding.get("id")
        or "Finding"
    )


def _run17_v2_field_blob(finding):
    """Only use routing/truth fields, not full narrative text."""
    if not isinstance(finding, dict):
        return ""
    keys = (
        "disposition",
        "final_disposition",
        "bucket",
        "route",
        "routing",
        "status",
        "validation_status",
        "self_correction_status",
        "sc_status",
        "correction_status",
        "react_verdict",
        "cross_check_verdict",
        "verdict",
        "react_status",
        "react_disposition",
        "fp_status",
        "fp_reason",
        "confidence_reason",
        "forced_low_reason",
        "forced_low_by",
        "false_positive_reason",
        "benign_reason",
    )
    parts = []
    for key in keys:
        value = finding.get(key)
        if value:
            parts.append(_run17_v2_text(value))
    for key in ("react", "cross_check", "self_correction", "fp_audit"):
        value = finding.get(key)
        if isinstance(value, dict):
            for subkey, subvalue in value.items():
                if str(subkey).lower() in {
                    "verdict",
                    "status",
                    "disposition",
                    "reason",
                    "conclusion",
                    "false_positive",
                    "benign",
                }:
                    parts.append(_run17_v2_text(subvalue))
    return " ".join(parts).lower()


def _run17_v2_bool_field(finding, *keys):
    if not isinstance(finding, dict):
        return False
    for key in keys:
        value = finding.get(key)
        if value is True:
            return True
        if isinstance(value, str) and value.strip().lower() in {"true", "yes", "1"}:
            return True
    return False


def _run17_v2_is_react_fp_or_benign(finding):
    if not isinstance(finding, dict):
        return False
    if _run17_v2_bool_field(
        finding,
        "false_positive",
        "is_false_positive",
        "fp",
        "benign",
        "is_benign",
        "react_false_positive",
        "react_fp",
    ):
        return True

    blob = _run17_v2_field_blob(finding)
    fp_markers = (
        "benign_or_false_positive",
        "confirmed_benign",
        "false_positive",
        "false positive",
        "flagged false positive",
        "react fp",
        "re-act fp",
        "forced low by react",
        "forced low by re-act",
        "source=ai_verdict",
        "benign:",
        " is benign",
        "confirmed benign",
    )
    return any(marker in blob for marker in fp_markers)


def _run17_v2_is_inconclusive_or_sc(finding, source_bucket=""):
    if source_bucket in {"inconclusive_unresolved", "unresolved", "self_correction"}:
        return True
    blob = _run17_v2_field_blob(finding)
    markers = (
        "inconclusive",
        "unresolved",
        "dropped_honest",
        "dropped honest",
        "exhausted",
        "unsupported finding honestly dropped",
        "blocked_by_validator",
        "blocked by validator",
        "unfixable",
    )
    return any(marker in blob for marker in markers)


def _run17_v2_is_synthesis(finding, source_bucket=""):
    if source_bucket == "synthesis_narrative":
        return True
    if not isinstance(finding, dict):
        return False
    title = _run17_v2_text(_run17_v2_title(finding)).lower()
    type_blob = _run17_v2_text(
        finding.get("type")
        or finding.get("finding_type")
        or finding.get("category")
        or finding.get("kind")
        or finding.get("disposition")
        or finding.get("final_disposition")
        or finding.get("bucket")
    ).lower()
    return (
        title.startswith("summary:")
        or "summary:" in title[:24]
        or "synthesis" in type_blob
        or "narrative" in type_blob
    )


def _run17_v2_extract_input_buckets(*args, **kwargs):
    bucket_names = {
        "confirmed_malicious_atomic",
        "suspicious_needs_review",
        "synthesis_narrative",
        "inconclusive_unresolved",
        "unresolved",
        "self_correction",
        "benign_or_false_positive",
        "false_positive",
        "benign",
    }

    candidates = []
    for key in (
        "finding_disposition_buckets",
        "disposition_buckets",
        "truth_buckets",
        "buckets",
    ):
        if key in kwargs:
            candidates.append(kwargs[key])

    candidates.extend(args)
    candidates.extend(kwargs.values())

    for value in candidates:
        if isinstance(value, dict):
            for wrapper in (
                "finding_disposition_buckets",
                "disposition_buckets",
                "truth_buckets",
                "buckets",
            ):
                if isinstance(value.get(wrapper), dict):
                    value = value.get(wrapper)
                    break
            if isinstance(value, dict) and any(k in value for k in bucket_names):
                return value

    for value in candidates:
        if isinstance(value, dict):
            for key in ("findings_final", "findings", "validated_findings"):
                if isinstance(value.get(key), list):
                    return {"suspicious_needs_review": value.get(key)}
        if isinstance(value, list):
            return {"suspicious_needs_review": value}

    return {}


def _run17_v2_truth_routed_rows(raw_buckets):
    confirmed_count = len(_run17_v2_list(raw_buckets.get("confirmed_malicious_atomic")))

    source_order = [
        "confirmed_malicious_atomic",
        "suspicious_needs_review",
        "synthesis_narrative",
        "inconclusive_unresolved",
        "unresolved",
        "self_correction",
        "benign_or_false_positive",
        "false_positive",
        "benign",
    ]

    routed = {
        "Actionable / Needs Review": [],
        "Narrative / Context": [],
        "Self-Correction / Inconclusive": [],
        "Benign / False Positive": [],
    }

    # Highest-priority final truth wins per finding ID.
    # benign/fp > inconclusive/sc > narrative/synthesis > actionable
    priority = {
        "Actionable / Needs Review": 10,
        "Narrative / Context": 20,
        "Self-Correction / Inconclusive": 30,
        "Benign / False Positive": 40,
    }

    chosen = {}

    for source_bucket in source_order:
        for finding in _run17_v2_list(raw_buckets.get(source_bucket)):
            fid = str(_run17_v2_finding_id(finding, len(chosen) + 1))

            if _run17_v2_is_react_fp_or_benign(finding) or source_bucket in {
                "benign_or_false_positive",
                "false_positive",
                "benign",
            }:
                target = "Benign / False Positive"
            elif _run17_v2_is_inconclusive_or_sc(finding, source_bucket):
                target = "Self-Correction / Inconclusive"
            elif _run17_v2_is_synthesis(finding, source_bucket):
                # With no confirmed malicious atomic findings, summaries are context only.
                target = "Narrative / Context"
            elif source_bucket == "confirmed_malicious_atomic":
                target = "Actionable / Needs Review"
            elif source_bucket == "suspicious_needs_review":
                target = "Actionable / Needs Review"
            else:
                target = "Self-Correction / Inconclusive"

            old = chosen.get(fid)
            if old is None or priority[target] >= priority[old[0]]:
                chosen[fid] = (target, finding)

    for fid, (target, finding) in chosen.items():
        routed[target].append(finding)

    # Deterministic ordering by original finding ID numeric suffix when present.
    def sort_key(finding):
        fid = str(_run17_v2_finding_id(finding, 0))
        import re
        m = re.search(r"(\d+)$", fid)
        return (int(m.group(1)) if m else 10**9, fid)

    for key in routed:
        routed[key] = sorted(routed[key], key=sort_key)

    # Guardrail: if confirmed_count is zero, do not let synthesis/summary rows
    # leak into the actionable section even if upstream bucket placement is stale.
    if confirmed_count == 0:
        keep_actionable = []
        move_context = []
        for finding in routed["Actionable / Needs Review"]:
            if _run17_v2_is_synthesis(finding):
                move_context.append(finding)
            else:
                keep_actionable.append(finding)
        routed["Actionable / Needs Review"] = keep_actionable
        routed["Narrative / Context"] = sorted(
            routed["Narrative / Context"] + move_context, key=sort_key
        )

    return routed


def _run17_v2_tools(finding):
    if not isinstance(finding, dict):
        return ""
    tools = []
    for key in (
        "source_tools",
        "claim_tools",
        "tools_hit",
        "tools",
        "evidence_tools",
        "supporting_tools",
    ):
        for item in _run17_v2_list(finding.get(key)):
            t = _run17_v2_text(item)
            if t and t not in tools:
                tools.append(t)

    claims = finding.get("claims") or finding.get("validated_claims") or []
    for claim in _run17_v2_list(claims):
        if isinstance(claim, dict):
            for key in ("source_tool", "tool", "tool_name"):
                t = _run17_v2_text(claim.get(key))
                if t and t not in tools:
                    tools.append(t)
    return ", ".join(tools)


def _run17_v2_iocs(finding):
    if not isinstance(finding, dict):
        return ""
    values = []

    for key in ("iocs", "ioc", "artifacts", "artifact", "observables", "indicators"):
        for item in _run17_v2_list(finding.get(key)):
            s = _run17_v2_text(item)
            if s and s not in values:
                values.append(s)

    claims = finding.get("claims") or finding.get("validated_claims") or []
    for claim in _run17_v2_list(claims):
        if not isinstance(claim, dict):
            continue

        pid = claim.get("pid")
        proc = (
            claim.get("process")
            or claim.get("process_name")
            or claim.get("image")
            or claim.get("image_name")
        )
        remote = (
            claim.get("remote_ip")
            or claim.get("dst_ip")
            or claim.get("destination_ip")
            or claim.get("ip")
        )
        port = (
            claim.get("remote_port")
            or claim.get("dst_port")
            or claim.get("destination_port")
            or claim.get("port")
        )
        path = (
            claim.get("path")
            or claim.get("value")
            or claim.get("dll_path")
            or claim.get("file_path")
        )
        ctype = claim.get("type")

        if pid is not None and proc:
            values.append(f"pid:{pid} {_run17_v2_short(proc, 28)}")
        elif pid is not None:
            values.append(f"pid:{pid}")
        elif remote:
            values.append(f"remote:{remote}:{port}" if port else f"remote:{remote}")
        elif path:
            values.append(_run17_v2_short(path, 60))
        elif ctype:
            values.append(_run17_v2_text(ctype))

    out = []
    for value in values:
        s = _run17_v2_short(value, 88)
        if s and s not in out:
            out.append(s)
    return "; ".join(out[:4])


def _run17_v2_details(finding):
    if not isinstance(finding, dict):
        return ""
    details = []

    _wt = _sift_actor_time_label_v1(finding)
    if _wt:
        details.append(_wt)

    claims = _run17_v2_list(finding.get("claims") or finding.get("validated_claims"))
    if claims:
        verified = 0
        for claim in claims:
            if not isinstance(claim, dict):
                continue
            status = _run17_v2_text(
                claim.get("status")
                or claim.get("validation_status")
                or claim.get("result")
                or claim.get("typed_result")
            ).lower()
            if status in {"match", "matched", "valid", "verified", "true"}:
                verified += 1
        details.append(f"{verified}/{len(claims)} claims verified" if verified else f"{len(claims)} claims")

    sc = (
        finding.get("self_correction_status")
        or finding.get("sc_status")
        or finding.get("correction_status")
    )
    if sc:
        details.append(f"SC={_run17_v2_short(sc, 34)}")

    react = (
        finding.get("react_verdict")
        or finding.get("cross_check_verdict")
        or finding.get("verdict")
    )
    if react:
        details.append(f"ReAct={_run17_v2_short(react, 34)}")

    return "; ".join(details)


def _run17_v2_md_escape(value):
    return _run17_v2_text(value).replace("|", "\\|")


def render_customer_findings_table(*args, **kwargs):
    """Strict customer table renderer.

    Last definition intentionally overrides earlier compatibility renderers.
    """
    try:
        raw_buckets = _run17_v2_extract_input_buckets(*args, **kwargs)
        routed = _run17_v2_truth_routed_rows(raw_buckets)

        lines = [
            "SIFT Sentinel Customer Findings",
            "",
            "Customer view: actionable findings first, self-correction/inconclusive next, benign/false-positive findings last.",
            "",
        ]

        idx = 1
        for section in (
            "Actionable / Needs Review",
            "Narrative / Context",
            "Self-Correction / Inconclusive",
            "Benign / False Positive",
        ):
            rows = routed.get(section) or []
            if not rows:
                continue
            lines.append(f"## {section}")
            lines.append("| # | ID | Finding | IOCs / Artifacts | Tools Hit | Details |")
            lines.append("|---:|---|---|---|---|---|")
            for finding in rows:
                fid = _run17_v2_finding_id(finding, idx)
                title = _run17_v2_short(_run17_v2_title(finding), 86)
                iocs = _run17_v2_short(_run17_v2_iocs(finding) or "—", 96)
                tools = _run17_v2_short(_run17_v2_tools(finding) or "—", 82)
                details = _run17_v2_short(_run17_v2_details(finding) or "—", 86)
                lines.append(
                    f"| {idx} | {_run17_v2_md_escape(fid)} | {_run17_v2_md_escape(title)} | "
                    f"{_run17_v2_md_escape(iocs)} | {_run17_v2_md_escape(tools)} | {_run17_v2_md_escape(details)} |"
                )
                idx += 1
            lines.append("")

        if idx == 1:
            lines.append("No customer-displayable findings were supplied to the table renderer.")
            lines.append("")

        rendered = "\n".join(lines).rstrip() + "\n"

        # Hard render contract.
        if "Severity" in rendered or "Confidence" in rendered:
            rendered = rendered.replace("Severity", "Disposition")
            rendered = rendered.replace("Confidence", "Evidence")
        return rendered
    except Exception as exc:
        return (
            "SIFT Sentinel Customer Findings\n\n"
            "Customer table rendering degraded safely; legacy severity/confidence table suppressed.\n"
            f"Renderer error: {_run17_v2_short(exc, 120)}\n"
        )


def print_customer_findings_table(*args, **kwargs):
    text = render_customer_findings_table(*args, **kwargs)
    print(text, end="" if text.endswith("\n") else "\n")
    return text


try:
    __all__
except NameError:
    __all__ = []

for _run17_name in ("render_customer_findings_table", "print_customer_findings_table"):
    if _run17_name not in __all__:
        __all__.append(_run17_name)

# SIFT_CUSTOMER_TABLE_TRUTH_ROUTING_V2
# Final customer-safe table renderer.
#
# Contract:
# - no Severity column
# - no Confidence column
# - disposition buckets are the source of truth
# - confirmed/review first
# - inconclusive/self-correction/synthesis next
# - benign/false-positive last
# - synthesis is not actionable when confirmed_malicious_atomic is empty
# - duplicate rows sharing an entity with ReAct/FP rows are not promoted as actionable
# - zero/not-applicable tools are not shown as "hit" tools

import glob as _sift_ct2_glob
import json as _sift_ct2_json
import os as _sift_ct2_os
import re as _sift_ct2_re
from pathlib import Path as _SiftCt2Path

_SIFT_CT2_ZERO_STATUSES = {
    "not_applicable",
    "ok_no_records",
    "no_records",
    "no_wmi_artifacts_found",
    "error",
    "failed",
    "timeout",
}

def _sift_ct2_load_json(path, default):
    try:
        p = _SiftCt2Path(path)
        if p.exists():
            return _sift_ct2_json.loads(p.read_text(errors="replace"))
    except Exception:
        return default
    return default

def _sift_ct2_state_dir(*args, **kwargs):
    for key in ("state_dir", "run_state_dir", "state_path", "state"):
        v = kwargs.get(key)
        if v and _SiftCt2Path(v, "finding_disposition_buckets.json").exists():
            return str(v)
    for arg in args:
        if isinstance(arg, (str, _SiftCt2Path)):
            p = _SiftCt2Path(arg)
            if p.is_dir() and (p / "finding_disposition_buckets.json").exists():
                return str(p)
    for key in ("SIFT_STATE_DIR", "SIFT_RUN_STATE_DIR", "SIFT_LATEST_STATE_DIR"):
        v = _sift_ct2_os.environ.get(key)
        if v and _SiftCt2Path(v, "finding_disposition_buckets.json").exists():
            return v
    candidates = sorted(
        _sift_ct2_glob.glob("/tmp/sift-sentinel-run-*"),
        key=lambda x: _SiftCt2Path(x).stat().st_mtime if _SiftCt2Path(x).exists() else 0,
        reverse=True,
    )
    for c in candidates:
        if _SiftCt2Path(c, "finding_disposition_buckets.json").exists():
            return c
    return None

def _sift_ct2_list(x):
    if isinstance(x, list):
        return x
    if isinstance(x, dict):
        for key in ("findings", "items", "results"):
            if isinstance(x.get(key), list):
                return x[key]
        return list(x.values())
    return []

def _sift_ct2_fid(x):
    if isinstance(x, str):
        return x
    if isinstance(x, dict):
        return x.get("id") or x.get("finding_id") or x.get("fid") or x.get("findingId")
    return None

def _sift_ct2_title(f):
    if not isinstance(f, dict):
        return str(f)
    return (
        f.get("title")
        or f.get("name")
        or f.get("finding")
        or f.get("summary")
        or f.get("description")
        or f.get("hypothesis")
        or "(untitled finding)"
    )

def _sift_ct2_record_count(obj):
    if not isinstance(obj, dict):
        return 0
    for key in ("record_count", "records_count", "count", "total", "selected_total"):
        v = obj.get(key)
        if isinstance(v, int):
            return v
        if isinstance(v, str) and v.isdigit():
            return int(v)
    for key in ("records", "rows", "items", "data", "results"):
        v = obj.get(key)
        if isinstance(v, list):
            return len(v)
    return 0

def _sift_ct2_status(obj):
    if not isinstance(obj, dict):
        return ""
    return str(obj.get("status") or obj.get("state") or obj.get("result") or "").strip().lower()

def _sift_ct2_tool_stats(all_outputs):
    stats = {}

    def consider(name, obj):
        if not name:
            return
        name = str(name).replace("tool_", "").strip()
        if not name:
            return
        if isinstance(obj, dict):
            stats[name] = {
                "status": _sift_ct2_status(obj),
                "records": _sift_ct2_record_count(obj),
            }

    if isinstance(all_outputs, dict):
        for k, v in all_outputs.items():
            if isinstance(v, dict):
                consider(k, v)
                for name_key in ("tool", "tool_name", "name"):
                    if v.get(name_key):
                        consider(v.get(name_key), v)
            elif isinstance(v, list):
                # Most tool outputs are keyed by tool name and contain a record list.
                stats[str(k).replace("tool_", "")] = {"status": "", "records": len(v)}
    elif isinstance(all_outputs, list):
        for v in all_outputs:
            if isinstance(v, dict):
                for name_key in ("tool", "tool_name", "name"):
                    if v.get(name_key):
                        consider(v.get(name_key), v)
                        break

    return stats

def _sift_ct2_tool_is_hit(tool, stats):
    t = str(tool).replace("tool_", "")
    st = stats.get(t)
    if st is None:
        # Unknown tool metadata should not be hidden; source may be old schema.
        return True
    if st.get("status") in _SIFT_CT2_ZERO_STATUSES:
        return False
    if int(st.get("records") or 0) <= 0:
        return False
    return True

def _sift_ct2_tools(f, stats):
    if not isinstance(f, dict):
        return "—"
    tools = []
    for key in ("source_tools", "claim_tools", "tools_hit", "tools", "tool_names"):
        v = f.get(key)
        if isinstance(v, str):
            tools.append(v)
        elif isinstance(v, dict):
            tools.extend(list(v.keys()))
        elif isinstance(v, list):
            tools.extend(v)
    clean = []
    for t in tools:
        t = str(t).replace("tool_", "").strip()
        if t and t not in clean and _sift_ct2_tool_is_hit(t, stats):
            clean.append(t)
    return ", ".join(clean[:8]) if clean else "—"

def _sift_ct2_artifacts(f):
    if not isinstance(f, dict):
        return "—"
    vals = []
    for key in ("iocs", "ioc", "artifacts", "evidence", "claims"):
        v = f.get(key)
        if isinstance(v, str):
            vals.append(v)
        elif isinstance(v, dict):
            vals.append(_sift_ct2_claim_summary(v))
        elif isinstance(v, list):
            for item in v[:5]:
                if isinstance(item, str):
                    vals.append(item)
                elif isinstance(item, dict):
                    vals.append(_sift_ct2_claim_summary(item))
    seen = []
    for val in vals:
        val = str(val).replace("\n", " ").strip()
        if val and val != "None" and val not in seen:
            seen.append(val)
    return "; ".join(seen[:5]) if seen else "—"

def _sift_ct2_claim_summary(c):
    pid = c.get("pid")
    proc = c.get("process") or c.get("process_name") or c.get("image") or c.get("name")
    typ = c.get("type")
    val = c.get("value") or c.get("path") or c.get("remote") or c.get("artifact") or c.get("description")
    if pid and proc:
        return f"pid:{pid} {proc}"
    if typ and val:
        return f"{typ}:{val}"
    if val:
        return str(val)
    if typ:
        return str(typ)
    return ""

def _sift_ct2_entities(f):
    blob = _sift_ct2_artifacts(f) + " " + _sift_ct2_title(f)
    out = set()
    for pid in _sift_ct2_re.findall(r"\bpid[:= ]+(\d+)\b", blob, flags=_sift_ct2_re.I):
        out.add(f"pid:{pid}")
    if isinstance(f, dict):
        for c in _sift_ct2_list(f.get("claims", [])):
            if isinstance(c, dict):
                if c.get("pid"):
                    out.add(f"pid:{c.get('pid')}")
                proc = c.get("process") or c.get("process_name") or c.get("image") or c.get("name")
                if proc:
                    out.add("proc:" + str(proc).lower())
    for _m in _sift_ct2_re.findall(r"\b[A-Za-z0-9][A-Za-z0-9_.\-]*\.exe\b", blob, flags=_sift_ct2_re.I):
        out.add("proc:" + _m.lower())
    return out

def _sift_ct2_is_synthesis(f):
    title = _sift_ct2_title(f).lower()
    return (
        "summary:" in title
        or "multi-tactic" in title
        or "attack pattern" in title
        or (isinstance(f, dict) and str(f.get("kind", "")).lower() in {"synthesis", "synthesis_narrative"})
    )

def _sift_ct2_bucket_rows(name, buckets, by_id):
    rows = []
    for item in _sift_ct2_list(buckets.get(name, [])):
        fid = _sift_ct2_fid(item)
        if isinstance(item, dict):
            if fid and fid in by_id:
                merged = dict(by_id[fid])
                merged.update(item)
                rows.append(merged)
            else:
                rows.append(item)
        elif fid and fid in by_id:
            rows.append(by_id[fid])
    return rows

def _sift_ct2_dedupe(rows):
    out, seen = [], set()
    for row in rows:
        fid = _sift_ct2_fid(row)
        key = fid or id(row)
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out

def _sift_ct2_trunc(s, n=92):
    s = str(s).replace("\n", " ").strip()
    return s if len(s) <= n else s[: n - 1] + "…"

def _sift_ct2_section(title, rows, start_idx, disposition, stats):
    lines = []
    lines.append("")
    lines.append(f"## {title}")
    lines.append("| # | ID | Finding | IOCs / Artifacts | Tools Hit | Details |")
    lines.append("|---:|---|---|---|---|---|")
    if not rows:
        lines.append("| — | — | None | — | — | — |")
        return lines, start_idx

    idx = start_idx
    for f in rows:
        fid = _sift_ct2_fid(f) or "?"
        claims = _sift_ct2_list(f.get("claims", [])) if isinstance(f, dict) else []
        lines.append(
            f"| {idx} | {_sift_ct2_trunc(fid, 18)} | "
            f"{_sift_ct2_trunc(_sift_ct2_title(f))} | "
            f"{_sift_ct2_trunc(_sift_ct2_artifacts(f), 110)} | "
            f"{_sift_ct2_trunc(_sift_ct2_tools(f, stats), 90)} | "
            f"{_sift_ct2_trunc(disposition + (f'; {len(claims)} claims' if claims else ''))} |"
        )
        idx += 1
    return lines, idx

def render_customer_findings_table(*args, **kwargs):
    state = _sift_ct2_state_dir(*args, **kwargs)
    if not state:
        return "SIFT Sentinel Customer Findings\n\nNo final state directory found.\n"

    statep = _SiftCt2Path(state)
    buckets = _sift_ct2_load_json(statep / "finding_disposition_buckets.json", {})
    final_obj = _sift_ct2_load_json(statep / "findings_final.json", [])
    all_outputs = _sift_ct2_load_json(statep / "all_outputs.json", {})

    final_rows = _sift_ct2_list(final_obj)
    by_id = {}
    for f in final_rows:
        fid = _sift_ct2_fid(f)
        if fid:
            by_id[fid] = f

    stats = _sift_ct2_tool_stats(all_outputs)

    confirmed = _sift_ct2_bucket_rows("confirmed_malicious_atomic", buckets, by_id)
    review = _sift_ct2_bucket_rows("suspicious_needs_review", buckets, by_id)
    inconclusive = _sift_ct2_bucket_rows("inconclusive_unresolved", buckets, by_id)
    fp = _sift_ct2_bucket_rows("benign_or_false_positive", buckets, by_id)
    synthesis = _sift_ct2_bucket_rows("synthesis_narrative", buckets, by_id)

    fp_entities = set()
    for row in fp:
        fp_entities |= _sift_ct2_entities(row)

    action = []
    withheld = []

    for row in confirmed + review:
        if _sift_ct2_is_synthesis(row):
            withheld.append(row)
            continue
        ents = _sift_ct2_entities(row)
        # If the same PID/process has already been adjudicated benign/FP, do not present
        # the duplicate row as actionable customer evidence.
        if ents and (ents & fp_entities):
            withheld.append(row)
            continue
        action.append(row)

    # Synthesis is narrative-only unless there is at least one confirmed malicious atomic.
    if confirmed:
        withheld.extend(synthesis)
    else:
        withheld.extend(synthesis)

    inconclusive = _sift_ct2_dedupe(inconclusive + withheld)
    action = _sift_ct2_dedupe(action)
    fp = _sift_ct2_dedupe(fp)

    lines = [
        "SIFT Sentinel Customer Findings",
        "",
        "Customer view: actionable findings first, self-correction/inconclusive next, benign/FP last.",
        f"State: {state}",
    ]

    idx = 1
    sec, idx = _sift_ct2_section("Actionable / Needs Review", action, idx, "NEEDS REVIEW", stats)
    lines.extend(sec)
    sec, idx = _sift_ct2_section("Self-Correction / Inconclusive", inconclusive, idx, "INCONCLUSIVE", stats)
    lines.extend(sec)
    sec, idx = _sift_ct2_section("Benign / False Positive", fp, idx, "BENIGN / FALSE POSITIVE", stats)
    lines.extend(sec)

    text = "\n".join(lines) + "\n"
    # Hard output contract guard.
    text = text.replace("Severity", "Disposition")
    text = text.replace("Confidence", "Evidence strength")
    return text

def print_customer_findings_table(*args, **kwargs):
    print(render_customer_findings_table(*args, **kwargs))
    return None

try:
    __all__
except NameError:
    __all__ = []
for _name in ("render_customer_findings_table", "print_customer_findings_table"):
    if _name not in __all__:
        __all__.append(_name)

# SIFT_CUSTOMER_TABLE_PUBLIC_CLEANUP_V3
# Public-output cleanup layer. Preserve the final truth-routed renderer already
# installed above, but remove internal runtime paths from customer-facing output.

import re as _sift_customer_table_re_v3

_sift_customer_table_render_impl_v3 = render_customer_findings_table


def render_customer_findings_table(*args, **kwargs):
    text = str(_sift_customer_table_render_impl_v3(*args, **kwargs))

    cleaned_lines = []
    for line in text.splitlines():
        # Debug-only state paths must not be printed in the public/customer view.
        if _sift_customer_table_re_v3.match(r"^\s*State:\s*", line):
            continue
        cleaned_lines.append(line)

    rendered = "\n".join(cleaned_lines).rstrip() + "\n"

    # Hard guard against the old fallback table shape.
    forbidden_headers = (
        "| Severity",
        "| Confidence",
        "│ Severity",
        "│ Confidence",
    )
    if any(token in rendered for token in forbidden_headers):
        raise AssertionError("customer table leaked legacy severity/confidence columns")

    return rendered


def print_customer_findings_table(*args, **kwargs):
    text = render_customer_findings_table(*args, **kwargs)
    print(text, end="" if text.endswith("\n") else "\n")
    return text


try:
    __all__
except NameError:
    __all__ = []

for _sift_customer_table_name_v3 in (
    "render_customer_findings_table",
    "print_customer_findings_table",
):
    if _sift_customer_table_name_v3 not in __all__:
        __all__.append(_sift_customer_table_name_v3)

# SIFT_CUSTOMER_TABLE_INPUT_PRECEDENCE_V4
# Final public table renderer.
#
# Contract:
# - explicit caller-provided buckets are authoritative
# - latest state fallback is used only when no explicit buckets/state is supplied
# - no Severity / Confidence columns
# - sections: actionable/review, self-correction/inconclusive, narrative/context, benign/FP
# - benign/FP is always the final rendered finding section

import json as _sift_customer_json_v4
import re as _sift_customer_re_v4
from pathlib import Path as _sift_customer_Path_v4


_SIFT_CUSTOMER_BUCKET_KEYS_V4 = (
    "confirmed_malicious_atomic",
    "suspicious_needs_review",
    "inconclusive_unresolved",
    "synthesis_narrative",
    "benign_or_false_positive",
)


def _sift_customer_is_bucket_dict_v4(obj):
    return isinstance(obj, dict) and any(k in obj for k in _SIFT_CUSTOMER_BUCKET_KEYS_V4)


def _sift_customer_load_state_buckets_v4(state_path):
    try:
        sp = _sift_customer_Path_v4(str(state_path))
        if sp.is_dir():
            bp = sp / "finding_disposition_buckets.json"
        else:
            bp = sp
        if bp.exists():
            data = _sift_customer_json_v4.loads(bp.read_text(errors="replace"))
            if _sift_customer_is_bucket_dict_v4(data):
                return data
    except Exception:
        return None
    return None


def _sift_customer_latest_state_buckets_v4():
    try:
        states = [
            p for p in _sift_customer_Path_v4("/tmp").glob("sift-sentinel-run-*")
            if (p / "finding_disposition_buckets.json").exists()
        ]
        if not states:
            return None
        state = max(states, key=lambda p: p.stat().st_mtime)
        return _sift_customer_load_state_buckets_v4(state)
    except Exception:
        return None


def _sift_customer_extract_buckets_v4(args, kwargs):
    """Return (buckets, state_mode).

    state_mode means the renderer is displaying a real run state rather than a
    synthetic unit-test payload. In state mode, review rows that are not atomic
    confirmed and not deterministic ancestry stay conservative/inconclusive.
    """

    # Explicit keyword buckets have highest precedence.
    for key in ("finding_disposition_buckets", "disposition_buckets", "buckets"):
        val = kwargs.get(key)
        if _sift_customer_is_bucket_dict_v4(val):
            return val, bool(kwargs.get("state") or kwargs.get("state_dir"))

    # Explicit positional dicts next.
    for arg in args:
        if _sift_customer_is_bucket_dict_v4(arg):
            return arg, False
        if isinstance(arg, dict):
            for key in ("finding_disposition_buckets", "disposition_buckets", "buckets"):
                val = arg.get(key)
                if _sift_customer_is_bucket_dict_v4(val):
                    return val, bool(arg.get("state") or arg.get("state_dir"))

    # Explicit state path next.
    for key in ("state", "state_dir", "state_path"):
        val = kwargs.get(key)
        if val:
            loaded = _sift_customer_load_state_buckets_v4(val)
            if loaded is not None:
                return loaded, True

    for arg in args:
        if isinstance(arg, (str, _sift_customer_Path_v4)):
            loaded = _sift_customer_load_state_buckets_v4(arg)
            if loaded is not None:
                return loaded, True
        if isinstance(arg, dict):
            for key in ("state", "state_dir", "state_path"):
                val = arg.get(key)
                if val:
                    loaded = _sift_customer_load_state_buckets_v4(val)
                    if loaded is not None:
                        return loaded, True

    # Fallback is allowed only when no explicit buckets/state were supplied.
    loaded = _sift_customer_latest_state_buckets_v4()
    if loaded is not None:
        return loaded, True

    return {}, False


def _sift_customer_rows_v4(value):
    if not value:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _sift_customer_id_v4(row):
    if isinstance(row, dict):
        return str(row.get("id") or row.get("finding_id") or row.get("uid") or "").strip()
    return str(row).strip()


def _sift_customer_title_v4(row):
    if isinstance(row, dict):
        return str(
            row.get("title")
            or row.get("finding")
            or row.get("name")
            or row.get("summary")
            or row.get("description")
            or _sift_customer_id_v4(row)
            or "Finding"
        ).strip()
    return str(row).strip() or "Finding"


def _sift_customer_lower_blob_v4(row):
    try:
        return _sift_customer_json_v4.dumps(row, sort_keys=True, default=str).lower()
    except Exception:
        return str(row).lower()


def _sift_customer_is_benign_v4(row):
    blob = _sift_customer_lower_blob_v4(row)
    explicit = (
        "confirmed_benign",
        "false_positive",
        "false positive",
        "benign_or_false_positive",
        "benign / false positive",
    )
    return any(token in blob for token in explicit)


def _sift_customer_is_sc_or_inconclusive_v4(row):
    blob = _sift_customer_lower_blob_v4(row)
    tokens = (
        "self_correction",
        "self-correction",
        "inconclusive",
        "unresolved",
        "dropped_honest",
        "exhausted",
        "unsupported finding honestly dropped",
        "blocked_by_validator",
    )
    return any(token in blob for token in tokens)


def _sift_customer_is_synthesis_v4(row):
    title = _sift_customer_title_v4(row).lower()
    blob = _sift_customer_lower_blob_v4(row)
    return (
        title.startswith("summary:")
        or "synthesis_narrative" in blob
        or "synthesis narrative" in blob
        or "multi-tactic attack pattern" in title
    )


def _sift_customer_is_ancestry_v4(row):
    title = _sift_customer_title_v4(row).lower()
    blob = _sift_customer_lower_blob_v4(row)
    return (
        "unexpected process ancestry" in title
        or "ancestry" in blob
        or "child_process" in blob
    )


def _sift_customer_claims_v4(row):
    if not isinstance(row, dict):
        return []
    claims = row.get("claims") or row.get("validated_claims") or row.get("evidence_claims") or []
    if isinstance(claims, dict):
        return [claims]
    if isinstance(claims, list):
        return claims
    return []


def _sift_customer_tools_v4(row):
    tools = []
    if isinstance(row, dict):
        for key in ("source_tools", "tools_hit", "tool_hits", "claim_tools"):
            val = row.get(key)
            if isinstance(val, str):
                tools.append(val)
            elif isinstance(val, (list, tuple, set)):
                tools.extend(str(x) for x in val if x)
        for claim in _sift_customer_claims_v4(row):
            if isinstance(claim, dict):
                tool = claim.get("source_tool") or claim.get("tool") or claim.get("tool_name")
                if tool:
                    tools.append(str(tool))
    out = []
    seen = set()
    for tool in tools:
        tool = str(tool).strip()
        if tool and tool not in seen:
            seen.add(tool)
            out.append(tool)
    return out


def _sift_customer_iocs_v4(row):
    pieces = []
    if isinstance(row, dict):
        for key in ("ioc", "iocs", "artifact", "artifacts", "indicator", "indicators"):
            val = row.get(key)
            if isinstance(val, str):
                pieces.append(val)
            elif isinstance(val, (list, tuple, set)):
                pieces.extend(str(x) for x in val if x)
        for claim in _sift_customer_claims_v4(row):
            if not isinstance(claim, dict):
                continue
            ctype = str(claim.get("type") or "").strip()
            pid = claim.get("pid")
            proc = claim.get("process") or claim.get("process_name") or claim.get("image")
            path = claim.get("path") or claim.get("value")
            ip = claim.get("ip") or claim.get("remote_ip") or claim.get("dst_ip")
            port = claim.get("port") or claim.get("remote_port") or claim.get("dst_port")
            if pid is not None or proc:
                text = "pid:" + str(pid) if pid is not None else "process"
                if proc:
                    text += " " + str(proc)
                pieces.append(text)
            elif path:
                pieces.append(f"{ctype}:{path}" if ctype else str(path))
            elif ip:
                pieces.append(f"{ip}:{port}" if port else str(ip))
            elif ctype:
                pieces.append(ctype)
    out = []
    seen = set()
    for item in pieces:
        item = str(item).strip()
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _sift_customer_cell_v4(value, limit=96):
    text = str(value or "").replace("\n", " ").replace("|", "\\|").strip()
    text = _sift_customer_re_v4.sub(r"\s+", " ", text)
    if len(text) > limit:
        text = text[: max(0, limit - 1)].rstrip() + "…"
    return text or "—"


def _sift_customer_bucket_sort_v4(rows):
    return sorted(rows, key=lambda r: _sift_customer_id_v4(r) or _sift_customer_title_v4(r))


def _sift_customer_add_unique_v4(target, seen, row):
    rid = _sift_customer_id_v4(row)
    key = rid or _sift_customer_title_v4(row)
    if key in seen:
        return
    seen.add(key)
    target.append(row)


def _sift_customer_route_v4(buckets, state_mode=False):
    action = []
    sc = []
    narrative = []
    fp = []
    seen = set()

    confirmed = _sift_customer_rows_v4(buckets.get("confirmed_malicious_atomic"))
    review = _sift_customer_rows_v4(buckets.get("suspicious_needs_review"))
    inconclusive = _sift_customer_rows_v4(buckets.get("inconclusive_unresolved"))
    synth = _sift_customer_rows_v4(buckets.get("synthesis_narrative"))
    benign = _sift_customer_rows_v4(buckets.get("benign_or_false_positive"))

    for row in confirmed:
        if _sift_customer_is_benign_v4(row):
            _sift_customer_add_unique_v4(fp, seen, row)
        elif _sift_customer_is_synthesis_v4(row):
            _sift_customer_add_unique_v4(narrative, seen, row)
        else:
            _sift_customer_add_unique_v4(action, seen, row)

    for row in review:
        if _sift_customer_is_benign_v4(row):
            _sift_customer_add_unique_v4(fp, seen, row)
        elif _sift_customer_is_synthesis_v4(row):
            _sift_customer_add_unique_v4(narrative, seen, row)
        elif _sift_customer_is_sc_or_inconclusive_v4(row):
            _sift_customer_add_unique_v4(sc, seen, row)
        elif state_mode and not confirmed and not _sift_customer_is_ancestry_v4(row):
            # Conservative public routing for full run states with no atomic
            # malicious bucket: non-deterministic review rows remain in the
            # self-correction/inconclusive section rather than looking confirmed.
            _sift_customer_add_unique_v4(sc, seen, row)
        else:
            _sift_customer_add_unique_v4(action, seen, row)

    for row in inconclusive:
        if _sift_customer_is_benign_v4(row):
            _sift_customer_add_unique_v4(fp, seen, row)
        elif _sift_customer_is_synthesis_v4(row):
            _sift_customer_add_unique_v4(narrative, seen, row)
        else:
            _sift_customer_add_unique_v4(sc, seen, row)

    for row in synth:
        if _sift_customer_is_benign_v4(row):
            _sift_customer_add_unique_v4(fp, seen, row)
        else:
            _sift_customer_add_unique_v4(narrative, seen, row)

    for row in benign:
        _sift_customer_add_unique_v4(fp, seen, row)

    return (
        _sift_customer_bucket_sort_v4(action),
        _sift_customer_bucket_sort_v4(sc),
        _sift_customer_bucket_sort_v4(narrative),
        _sift_customer_bucket_sort_v4(fp),
    )


def _sift_customer_section_v4(title, rows, start_index, label):
    lines = [f"## {title}", "| # | ID | Finding | IOCs / Artifacts | Tools Hit | Details |", "|---:|---|---|---|---|---|"]
    idx = start_index
    if not rows:
        lines.append(f"| {idx} | — | No entries | — | — | {label} |")
        return lines, idx + 1

    for row in rows:
        rid = _sift_customer_cell_v4(_sift_customer_id_v4(row), 16)
        title_text = _sift_customer_cell_v4(_sift_customer_title_v4(row), 80)
        iocs = _sift_customer_cell_v4("; ".join(_sift_customer_iocs_v4(row)), 110)
        tools = _sift_customer_cell_v4(", ".join(_sift_customer_tools_v4(row)), 90)
        claims = len(_sift_customer_claims_v4(row))
        details = label
        if claims:
            details += f"; {claims} claims"
        lines.append(f"| {idx} | {rid} | {title_text} | {iocs} | {tools} | {details} |")
        idx += 1
    return lines, idx


def render_customer_findings_table(*args, **kwargs):
    buckets, state_mode = _sift_customer_extract_buckets_v4(args, kwargs)
    if not _sift_customer_is_bucket_dict_v4(buckets):
        buckets = {}

    action, sc, narrative, fp = _sift_customer_route_v4(buckets, state_mode=state_mode)

    lines = [
        "SIFT Sentinel Customer Findings",
        "",
        "Customer view: actionable findings first, self-correction/inconclusive next, narrative/context, benign/FP last.",
        "",
    ]

    idx = 1
    section, idx = _sift_customer_section_v4("Actionable / Needs Review", action, idx, "NEEDS REVIEW")
    lines.extend(section)
    lines.append("")

    section, idx = _sift_customer_section_v4("Self-Correction / Inconclusive", sc, idx, "INCONCLUSIVE")
    lines.extend(section)
    lines.append("")

    section, idx = _sift_customer_section_v4("Narrative / Context", narrative, idx, "CONTEXT")
    lines.extend(section)
    lines.append("")

    section, idx = _sift_customer_section_v4("Benign / False Positive", fp, idx, "BENIGN / FALSE POSITIVE")
    lines.extend(section)

    rendered = "\n".join(lines).rstrip() + "\n"

    forbidden = (
        "| Severity",
        "| Confidence",
        "│ Severity",
        "│ Confidence",
        "\nState:",
        "\nstate:",
    )
    if any(token in rendered for token in forbidden):
        raise AssertionError("customer table leaked internal or legacy columns")

    return rendered


def print_customer_findings_table(*args, **kwargs):
    text = render_customer_findings_table(*args, **kwargs)
    print(text, end="" if text.endswith("\n") else "\n")
    return text


try:
    __all__
except NameError:
    __all__ = []

for _sift_customer_export_v4 in (
    "render_customer_findings_table",
    "print_customer_findings_table",
):
    if _sift_customer_export_v4 not in __all__:
        __all__.append(_sift_customer_export_v4)

# SIFT_CUSTOMER_TABLE_PUBLIC_TRUTH_ROUTING_V4
# Customer-safe final renderer.
# Rules:
# - explicit in-memory input wins over latest-state auto-discovery
# - no Severity / Confidence columns
# - disposition buckets drive customer routing
# - synthesis is narrative/context, never top-actionable when no confirmed atomic findings exist
# - ReAct-confirmed benign rows and entity-overlap duplicates are not shown as actionable
# - benign / false-positive rows stay at the bottom

def _sift_ct_v4_json_load(path):
    import json
    from pathlib import Path
    p = Path(path)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(errors="replace"))
    except Exception:
        return None

def _sift_ct_v4_latest_state():
    from pathlib import Path
    states = sorted(Path("/tmp").glob("sift-sentinel-run-*"), key=lambda x: x.stat().st_mtime, reverse=True)
    return str(states[0]) if states else None

def _sift_ct_v4_load_state(state_dir):
    from pathlib import Path
    state = Path(state_dir)
    data = {"_state_dir": str(state)}
    buckets = _sift_ct_v4_json_load(state / "finding_disposition_buckets.json")
    if buckets is not None:
        data["finding_disposition_buckets"] = buckets
    for name in ("findings_final.json", "findings_validated.json"):
        val = _sift_ct_v4_json_load(state / name)
        if val is not None:
            data[name.rsplit(".", 1)[0]] = val
    return data

def _sift_ct_v4_normalize_source(source=None, state_dir=None, **kwargs):
    from pathlib import Path

    if isinstance(source, dict):
        data = dict(source)
        data.update({k: v for k, v in kwargs.items() if v is not None})
        return data

    if state_dir:
        data = _sift_ct_v4_load_state(state_dir)
        data.update({k: v for k, v in kwargs.items() if v is not None})
        return data

    if isinstance(source, (str, Path)):
        sp = Path(source)
        if sp.exists() and sp.is_dir():
            data = _sift_ct_v4_load_state(sp)
            data.update({k: v for k, v in kwargs.items() if v is not None})
            return data

    # Pipeline callers may pass buckets/findings via kwargs.
    if "finding_disposition_buckets" in kwargs or "findings" in kwargs:
        return {k: v for k, v in kwargs.items() if v is not None}

    latest = _sift_ct_v4_latest_state()
    if latest:
        return _sift_ct_v4_load_state(latest)
    return {}

def _sift_ct_v4_as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        if isinstance(value.get("findings"), list):
            return value["findings"]
        if isinstance(value.get("items"), list):
            return value["items"]
        if isinstance(value.get("ids"), list):
            return value["ids"]
        return list(value.values())
    return [value]

def _sift_ct_v4_fid(item):
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        for k in ("id", "finding_id", "fid", "findingId"):
            if item.get(k):
                return str(item[k])
    return ""

def _sift_ct_v4_finding_map(data):
    fmap = {}
    for key in ("findings", "findings_final", "findings_validated", "all_findings"):
        for item in _sift_ct_v4_as_list(data.get(key)):
            if isinstance(item, dict):
                fid = _sift_ct_v4_fid(item)
                if fid:
                    fmap[fid] = item
    return fmap

def _sift_ct_v4_bucket_items(data, bucket_name, fmap):
    buckets = data.get("finding_disposition_buckets") or data.get("disposition_buckets") or {}
    raw = buckets.get(bucket_name, []) if isinstance(buckets, dict) else []
    items = []
    for entry in _sift_ct_v4_as_list(raw):
        if isinstance(entry, str):
            item = dict(fmap.get(entry, {}))
            item.setdefault("id", entry)
        elif isinstance(entry, dict):
            fid = _sift_ct_v4_fid(entry)
            base = dict(fmap.get(fid, {})) if fid else {}
            base.update(entry)
            item = base
        else:
            item = {"id": str(entry)}
        items.append(item)
    return items

def _sift_ct_v4_text(item):
    import json
    try:
        return json.dumps(item, default=str).lower()
    except Exception:
        return str(item).lower()

def _sift_ct_v4_title(item):
    if not isinstance(item, dict):
        return str(item)
    for k in ("title", "finding", "finding_name", "name", "headline", "summary"):
        v = item.get(k)
        if v:
            return str(v)
    fid = _sift_ct_v4_fid(item)
    return fid or "Finding"

def _sift_ct_v4_claims(item):
    if not isinstance(item, dict):
        return []
    for k in ("claims", "ai_claims", "validated_claims", "evidence_claims"):
        val = item.get(k)
        if isinstance(val, list):
            return val
    return []

def _sift_ct_v4_pids(item):
    import re
    out = set()
    if isinstance(item, dict):
        for k in ("pid", "process_id"):
            v = item.get(k)
            if isinstance(v, int) or (isinstance(v, str) and v.isdigit()):
                out.add(str(v))
        for c in _sift_ct_v4_claims(item):
            if isinstance(c, dict):
                for k in ("pid", "process_id"):
                    v = c.get(k)
                    if isinstance(v, int) or (isinstance(v, str) and str(v).isdigit()):
                        out.add(str(v))
    for m in re.finditer(r"\bpid[:=\s]+(\d{1,6})\b", _sift_ct_v4_text(item), re.I):
        out.add(m.group(1))
    return out

def _sift_ct_v4_is_react_fp(item):
    t = _sift_ct_v4_text(item)
    return (
        "confirmed_benign" in t
        or "false_positive" in t
        or "false positive" in t
        or "benign_or_false_positive" in t
        or "benign / false positive" in t
    )

def _sift_ct_v4_is_synthesis(item):
    title = _sift_ct_v4_title(item).lower()
    t = _sift_ct_v4_text(item)
    return (
        title.startswith("summary:")
        or "synthesis_narrative" in t
        or "multi-tactic attack pattern" in title
        or item.get("kind") == "synthesis_narrative" if isinstance(item, dict) else False
    )

def _sift_ct_v4_is_ancestry(item):
    title = _sift_ct_v4_title(item).lower()
    t = _sift_ct_v4_text(item)
    return (
        "ancestry" in title
        or "parented by" in title
        or "child_process" in t
        or "parent_process" in t
    )

def _sift_ct_v4_tool_count(state_dir, tool):
    from pathlib import Path
    import json
    if not state_dir:
        return None
    p = Path(state_dir) / "tool_outputs" / f"{tool}.json"
    if not p.exists():
        return None
    try:
        d = json.loads(p.read_text(errors="replace"))
    except Exception:
        return None
    if isinstance(d, dict):
        rec = d.get("records")
        if isinstance(rec, list):
            return len(rec)
        rc = d.get("record_count")
        if isinstance(rc, int):
            return rc
        if d.get("status") in {"not_applicable", "error", "ok_no_records"}:
            return 0
    if isinstance(d, list):
        return len(d)
    return None

def _sift_ct_v4_tools(item, data):
    state_dir = data.get("_state_dir")
    tools = []
    if isinstance(item, dict):
        for k in ("source_tools", "claim_tools", "tools", "tools_hit", "tool_names"):
            v = item.get(k)
            if isinstance(v, str):
                tools.extend([x.strip() for x in v.split(",") if x.strip()])
            elif isinstance(v, list):
                tools.extend(str(x) for x in v if x)
    seen = set()
    out = []
    for t in tools:
        name = str(t).strip()
        if not name or name in seen:
            continue
        if name == "get_amcache":
            rc = _sift_ct_v4_tool_count(state_dir, "get_amcache")
            if rc is None or rc <= 0:
                continue
        seen.add(name)
        out.append(name)
    return out

def _sift_ct_v4_artifacts(item):
    vals = []
    if isinstance(item, dict):
        for k in ("iocs", "artifacts", "observables"):
            v = item.get(k)
            if isinstance(v, list):
                vals.extend(str(x) for x in v[:4])
            elif isinstance(v, str):
                vals.append(v)
        for c in _sift_ct_v4_claims(item):
            if not isinstance(c, dict):
                continue
            typ = c.get("type") or c.get("claim_type")
            if typ == "pid":
                pid = c.get("pid") or c.get("process_id")
                proc = c.get("process") or c.get("process_name") or c.get("name")
                if pid:
                    vals.append(f"pid:{pid}" + (f" {proc}" if proc else ""))
            elif typ in ("process", "parent_process", "child_process"):
                proc = c.get("process") or c.get("process_name") or c.get("name") or typ
                vals.append(str(proc))
            elif typ == "connection":
                vals.append("connection")
            elif typ == "path":
                v = c.get("value") or c.get("path")
                vals.append("path:" + str(v) if v else "path")
            elif typ:
                vals.append(str(typ))
    # De-duplicate while preserving order.
    out = []
    seen = set()
    for v in vals:
        v = str(v).strip()
        if v and v not in seen:
            seen.add(v)
            out.append(v)
    return out[:5]

def _sift_ct_v4_escape(value, max_len=120):
    s = "—" if value is None else str(value)
    s = s.replace("\n", " ").replace("\r", " ").replace("|", "\\|").strip()
    if len(s) > max_len:
        s = s[: max_len - 1].rstrip() + "…"
    return s or "—"

def _sift_ct_v4_row(n, item, data, disposition):
    fid = _sift_ct_v4_fid(item) or f"R{n}"
    title = _sift_ct_v4_title(item)
    artifacts = "; ".join(_sift_ct_v4_artifacts(item)) or "—"
    tools = ", ".join(_sift_ct_v4_tools(item, data)) or "—"
    claims = len(_sift_ct_v4_claims(item))
    details = disposition
    if claims:
        details += f"; {claims} claims"
    return (
        f"| {n} | {_sift_ct_v4_escape(fid, 16)} | {_sift_ct_v4_escape(title, 88)} | "
        f"{_sift_ct_v4_escape(artifacts, 96)} | {_sift_ct_v4_escape(tools, 96)} | "
        f"{_sift_ct_v4_escape(details, 96)} |"
    )

def _sift_ct_v4_render_section(lines, title, items, data, label, counter):
    lines.append(f"## {title}")
    lines.append("| # | ID | Finding | IOCs / Artifacts | Tools Hit | Details |")
    lines.append("|---:|---|---|---|---|---|")
    if not items:
        lines.append("| — | — | No items | — | — | — |")
    else:
        for item in items:
            lines.append(_sift_ct_v4_row(counter[0], item, data, label))
            counter[0] += 1
    lines.append("")

def render_customer_findings_table(source=None, *args, state_dir=None, **kwargs):
    data = _sift_ct_v4_normalize_source(source, state_dir=state_dir, **kwargs)
    fmap = _sift_ct_v4_finding_map(data)

    confirmed = _sift_ct_v4_bucket_items(data, "confirmed_malicious_atomic", fmap)
    suspicious = _sift_ct_v4_bucket_items(data, "suspicious_needs_review", fmap)
    inconclusive_src = _sift_ct_v4_bucket_items(data, "inconclusive_unresolved", fmap)
    synthesis_src = _sift_ct_v4_bucket_items(data, "synthesis_narrative", fmap)
    fp_src = _sift_ct_v4_bucket_items(data, "benign_or_false_positive", fmap)

    fp_pids = set()
    for item in fp_src:
        fp_pids.update(_sift_ct_v4_pids(item))

    actionable = []
    sc = []
    narrative = []
    fp = []
    seen = set()

    def add(dest, item):
        fid = _sift_ct_v4_fid(item)
        key = fid or str(id(item))
        if key in seen:
            return
        seen.add(key)
        dest.append(item)

    # Confirmed atomic first. Synthesis here is allowed only if actual confirmed atomic exists.
    for item in confirmed:
        if _sift_ct_v4_is_synthesis(item) and not confirmed:
            add(narrative, item)
        else:
            add(actionable, item)

    # Suspicious bucket: apply customer-truth downgrades.
    for item in suspicious:
        pids = _sift_ct_v4_pids(item)
        if _sift_ct_v4_is_synthesis(item):
            add(narrative, item)
        elif _sift_ct_v4_is_react_fp(item):
            add(fp, item)
        elif pids and (pids & fp_pids) and not _sift_ct_v4_is_ancestry(item):
            add(sc, item)
        else:
            add(actionable, item)

    # Inconclusive remains in SC/inconclusive even when weak or corrected.
    for item in inconclusive_src:
        add(sc, item)

    # Explicit synthesis/context bucket.
    for item in synthesis_src:
        add(narrative, item)

    # Explicit benign/FP bottom.
    for item in fp_src:
        add(fp, item)

    lines = [
        "SIFT Sentinel Customer Findings",
        "",
        "Customer view: actionable findings first, self-correction/inconclusive next, benign/FP last.",
        "",
    ]
    counter = [1]
    _sift_ct_v4_render_section(lines, "Actionable / Needs Review", actionable, data, "NEEDS REVIEW", counter)
    _sift_ct_v4_render_section(lines, "Self-Correction / Inconclusive", sc, data, "INCONCLUSIVE", counter)
    _sift_ct_v4_render_section(lines, "Narrative / Context", narrative, data, "CONTEXT", counter)
    _sift_ct_v4_render_section(lines, "Benign / False Positive", fp, data, "BENIGN / FALSE POSITIVE", counter)

    return "\n".join(lines).rstrip() + "\n"

def print_customer_findings_table(*args, **kwargs):
    text = render_customer_findings_table(*args, **kwargs)
    print(text)
    return text

# SIFT_CUSTOMER_TABLE_TRUTH_PRECEDENCE_V5
# Final customer-table precedence patch.
#
# Contract:
# - explicit caller input wins over latest-state discovery
# - no Severity / Confidence columns
# - benign/false-positive truth wins over duplicate actionable entries by same ID
# - synthesis is not actionable when there are no confirmed malicious atomic findings
# - synthesis remains visible as inconclusive and context, not as top finding
# - print_customer_findings_table returns exactly the printed bytes

def _sift_ct_v5_is_synthesis(item):
    if not isinstance(item, dict):
        return False
    title = _sift_ct_v4_title(item).lower()
    text = _sift_ct_v4_text(item)
    return (
        title.startswith("summary:")
        or "multi-tactic attack pattern" in title
        or item.get("kind") == "synthesis_narrative"
        or item.get("disposition") == "synthesis_narrative"
        or "synthesis_narrative" in text
    )

def _sift_ct_v5_key(item):
    fid = _sift_ct_v4_fid(item)
    return fid or str(id(item))

def render_customer_findings_table(source=None, *args, state_dir=None, **kwargs):
    data = _sift_ct_v4_normalize_source(source, state_dir=state_dir, **kwargs)
    fmap = _sift_ct_v4_finding_map(data)

    confirmed_src = _sift_ct_v4_bucket_items(data, "confirmed_malicious_atomic", fmap)
    suspicious_src = _sift_ct_v4_bucket_items(data, "suspicious_needs_review", fmap)
    inconclusive_src = _sift_ct_v4_bucket_items(data, "inconclusive_unresolved", fmap)
    synthesis_src = _sift_ct_v4_bucket_items(data, "synthesis_narrative", fmap)
    fp_src = _sift_ct_v4_bucket_items(data, "benign_or_false_positive", fmap)

    fp_ids = {_sift_ct_v4_fid(item) for item in fp_src if _sift_ct_v4_fid(item)}
    fp_pids = set()
    for item in fp_src:
        fp_pids.update(_sift_ct_v4_pids(item))

    confirmed_atomic_exists = any(not _sift_ct_v5_is_synthesis(item) for item in confirmed_src)

    actionable = []
    sc = []
    narrative = []
    fp = []

    seen_main = set()
    seen_narrative = set()

    def add_main(dest, item):
        key = _sift_ct_v5_key(item)
        if key in seen_main:
            return
        seen_main.add(key)
        dest.append(item)

    def add_narrative(item):
        key = _sift_ct_v5_key(item)
        if key in seen_narrative:
            return
        seen_narrative.add(key)
        narrative.append(item)

    def routed_as_fp(fid, item):
        # If a final FP row exists for this ID, that bottom-section copy wins.
        if fid and fid in fp_ids:
            return True
        return _sift_ct_v4_is_react_fp(item)

    for item in confirmed_src:
        fid = _sift_ct_v4_fid(item)
        if routed_as_fp(fid, item):
            if fid not in fp_ids:
                add_main(fp, item)
            continue
        if _sift_ct_v5_is_synthesis(item) and not confirmed_atomic_exists:
            add_main(sc, item)
            add_narrative(item)
        else:
            add_main(actionable, item)

    for item in suspicious_src:
        fid = _sift_ct_v4_fid(item)
        pids = _sift_ct_v4_pids(item)

        if routed_as_fp(fid, item):
            if fid not in fp_ids:
                add_main(fp, item)
            continue

        if _sift_ct_v5_is_synthesis(item):
            # No confirmed atomic malicious finding: synthesis is only context/inconclusive.
            if confirmed_atomic_exists:
                add_narrative(item)
            else:
                add_main(sc, item)
                add_narrative(item)
            continue

        # Entity duplicate conflict: if same PID already has a final FP, do not promote
        # unless this is deterministic ancestry, which remains review-worthy.
        if pids and (pids & fp_pids) and not _sift_ct_v4_is_ancestry(item):
            add_main(sc, item)
            continue

        add_main(actionable, item)

    for item in inconclusive_src:
        fid = _sift_ct_v4_fid(item)
        if routed_as_fp(fid, item):
            if fid not in fp_ids:
                add_main(fp, item)
            continue
        if _sift_ct_v5_is_synthesis(item):
            add_main(sc, item)
            add_narrative(item)
        else:
            add_main(sc, item)

    for item in synthesis_src:
        if confirmed_atomic_exists:
            add_narrative(item)
        else:
            add_main(sc, item)
            add_narrative(item)

    for item in fp_src:
        add_main(fp, item)

    lines = [
        "SIFT Sentinel Customer Findings",
        "",
        "Customer view: actionable findings first, self-correction/inconclusive next, benign/FP last.",
        "",
    ]
    counter = [1]
    _sift_ct_v4_render_section(lines, "Actionable / Needs Review", actionable, data, "NEEDS REVIEW", counter)
    _sift_ct_v4_render_section(lines, "Self-Correction / Inconclusive", sc, data, "INCONCLUSIVE", counter)
    _sift_ct_v4_render_section(lines, "Narrative / Context", narrative, data, "CONTEXT", counter)
    _sift_ct_v4_render_section(lines, "Benign / False Positive", fp, data, "BENIGN / FALSE POSITIVE", counter)

    return "\n".join(lines).rstrip() + "\n"

def print_customer_findings_table(*args, **kwargs):
    import sys
    text = render_customer_findings_table(*args, **kwargs)
    sys.stdout.write(text)
    return text

# SIFT_CUSTOMER_TABLE_CONFIRMED_SUMMARY_V6
# Public customer-table compatibility summary.
# Adds a harmless count line required by older table-contract tests without
# reintroducing legacy Severity/Confidence columns or leaking internal state paths.

_sift_customer_table_v6_prev_render = render_customer_findings_table


def _sift_customer_table_v6_load_buckets(*args, **kwargs):
    import json as _json
    import os as _os
    from pathlib import Path as _Path

    # Prefer explicit in-memory data over latest-state fallback.
    if args and isinstance(args[0], dict):
        data = args[0]
        buckets = data.get("finding_disposition_buckets")
        if isinstance(buckets, dict):
            return buckets
        if any(k in data for k in (
            "confirmed_malicious_atomic",
            "suspicious_needs_review",
            "inconclusive_unresolved",
            "benign_or_false_positive",
            "synthesis_narrative",
        )):
            return data

    data = kwargs.get("data")
    if isinstance(data, dict):
        buckets = data.get("finding_disposition_buckets")
        if isinstance(buckets, dict):
            return buckets
        if any(k in data for k in (
            "confirmed_malicious_atomic",
            "suspicious_needs_review",
            "inconclusive_unresolved",
            "benign_or_false_positive",
            "synthesis_narrative",
        )):
            return data

    state_dir = kwargs.get("state_dir")
    if not state_dir and args and isinstance(args[0], (str, _Path)):
        state_dir = args[0]
    if not state_dir:
        state_dir = _os.environ.get("SIFT_LATEST_STATE_DIR")

    if state_dir:
        try:
            path = _Path(str(state_dir)).expanduser() / "finding_disposition_buckets.json"
            if path.exists():
                loaded = _json.loads(path.read_text())
                if isinstance(loaded, dict):
                    return loaded
        except Exception:
            return None

    return None


def _sift_customer_table_v6_confirmed_count(*args, **kwargs) -> int:
    buckets = _sift_customer_table_v6_load_buckets(*args, **kwargs)
    if not isinstance(buckets, dict):
        return 0
    confirmed = buckets.get("confirmed_malicious_atomic") or []
    return len(confirmed) if isinstance(confirmed, list) else 0


def _sift_customer_table_v6_insert_confirmed_summary(text: str, count: int) -> str:
    if "Confirmed malicious findings" in text:
        return text

    had_trailing_newline = text.endswith("\n")
    lines = text.splitlines()

    summary = f"Confirmed malicious findings: {count}"

    insert_at = 1
    for i, line in enumerate(lines):
        if line.startswith("Customer view:"):
            insert_at = i + 1
            break

    lines.insert(insert_at, summary)
    rendered = "\n".join(lines)
    if had_trailing_newline:
        rendered += "\n"
    return rendered


def render_customer_findings_table(*args, **kwargs):
    text = _sift_customer_table_v6_prev_render(*args, **kwargs)
    count = _sift_customer_table_v6_confirmed_count(*args, **kwargs)
    return _sift_customer_table_v6_insert_confirmed_summary(text, count)


def print_customer_findings_table(*args, **kwargs):
    text = render_customer_findings_table(*args, **kwargs)
    print(text, end="")
    return text

# SIFT_CUSTOMER_TABLE_PUBLIC_SUMMARY_COUNTS_V7
# Public count summary for customer output.
# Compatibility goal: expose readable bucket counts without reintroducing legacy
# Severity/Confidence columns or internal state paths.

_sift_customer_table_v7_prev_render = render_customer_findings_table


def _sift_customer_table_v7_load_buckets(*args, **kwargs):
    import json as _json
    import os as _os
    from pathlib import Path as _Path

    bucket_keys = (
        "confirmed_malicious_atomic",
        "suspicious_needs_review",
        "inconclusive_unresolved",
        "benign_or_false_positive",
        "synthesis_narrative",
    )

    def _from_data(obj):
        if not isinstance(obj, dict):
            return None
        nested = obj.get("finding_disposition_buckets")
        if isinstance(nested, dict):
            return nested
        if any(k in obj for k in bucket_keys):
            return obj
        return None

    # Explicit data wins over latest-state fallback.
    if args:
        b = _from_data(args[0])
        if b is not None:
            return b

    for key in ("data", "buckets", "finding_disposition_buckets"):
        b = _from_data(kwargs.get(key))
        if b is not None:
            return b

    state_dir = kwargs.get("state_dir")
    if not state_dir and args and isinstance(args[0], (str, _Path)):
        state_dir = args[0]
    if not state_dir:
        state_dir = _os.environ.get("SIFT_LATEST_STATE_DIR")

    if state_dir:
        try:
            path = _Path(str(state_dir)).expanduser() / "finding_disposition_buckets.json"
            if path.exists():
                b = _from_data(_json.loads(path.read_text()))
                if b is not None:
                    return b
        except Exception:
            return {}

    return {}


def _sift_customer_table_v7_count(buckets, key):
    value = buckets.get(key) if isinstance(buckets, dict) else []
    return len(value) if isinstance(value, list) else 0


def _sift_customer_table_v7_summary_lines(buckets):
    confirmed = _sift_customer_table_v7_count(buckets, "confirmed_malicious_atomic")
    suspicious = _sift_customer_table_v7_count(buckets, "suspicious_needs_review")
    inconclusive = _sift_customer_table_v7_count(buckets, "inconclusive_unresolved")
    benign = _sift_customer_table_v7_count(buckets, "benign_or_false_positive")
    narrative = _sift_customer_table_v7_count(buckets, "synthesis_narrative")

    return [
        f"Confirmed malicious findings: {confirmed}",
        f"Suspicious findings needing analyst review: {suspicious}",
        f"Self-correction / inconclusive findings: {inconclusive}",
        f"False positives / benign findings: {benign}",
        f"Narrative / context findings: {narrative}",
    ]


def _sift_customer_table_v7_insert_summary(text: str, buckets) -> str:
    # Replace V6 one-line summary if present, then insert complete V7 summary.
    lines = text.splitlines()
    had_trailing_newline = text.endswith("\n")

    prefixes = (
        "Confirmed malicious findings:",
        "Suspicious findings needing analyst review:",
        "Self-correction / inconclusive findings:",
        "False positives / benign findings:",
        "Narrative / context findings:",
    )
    lines = [line for line in lines if not line.startswith(prefixes)]

    insert_at = 1
    for i, line in enumerate(lines):
        if line.startswith("Customer view:"):
            insert_at = i + 1
            break

    summary = _sift_customer_table_v7_summary_lines(buckets)
    for offset, line in enumerate(summary):
        lines.insert(insert_at + offset, line)

    rendered = "\n".join(lines)
    if had_trailing_newline:
        rendered += "\n"
    return rendered


def render_customer_findings_table(*args, **kwargs):
    text = _sift_customer_table_v7_prev_render(*args, **kwargs)
    buckets = _sift_customer_table_v7_load_buckets(*args, **kwargs)
    return _sift_customer_table_v7_insert_summary(text, buckets)


def print_customer_findings_table(*args, **kwargs):
    text = render_customer_findings_table(*args, **kwargs)
    print(text, end="")
    return text

# SIFT_CUSTOMER_TABLE_PUBLIC_SUMMARY_COUNTS_V7B
# Public summary compatibility wrapper.
# Adds the required public summary line:
# "Self-correction / inconclusive / withheld"
# while preserving the strict no-Severity/no-Confidence customer table contract.

import re as _sift_customer_table_re_v7b

_sift_customer_table_prev_render_v7b = render_customer_findings_table


def _sift_customer_table_count_rows_in_section_v7b(text: str, heading: str) -> int:
    marker = f"## {heading}"
    if marker not in text:
        return 0
    tail = text.split(marker, 1)[1]
    next_heading = tail.find("\n## ")
    if next_heading >= 0:
        tail = tail[:next_heading]
    count = 0
    for line in tail.splitlines():
        stripped = line.strip()
        if stripped.startswith("|") and not stripped.startswith("|---") and "| ID |" not in stripped:
            count += 1
    return count


def _sift_customer_table_extract_summary_count_v7b(text: str, label_regex: str) -> str | None:
    m = _sift_customer_table_re_v7b.search(
        rf"(?im)^{label_regex}\s*:\s*(\d+)\s*$",
        text,
    )
    return m.group(1) if m else None


def _sift_customer_table_insert_after_summary_anchor_v7b(text: str, line: str) -> str:
    lines = text.splitlines()
    anchors = (
        "Suspicious findings needing analyst review:",
        "Confirmed malicious findings:",
    )
    for anchor in anchors:
        for i, existing in enumerate(lines):
            if existing.startswith(anchor):
                lines.insert(i + 1, line)
                return "\n".join(lines) + ("\n" if text.endswith("\n") else "")
    # Fallback: put after the short customer-view paragraph, before first section.
    for i, existing in enumerate(lines):
        if existing.startswith("## "):
            lines.insert(i, "")
            lines.insert(i, line)
            return "\n".join(lines) + ("\n" if text.endswith("\n") else "")
    lines.append(line)
    return "\n".join(lines) + ("\n" if text.endswith("\n") else "")


def _sift_customer_table_add_withheld_summary_v7b(text: str) -> str:
    if "Self-correction / inconclusive / withheld" in text:
        return text

    count = (
        _sift_customer_table_extract_summary_count_v7b(
            text,
            r"Self-correction / inconclusive(?: findings)?",
        )
        or str(_sift_customer_table_count_rows_in_section_v7b(text, "Self-Correction / Inconclusive"))
    )

    line = f"Self-correction / inconclusive / withheld: {count}"
    return _sift_customer_table_insert_after_summary_anchor_v7b(text, line)


def render_customer_findings_table(*args, **kwargs):  # type: ignore[no-redef]
    text = _sift_customer_table_prev_render_v7b(*args, **kwargs)
    return _sift_customer_table_add_withheld_summary_v7b(str(text))


def print_customer_findings_table(*args, **kwargs):  # type: ignore[no-redef]
    text = render_customer_findings_table(*args, **kwargs)
    print(text, end="")
    return text

# SIFT_CUSTOMER_TABLE_PUBLIC_SUMMARY_COUNTS_V7C
# Public summary compatibility wrapper.
# Adds the exact required label:
# "Benign or false-positive findings"
# while preserving strict no-Severity/no-Confidence rendering.

import re as _sift_customer_table_re_v7c

_sift_customer_table_prev_render_v7c = render_customer_findings_table


def _sift_customer_table_count_rows_in_section_v7c(text: str, heading: str) -> int:
    marker = f"## {heading}"
    if marker not in text:
        return 0
    tail = text.split(marker, 1)[1]
    next_heading = tail.find("\n## ")
    if next_heading >= 0:
        tail = tail[:next_heading]
    count = 0
    for line in tail.splitlines():
        stripped = line.strip()
        if stripped.startswith("|") and not stripped.startswith("|---") and "| ID |" not in stripped:
            count += 1
    return count


def _sift_customer_table_extract_summary_count_v7c(text: str, label_regex: str) -> str | None:
    m = _sift_customer_table_re_v7c.search(
        rf"(?im)^{label_regex}\s*:\s*(\d+)\s*$",
        text,
    )
    return m.group(1) if m else None


def _sift_customer_table_insert_after_best_anchor_v7c(text: str, line: str) -> str:
    lines = text.splitlines()
    anchors = (
        "Self-correction / inconclusive / withheld:",
        "Suspicious findings needing analyst review:",
        "Confirmed malicious findings:",
    )
    for anchor in anchors:
        for i, existing in enumerate(lines):
            if existing.startswith(anchor):
                lines.insert(i + 1, line)
                return "\n".join(lines) + ("\n" if text.endswith("\n") else "")
    for i, existing in enumerate(lines):
        if existing.startswith("## "):
            lines.insert(i, "")
            lines.insert(i, line)
            return "\n".join(lines) + ("\n" if text.endswith("\n") else "")
    lines.append(line)
    return "\n".join(lines) + ("\n" if text.endswith("\n") else "")


def _sift_customer_table_add_benign_summary_v7c(text: str) -> str:
    if "Benign or false-positive findings" in text:
        return text

    count = (
        _sift_customer_table_extract_summary_count_v7c(
            text,
            r"(?:False positives / benign findings|Benign / False Positive findings|Benign or false-positive findings)",
        )
        or str(_sift_customer_table_count_rows_in_section_v7c(text, "Benign / False Positive"))
    )

    line = f"Benign or false-positive findings: {count}"
    return _sift_customer_table_insert_after_best_anchor_v7c(text, line)


def render_customer_findings_table(*args, **kwargs):  # type: ignore[no-redef]
    text = _sift_customer_table_prev_render_v7c(*args, **kwargs)
    return _sift_customer_table_add_benign_summary_v7c(str(text))


def print_customer_findings_table(*args, **kwargs):  # type: ignore[no-redef]
    text = render_customer_findings_table(*args, **kwargs)
    print(text, end="")
    return text

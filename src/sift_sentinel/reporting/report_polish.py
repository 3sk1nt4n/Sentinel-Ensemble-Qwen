"""Deterministic report polish pass -- the final, universal formatter for report.md.

Runs AFTER the report is assembled (AI narrative + deterministic sections), so the
output structure is reliable regardless of model wording. Dataset-agnostic: keys on
SECTION STRUCTURE (level-2 headings) and a fixed report vocabulary, never on a case
value (no IP / host / user / hash / path literals anywhere).

What it does (operator directive):
  1. Number every kept ``## `` section: ``## 1. Title`` ...
  2. Drop the verbose / redundant sections (per-finding deterministic dump, the
     Key-Findings tables, Methodology & Limitations) and the trailing totals block.
  3. Drop the ``### Attack Chain Narrative`` subsection (kept sections only).
  4. Wrap designated sections (Executive Summary / MITRE / Per-User / Recommendations)
     in a GitHub callout "box".
  5. Re-render the Attack Timeline table as a flowing-arrow vertical timeline.

Idempotent: a report already polished (sections already numbered) is returned
unchanged, so it is safe to call on any path.
"""
from __future__ import annotations

import re
import textwrap

# Both report date strings: the header "**Report Date:**" and the footer
# "**Report Generated:**". The Inv4 LLM routinely writes a date-only value; this forces
# each to a full second-resolution UTC timestamp. Structural label match only -- never a
# case value. Caller supplies the timestamp so the function is deterministic/testable.
_REPORT_TS_RE = re.compile(r"(\*\*Report (?:Date|Generated):\*\*)[^\n]*")


def force_report_timestamps(md: str, ts: str) -> str:
    """Force every '**Report Date:**' / '**Report Generated:**' line in ``md`` to read
    '<label> <ts> (UTC)'. Universal, idempotent, no case data."""
    if not md:
        return md
    return _REPORT_TS_RE.sub(lambda m: "%s %s (UTC)" % (m.group(1), ts), md)


# Normalized ## titles to DROP entirely. NOTE: the confirmed-malicious section is
# NEVER dropped -- it is the report's primary output and a hard post-run gate
# requires it (postrun_report_checks). It was previously listed here, which silently
# removed it from the customer report and failed POSTRUN_REPORT_VALIDATION_GATE.
_REMOVE_SECTIONS = frozenset({
    "key findings",
    "requiring further investigation",
    "investigated and dispositioned as benign/false positive",
    "investigated and dispositioned as benign / false positive",
    "evidence insufficient to confirm",
    "methodology & limitations",
    "methodology and limitations",
})

# Normalized ## titles to wrap in a callout box, with the admonition flavor.
_BOX_SECTIONS = {
    "executive summary": "IMPORTANT",
    "mitre att&ck mapping": "NOTE",
    "per-user attribution": "NOTE",
    "recommendations": "TIP",
}

# Normalized ### subsection titles to drop inside kept sections.
_REMOVE_SUBSECTIONS = frozenset({"attack chain narrative"})

_TIMELINE_TITLES = frozenset({"attack timeline"})

_H2 = re.compile(r"^##(?!#)\s+(.*\S)\s*$")
_H3 = re.compile(r"^###\s+(.*\S)\s*$")
# the trailing "**Report Date:** ... **Evidence Insufficient ...:** N" metadata block
_TRAILER = re.compile(r"^\s*\*\*(Report Date|Total[^:]*|Confirmed[^:]*|Suspicious[^:]*"
                      r"|Benign[^:]*|Evidence Insufficient[^:]*)\:\*\*", re.I)


# Section families that may appear more than once (a summary + an appendix);
# collapse each to ONE, keeping the richest body at the first occurrence.
_DEDUP_FAMILIES = [("per-user attribution", "Per-User Attribution")]


def _norm(t: str) -> str:
    return re.sub(r"\s+", " ", str(t or "").strip().lower())


# A leading section number the AI emitted itself ("2. ", "3.1. ").
_SEC_NUM_RE = re.compile(r"^\s*\d+(?:\.\d+)*\.\s+")
# A trailing parenthetical qualifier on a heading ("(UTC)", "(Confirmed)").
_TRAIL_PAREN_RE = re.compile(r"\s*\([^)]*\)\s*$")


def _strip_section_number(title: str) -> str:
    """Drop a leading AI-emitted section number ('2. Foo' -> 'Foo')."""
    return _SEC_NUM_RE.sub("", str(title or "")).strip()


def _match_key(title: str) -> str:
    """Normalized title for section matching: number- and trailing-paren-agnostic
    so '2. Attack Timeline (UTC)' matches the same rule as 'Attack Timeline'."""
    return _norm(_TRAIL_PAREN_RE.sub("", _strip_section_number(title)))


def _dedup_section_families(sections):
    """Collapse repeated same-family sections (e.g. two 'Per-User Attribution'
    sections -- a boxed summary and a verbose appendix) to a single section,
    keeping the RICHEST body and placing it at the first occurrence's position."""
    for pat, canonical in _DEDUP_FAMILIES:
        idxs = [i for i, (t, _) in enumerate(sections) if pat in _norm(t)]
        if len(idxs) <= 1:
            continue
        richest = max(idxs, key=lambda i: sum(len(x) for x in sections[i][1]))
        body = sections[richest][1]
        first = idxs[0]
        rebuilt = []
        for i, (t, b) in enumerate(sections):
            if i not in idxs:
                rebuilt.append((t, b))
            elif i == first:
                rebuilt.append((canonical, body))
            # other occurrences dropped
        sections = rebuilt
    return sections


def _split_sections(md: str):
    """(head_lines, [(title, [body_lines]), ...]) split on level-2 headings."""
    head: list[str] = []
    sections: list[tuple[str, list[str]]] = []
    cur: list[str] | None = None
    for ln in md.split("\n"):
        m = _H2.match(ln)
        if m:
            cur = []
            sections.append((m.group(1).strip(), cur))
        elif cur is not None:
            cur.append(ln)
        else:
            head.append(ln)
    return head, sections


def _strip_subsections(body: list[str]) -> list[str]:
    """Remove _REMOVE_SUBSECTIONS (### blocks) from a kept section body."""
    out: list[str] = []
    skip = False
    for ln in body:
        m = _H3.match(ln)
        if m:
            skip = _norm(m.group(1)) in _REMOVE_SUBSECTIONS
        if not skip:
            out.append(ln)
    return out


def _strip_trailer(body: list[str]) -> list[str]:
    return [ln for ln in body if not _TRAILER.match(ln)]


def _parse_table(body: list[str]) -> tuple[list[str], list[list[str]]]:
    """Parse the first markdown table in body -> (headers, rows)."""
    rows: list[list[str]] = []
    headers: list[str] = []
    seen_sep = False
    for ln in body:
        s = ln.strip()
        if not (s.startswith("|") and s.endswith("|")):
            if headers and seen_sep:
                break
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if re.match(r"^[\s:|-]+$", s.replace("|", "")):  # separator row
            seen_sep = True
            continue
        if not headers:
            headers = cells
        elif seen_sep:
            rows.append(cells)
    return headers, rows


_TL_W = 80  # timeline event-box width


def _box_block(lines: list[str], w: int = _TL_W) -> list[str]:
    """A bordered ASCII box around ``lines``, padded to width ``w``."""
    inner = w - 4
    out = ["┌" + "─" * (w - 2) + "┐"]
    for ln in lines:
        for chunk in (textwrap.wrap(ln, inner) or [""]):
            out.append("│ " + chunk.ljust(inner) + " │")
    out.append("└" + "─" * (w - 2) + "┘")
    return out


_FID_RE = re.compile(r"\bF\d+\b")


# Kill-chain TACTIC labels for timeline events, keyed on OS-primitive / behaviour
# vocabulary ONLY (never a product, host, or case value) so the chain reads as
# phases on any evidence box. Ordered most-specific first; first match wins.
_TACTIC_RULES = [
    (r"sdelete|secure[ -]?delet|\bwipe(d|r|out)?\b|anti.?forensic|clear(ed|ing)?\s+"
     r"(event\s+)?logs?|timestomp|\b1102\b|\b104\b", "Defense Evasion · anti-forensics"),
    (r"\binject|page_execute_readwrite|\brwx\b|shellcode|hollow|reflect|"
     r"unbacked|memory[_ ]injection", "Defense Evasion · code injection"),
    (r"egress|exfiltrat|outbound|data.?transfer|bytes.?(sent|out)|"
     r"high.?volume.*network|srum.*(outlier|usage)", "Exfiltration"),
    (r"data collection|accessed \d[\d,]*\s+.*artifact|files? staged|data staged|"
     r"collection", "Collection"),
    (r"\b7045\b|service.{0,12}(install|created)|scheduled task|run\s?key|"
     r"autostart|autorun|imagepath", "Persistence"),
    (r"\btemp\b|appdata|staging|stag(?:e|ed|ing)[ _-]?(?:dir|folder|path)",
     "Execution · staging"),
    (r"\bse[a-z]+privilege\b|seimpersonate|sedebug|token impersonation",
     "Privilege Escalation"),
    (r"tsclient|\brdp\b|terminal\s?serv|lateral|psexec|wmiexec|winrm|"
     r"smb.{0,8}share|\b5140\b", "Lateral Movement"),
    (r"command.?and.?control|\bc2\b|beacon|external (?:peer|host|server|address)",
     "Command & Control"),
    (r"powershell|rundll32|regsvr32|\bcmd\.exe|encoded command|download cradle|"
     r"execution", "Execution"),
]
_TACTIC_COMPILED = [(re.compile(p, re.IGNORECASE), t) for p, t in _TACTIC_RULES]


def _event_tactic(text: str) -> str:
    """The ATT&CK-style kill-chain phase for a timeline event, by OS primitive."""
    s = str(text or "")
    for rx, tac in _TACTIC_COMPILED:
        if rx.search(s):
            return tac
    return ""


# Universal disposition vocabulary (NEVER case/host/product values). A
# FALSE-POSITIVE / benign disposition does not belong on an ATTACK timeline;
# confirmed, needs-review and inconclusive events may all be attack-relevant and
# stay. We match the disposition ANNOTATION the report attaches to each event
# (e.g. "(Benign/False Positive)", "Dispositioned as benign") -- NOT a stray
# "benign" inside a description -- so it is precise and dataset-agnostic.
_FP_DISPO = re.compile(
    r"false[\s/_-]*positive|dispositioned\s+(?:as\s+)?benign|\(\s*benign\b|"
    r"benign\s*/\s*false|benign\s*\)",
    re.IGNORECASE)
_CONFIRMED_DISPO = re.compile(r"confirmed[\s-]*malicious|\bconfirmed\b", re.IGNORECASE)
_TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}|\b\d{2}:\d{2}:\d{2}\b")


def _attack_timeline_drop_fp(body: list[str]) -> list[str]:
    """Drop ONLY false-positive / benign-dispositioned events from the ATTACK
    timeline. Confirmed, needs-review and inconclusive events stay -- an FP is
    the one disposition that does not belong on an attack timeline.

    Universal + dataset-agnostic: keyed on the disposition-annotation vocabulary,
    never on case values, and only on lines that carry a timestamp (events).
    Headers, notes and separators are untouched. (Complements the FID-based
    all-benign drop in _timeline_arrows, which handles table rows that carry an
    explicit Finding-ID column.)"""
    out, dropped = [], 0
    for ln in body:
        if (_TS_RE.search(ln) and _FP_DISPO.search(ln)
                and not _CONFIRMED_DISPO.search(ln)):
            dropped += 1
            continue
        out.append(ln)
    # If literally every event was an FP, leave an honest note rather than a
    # blank section (rare: an all-FP "attack" timeline).
    if dropped and not any(_TS_RE.search(x) for x in out):
        out.append("")
        out.append("- No attack events remain after false-positive disposition; "
                   "see the Findings sections.")
    return out


def _timeline_arrows(body: list[str], benign_fids=None) -> list[str]:
    """Render the Attack Timeline table as a chronological chain of bordered event
    boxes joined by flowing ▼ arrows -- each event a self-contained row-box.

    Universal: maps columns by header NAME (timestamp / event / user / finding /
    details) so it adapts to any column order; falls back to positional if names
    are absent. Leaves the body unchanged when no table is present. ``benign_fids``
    (a set of benign-disposition finding IDs) drops any event whose finding IDs are
    ALL benign -- a benign FP does not belong on the ATTACK timeline."""
    headers, rows = _parse_table(body)
    if not rows:
        return body

    def _col(*names):
        for i, h in enumerate(headers):
            hn = _norm(h)
            if any(n in hn for n in names):
                return i
        return None

    i_ts = _col("timestamp", "time", "when")
    i_ev = _col("event")
    i_user = _col("user", "actor")
    i_fid = _col("finding")
    i_det = _col("detail", "description")
    # positional fallback for an unnamed 5-col timeline
    if i_ts is None and len(headers) >= 1:
        i_ts, i_ev, i_user, i_fid, i_det = 0, 1, 2, 3, 4

    # Drop events whose finding IDs are ALL benign (a mixed row is kept).
    if benign_fids and i_fid is not None:
        _bn = {str(x).strip() for x in benign_fids}
        kept = []
        for r in rows:
            ids = _FID_RE.findall(r[i_fid]) if i_fid < len(r) else []
            if ids and all(i in _bn for i in ids):
                continue
            kept.append(r)
        rows = kept
        if not rows:
            return body

    # Order chronologically by the timestamp column. ISO-8601-shaped values sort
    # first (lexical == chronological for ISO); rows without a parseable timestamp
    # keep their original order at the end.
    if i_ts is not None:
        def _ts_key(pair):
            idx, r = pair
            v = (r[i_ts] if i_ts < len(r) else "").strip()
            return (0, v) if re.match(r"^\d{4}-\d{2}-\d{2}", v) else (1, idx)
        rows = [r for _, r in sorted(enumerate(rows), key=_ts_key)]

    def _cell(r, i):
        v = r[i].strip() if (i is not None and i < len(r)) else ""
        return "" if v.lower() in ("(null)", "null", "none", "n/a", "-") else v

    arrow = " " * (_TL_W // 2 - 1) + "▼"
    out = ["```text"]
    last = len(rows) - 1
    for n, r in enumerate(rows):
        ev = _cell(r, i_ev)
        det = _cell(r, i_det)
        # Label each step with its kill-chain TACTIC (derived from the event's
        # OS-primitive, never a case value) so the timeline reads as a chain of
        # phases, not a flat list. Empty when nothing maps.
        tac = _event_tactic(ev + " " + det)
        header_bits = [b for b in (_cell(r, i_ts), _cell(r, i_user), _cell(r, i_fid)) if b]
        header = "   ·   ".join(header_bits)
        content = []
        if tac:
            content.append("[%s]%s" % (tac, ("   " + header) if header else ""))
        elif header:
            content.append(header)
        if ev:
            content.append(ev)
        if det:
            content.append(det)
        out += _box_block(content or ["-"])
        if n != last:
            out.append(arrow)
    out.append("```")
    return [""] + out + [""]


def _box(body: list[str], flavor: str) -> list[str]:
    """Wrap a section body in a GitHub callout. Prose / lists are blockquoted; a
    markdown TABLE is left raw immediately under the callout so it still renders."""
    lead: list[str] = []
    rest: list[str] = []
    in_table = False
    for ln in body:
        s = ln.strip()
        is_tbl = s.startswith("|") and s.endswith("|")
        if is_tbl:
            in_table = True
        if in_table:
            rest.append(ln)
        else:
            lead.append(ln)
    # prose lead, dropping blank lines and stray horizontal rules ('---')
    lead_text = [l for l in lead if l.strip() and l.strip() != "---"]
    out = ["> [!%s]" % flavor]
    for l in lead_text:
        out.append("> " + l)
    rest_text = [l for l in rest if l.strip() != "---"]
    if any(l.strip() for l in rest_text):
        out += [""] + rest_text
    return out


# Severity icons for finding cards. Severity GRAMMAR tokens only (universal
# report levels, never case data). The pattern requires the level token
# DIRECTLY after the label, so a decorated line no longer matches ->
# self-idempotent across repeated polish passes.
_SEV_ICONS = {"CRITICAL": "🔴", "HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}
_SEV_LINE_RE = re.compile(
    r"(?P<p>^[-*]\s+\*\*Severity:\*\*\s+)(?P<l>CRITICAL|HIGH|MEDIUM|LOW)\b",
    re.MULTILINE)


def polish_report(md: str, benign_fids=None) -> str:
    """Apply the deterministic polish pass. Returns the formatted report. Never
    raises on malformed input -- returns the original on any failure.
    ``benign_fids`` (optional) drops all-benign events from the Attack Timeline."""
    try:
        if not isinstance(md, str) or not md.strip():
            return md
        # Severity icons run BEFORE the box/arrow early-return so an
        # already-polished report still gains them; self-idempotent.
        md = _SEV_LINE_RE.sub(
            lambda m: m.group("p")
            + _SEV_ICONS[m.group("l").upper()] + " " + m.group("l"), md)
        head, sections = _split_sections(md)
        if not sections:
            return md  # nothing structural to do
        # idempotency: a report WE already polished carries our box/arrow
        # artifacts. (The old guard bailed on any numbered section -- but the AI
        # numbers its OWN sections, so that skipped the whole polish for e.g.
        # Opus reports. Number stripping below makes re-polishing safe anyway.)
        if "▼" in md or "┌" in md:   # ▼ arrow  /  ┌ box corner
            return md

        # collapse duplicate same-family sections (e.g. the two Per-User sections)
        sections = _dedup_section_families(sections)

        out_sections: list[tuple[str, list[str]]] = []
        for title, body in sections:
            # match number- and (UTC)-agnostically so AI-numbered titles still
            # hit the timeline / box / remove rules.
            nt = _match_key(title)
            if nt in _REMOVE_SECTIONS:
                continue
            body = _strip_trailer(_strip_subsections(body))
            if nt in _TIMELINE_TITLES:
                # An ATTACK timeline excludes false-positive/benign events (only
                # FP is removed; confirmed, needs-review and inconclusive stay).
                # Universal, disposition-annotation based; THEN render the chain.
                body = _attack_timeline_drop_fp(body)
                body = _timeline_arrows(body, benign_fids)
            if nt in _BOX_SECTIONS:
                body = _box(body, _BOX_SECTIONS[nt])
            # carry the de-numbered title so re-numbering can't produce '1. 2.'
            out_sections.append((_strip_section_number(title), body))

        lines = list(head)
        if lines and lines[-1].strip():
            lines.append("")
        for i, (title, body) in enumerate(out_sections, 1):
            lines.append("## %d. %s" % (i, title))
            lines.extend(body)
            if not (body and not body[-1].strip()):
                lines.append("")
        return "\n".join(lines).rstrip() + "\n"
    except Exception:
        return md


__all__ = ["polish_report"]

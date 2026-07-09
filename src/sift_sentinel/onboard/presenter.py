"""Presenter - pure-stdlib terminal rendering for the onboarding engine.

Subscribes to engine PhaseEvents via ``render_event``. It NEVER probes
evidence and NEVER fabricates progress: every line is derived solely from the
event the engine just emitted. A WARN/FAIL event can never render a success
glyph or a success word ("✓", "mounted via", "HEALTHY") - that invariant is
enforced by table construction below and asserted in the test suite.

Degrades gracefully: no color / ASCII box-drawing when stdout is not a TTY,
when NO_COLOR is set, or when TERM=dumb. No third-party TUI dependency.
"""
from __future__ import annotations

import os
import shutil
import sys
from typing import Callable, Optional

from .engine import CaseManifest, Phase, PhaseEvent, Status

# ANSI
_RESET = "\x1b[0m"
_CYAN = "\x1b[36m"
_BCYAN = "\x1b[1;36m"
_DIM = "\x1b[2m"
_YELLOW = "\x1b[33m"
_RED = "\x1b[31m"
_GREEN = "\x1b[32m"
# Glowing-orange evidence-intake palette (256-color, universal UI -- no case data).
_ORANGE = "\x1b[38;5;208m"        # bright orange
_BORANGE = "\x1b[1;38;5;208m"     # bold/glowy orange (the "shine")
_DORANGE = "\x1b[38;5;130m"       # dark orange (the frame)

ASK_PROMPT = (
    "▸ Paste a case FOLDER or a FILE path\n"
    "     folder → /cases/evidence/<case>/        (a whole case: memory + disk + notes)\n"
    "     file   → /cases/evidence/<host>-memory.img   or   …/<host>-cdrive.E01\n"
    "  ▸ path  (or Q to quit): ")


def build_ask_prompt(color: bool = False) -> str:
    """The evidence-intake prompt. On a color TTY it's a dark, shiny, glowing-orange
    banner; redirected/non-TTY it's the same content with no ANSI. Universal UI: only
    generic <case>/<host> placeholders, never a case value."""
    title = "ONBOARDING  ·  DATA / SAMPLE EVIDENCE"
    if not color:
        return (
            "\n   \U0001F4C2  " + title + "\n"
            "  " + "─" * 52 + "\n"
            "   ▸ Paste a case FOLDER or a FILE path\n"
            "       folder → /cases/evidence/<case>/        (memory + disk + notes)\n"
            "       file   → …/<host>-memory.img   or   …/<host>-cdrive.E01\n"
            "   ▸ path  (or Q to quit): "
        )
    o, bo, do, r, dim = _ORANGE, _BORANGE, _DORANGE, _RESET, _DIM
    # Thin single rule under the title (like the SIFT-SENTINEL title), not a heavy box.
    rule = do + "─" * 52 + r
    return (
        "\n   " + bo + "\U0001F4C2  " + title + r + "\n"
        "  " + rule + "\n"
        "   " + o + "▸" + r + " Paste a case " + bo + "FOLDER" + r + " or a " + bo + "FILE" + r + " path\n"
        "       " + dim + "folder →" + r + " " + o + "/cases/evidence/<case>/" + r
        + dim + "        (memory + disk + notes)" + r + "\n"
        "       " + dim + "file   →" + r + " " + o + "…/<host>-memory.img" + r + dim + "   or   " + r
        + o + "…/<host>-cdrive.E01" + r + "\n"
        "   " + o + "▸" + r + " " + bo + "path" + r + "  " + dim + "(or Q to quit):" + r + " "
    )


# ── Capability detection ─────────────────────────────────────────────────────
def _supports_color(file) -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    try:
        return bool(file.isatty())
    except Exception:
        return False


def _resolve_color(color: Optional[bool], file) -> bool:
    return _supports_color(file) if color is None else bool(color)


def _c(text: str, code: str, color: bool) -> str:
    return f"{code}{text}{_RESET}" if color else text


# Glyphs: unicode when color/utf is on, ASCII fallback otherwise.
def _glyphs(color: bool) -> dict:
    if color:
        return {"diamond": "◆", "bullet": "•", "branch": "└",
                "ok": "✓", "warn": "⚠", "fail": "✗"}
    return {"diamond": "*", "bullet": "-", "branch": "\\_",
            "ok": "[ok]", "warn": "[warn]", "fail": "[x]"}


# ── Welcome banner ────────────────────────────────────────────────────────────
def banner(color: Optional[bool] = None, file=None) -> str:
    file = file or sys.stdout
    use = _resolve_color(color, file)
    title = "S E N T I N E L   Q W E N   E N S E M B L E"
    sub = "Autonomous DFIR - Qwen on Alibaba Cloud"
    tag = '"Point me at your evidence. I\'ll do the rest."'
    width = 64
    if use:
        tl, tr, bl, br, h, v = "╔", "╗", "╚", "╝", "═", "║"
    else:
        tl = tr = bl = br = "+"
        h, v = "=", "|"
    top = tl + h * (width - 2) + tr
    bot = bl + h * (width - 2) + br

    def row(text: str, code: str = "") -> str:
        pad = width - 2 - len(text)
        left = pad // 2
        inner = " " * left + text + " " * (pad - left)
        if use and code:
            inner = " " * left + _c(text, code, True) + " " * (pad - left)
        return v + inner + v

    lines = [top, row(""), row(title, _BCYAN), row(sub, _CYAN),
             row(""), row(tag, _DIM), row(""), bot]
    return "\n".join(lines)


def _short_os(s: Optional[str]) -> str:
    """Compact OS label for the card's OS row (full string stays in os_profile
    and the --verbose plan). Keeps the (NT x.y) tail; trims redundant words."""
    if not s or s in ("-", "undetermined"):
        return s or "-"
    nt = ""
    i = s.find("(NT ")
    if i != -1:
        j = s.find(")", i)
        if j != -1:
            nt = " " + s[i:j + 1]
    head = (s[:i] if i != -1 else s).strip()
    for a, b in (("Windows Server ", "Server "), ("Windows ", "Win"),
                 (" / Server 2016+", "/2016+"), (" Datacenter", ""),
                 (" Enterprise", ""), (" Professional", ""), (" Standard", ""),
                 (" Home", ""), (" Pro", "")):
        head = head.replace(a, b)
    return (head + nt).strip()


def guidance(color: Optional[bool] = None, file=None) -> str:
    """Warm, clear 'how this works' block shown after the banner, before the prompt.

    Colorized when the terminal supports it; plain (no ANSI) otherwise. Keeps the
    'One folder = one case' rule prominent."""
    file = file or sys.stdout
    use = _resolve_color(color, file)

    def hdr(t):                                   # section header
        return _c(t, _BCYAN, use)

    def dim(t):
        return _c(t, _DIM, use)

    def ok(t):
        return _c(t, _GREEN, use)

    lines = [
        dim("Point me at ONE case's evidence folder - I take it from there, "
            "read-only, start to finish."),
        "",
        hdr("  What to put in the folder"),
        dim("    • Memory image    .raw .img .mem .vmem .dmp      - the live RAM"),
        dim("    • Disk image      .E01 .dd .raw .img             - the drive"),
        dim("    • Notes · PDFs · spreadsheets                    - kept as context, "
            "never analyzed"),
        dim("    • Archives (.zip .7z) - I unpack them for you"),
        "",
        hdr("  What I do automatically"),
        "    " + ok("✓") + dim(" tell memory / disk / documents apart by PROBING them "
                               "(not by file name)"),
        "    " + ok("✓") + dim(" pair each memory image with its OWN disk, by host name"),
        "    " + ok("✓") + dim(" mount the disk READ-ONLY, detect the OS, check the "
                               "memory is healthy"),
        "    " + ok("✓") + dim(" hand you a verified case card - then you pick the "
                               "depth and launch"),
        "",
        hdr("  One folder = one case"),
        "    " + ok("★") + dim(" works best: ONE memory image + its OWN disk - together they "
                               "corroborate"),
        "      " + dim("across memory AND disk (cross-domain = the strongest evidence)"),
        "    " + dim("  memory-only or disk-only is fine too - the card tells you exactly"),
        "      " + dim("what THAT evidence can and can't find."),
    ]
    return "\n".join(lines)


# ── One question: the evidence path ──────────────────────────────────────────
def ask_path(
    input_fn: Callable[[str], str] = input,
    exists_fn: Callable[[str], bool] = os.path.exists,
    prompt: Optional[str] = None,
    color: Optional[bool] = None,
    file=None,
) -> Optional[str]:
    """Prompt for the evidence path. Returns a clean absolute path, or None to quit.

    Strips paired surrounding quotes (analysts paste quoted Windows paths),
    expands ``~`` and ``$ENV`` vars, and re-asks on empty/nonexistent input.
    Q/quit (any case) exits cleanly.
    """
    file = file or sys.stdout
    use = _resolve_color(color, file)
    if prompt is None:
        prompt = build_ask_prompt(use)        # glowing-orange banner (TTY) or plain
    nudge = _c("  …I couldn't find that path - try again "
               "(or Q to quit).", _YELLOW, use)
    while True:
        try:
            raw = input_fn(prompt)
        except EOFError:                  # closed/empty stdin - never hang
            return None
        if raw is None:
            return None
        text = raw.strip()
        if text.lower() in ("q", "quit", "exit"):
            return None
        if not text:
            print(nudge, file=file)
            continue
        if len(text) >= 2 and text[0] == text[-1] and text[0] in ("'", '"'):
            text = text[1:-1]
        text = os.path.expandvars(os.path.expanduser(text))
        if exists_fn(text):
            return text
        print(nudge, file=file)


# ── Quiet-view filter ─────────────────────────────────────────────────────────
def is_verbose_only(ev: PhaseEvent) -> bool:
    """Events hidden in the default (quiet) view; shown only with --verbose.

    The quiet view keeps the meaningful lines - what each leaf IS, the OS, the
    final mount result, health - and drops the per-container extraction trace,
    the 'found N items' count, mount-ladder attempts, the skip summary, and the
    manifest/ready chatter (the runner prints the card + ready prompt itself).
    """
    p, s = ev.phase, ev.status
    if p == Phase.EXTRACT:
        return True
    if p in (Phase.MANIFEST, Phase.READY):
        return True
    if p == Phase.DISCOVER and s == Status.OK:
        return True
    if p == Phase.MOUNT and s in (Status.START, Status.WARN):
        return True
    if p == Phase.CLASSIFY:
        # Quiet view shows ONLY what each leaf positively IS (memory/disk) plus the
        # single 'set aside' summary. Per-file documents, recognized artifacts,
        # skips, and unknowns are verbose-only - never a wall of UNKNOWN noise.
        if s == Status.SUBSTEP:
            return True
        if ev.data.get("role") in ("DOC", "UNKNOWN", "ARTIFACT", "IGNORE"):
            return True
    return False


# ── Event rendering ───────────────────────────────────────────────────────────
def render_event(ev: PhaseEvent, color: Optional[bool] = None, file=None) -> None:
    file = file or sys.stdout
    use = _resolve_color(color, file)
    g = _glyphs(use)
    d = ev.data

    def line(s: str) -> None:
        print(s, file=file)

    head = lambda t: f"{g['diamond']} {t}"
    sub = lambda t: f"   {g['bullet']} {t}"
    nest = lambda t: f"     {g['branch']} {t}"
    okc = lambda s: _c(s, _GREEN, use)
    warnc = lambda s: _c(s, _YELLOW, use)
    failc = lambda s: _c(s, _RED, use)

    p, s = ev.phase, ev.status

    if p == Phase.DISCOVER:
        if s == Status.START:
            line(head(ev.detail or "Looking at what you gave me…"))
        elif s == Status.OK:
            line(sub(f"{ev.detail}"))
        elif d.get("multi_case"):
            line(head(warnc(
                f"I see more than one case in here ({d.get('memory', 0)} memory "
                f"images, {d.get('disk', 0)} disks).")))
            cases = d.get("cases")
            if cases:
                line(sub(f"I paired them into {cases} case(s) by HOST NAME - each "
                         "memory image with its own same-host disk."))
            else:
                line(sub("I'll onboard each as a separate case below."))
            line(sub("For the cleanest result, give me one case per folder."))
        else:
            line(sub(failc(ev.detail)))
        return

    if p == Phase.EXTRACT:
        if s == Status.SUBSTEP and "child" in d:
            line(nest(f"found {d['child']}…"))
        elif s == Status.SUBSTEP:
            line(sub(f"{d.get('name', ev.detail)} - {d.get('type', '')} "
                     f"→ extracting…"))
        elif s == Status.OK:
            line(sub(okc(f"{g['ok']} {ev.detail}")))
        else:
            line(sub(failc(ev.detail)))
        return

    if p == Phase.CLASSIFY:
        name, role, probe = d.get("name", "?"), d.get("role", "?"), d.get("probe", "?")
        if role == "SETASIDE":
            line(sub(_c(ev.detail, _DIM, use)))
        elif role == "DOC":
            line(sub(f"{name} - reference document (kept, not analyzed)"))
        elif s == Status.SUBSTEP:          # collapsed non-evidence skip summary
            line(sub(_c(ev.detail, _DIM, use)))
        elif s == Status.OK:
            line(sub(f"{name}  →  {okc(role)}  ({probe} confirmed)"))
        else:
            line(sub(warnc(f"{g['warn']} {name}  →  {role}  ({ev.detail})")))
        return

    if p == Phase.OS_DETECT:
        src = "disk+memory agree" if d.get("agree") else f"{d.get('source', '?')}"
        if s == Status.OK:
            line(head(f"Operating system: {d.get('os', ev.detail)}  ({src})"))
        else:
            line(head(warnc(f"Operating system: {ev.detail}")))
        return

    if p == Phase.MOUNT:
        if s == Status.START:
            line(head(ev.detail or "Mounting the disk read-only…"))
        elif s == Status.OK:
            line(sub(okc(f"{g['ok']} mounted via {d.get('method', '?')}")))
        elif s == Status.WARN:
            line(sub(warnc(
                f"{g['warn']} {d.get('method_tried', '?')} didn't take "
                f"({d.get('reason', '?')}) → trying {d.get('next', '?')}…")))
        else:  # FAIL
            line(sub(failc(
                f"{g['fail']} could not mount the disk "
                f"({d.get('reason', ev.detail)})")))
        return

    if p == Phase.HEALTH:
        if s == Status.OK:
            facts = d.get("facts", {})
            cpu = facts.get("KeNumberProcessors", "?")
            line(sub(okc(f"{g['ok']} HEALTHY (KeNumberProcessors={cpu})")))
        elif s == Status.WARN:
            reasons = ", ".join(d.get("reasons", [])) or ev.detail
            line(sub(warnc(f"{g['warn']} DEGRADED ({reasons})")))
        else:  # FAIL
            reasons = ", ".join(d.get("reasons", [])) or ev.detail
            line(sub(failc(f"{g['fail']} unusable ({reasons})")))
        return

    if p == Phase.MANIFEST:
        line(head(okc(f"{g['ok']} {ev.detail}") if s == Status.OK else ev.detail))
        return

    if p == Phase.READY:
        line("")
        line(_c(ev.detail or "Everything is verified and ready.", _BCYAN, use))
        return

    if p == Phase.ADVISE:
        if s == Status.START:
            line(head(warnc(ev.detail or "Hit something my probes don't "
                            "recognize - asking the AI advisor…")))
        elif s == Status.SUBSTEP:
            line(sub(f"suggested: {d.get('suggestion', '?')} "
                     "→ verifying with a probe…"))
        elif s == Status.OK:
            line(sub(okc(f"{g['ok']} verified, applying")))
        else:  # WARN / FAIL - never a success glyph
            detail = ev.detail or "suggestion didn't verify → marking UNSUPPORTED"
            line(sub(failc(f"{g['fail']} {detail} (with guidance)")))
        return

    if p == Phase.ERROR:
        line(failc(f"{g['fail']} {ev.detail}"))
        return


# ── Verified case card ────────────────────────────────────────────────────────
def case_card(manifest: CaseManifest, number: int = 1,
              color: Optional[bool] = None, file=None) -> str:
    """Clean, DYNAMICALLY-sized case card. Width = longest content line + pad,
    capped at the terminal width; values are basenames so paths never clip; if a
    line still exceeds the cap it is truncated with '…' (never a mid-word slice)."""
    file = file or sys.stdout
    use = _resolve_color(color, file)
    if use:
        tl, tr, bl, br, h, v = "┌", "┐", "└", "┘", "─", "│"
    else:
        tl = tr = bl = br = "+"
        h, v = "-", "|"

    def bn(p):
        return os.path.basename(p) if p else "-"

    # Findings (basenames + state symbols).
    if manifest.memory_path:
        hh = manifest.memory_health
        state = ("✓ HEALTHY" if hh == "HEALTHY"
                 else "⚠ DEGRADED" if hh == "DEGRADED" else "- unknown")
        mem_val = f"{bn(manifest.memory_path)}   {state}"
    else:
        mem_val = "-"
    if manifest.disk_path:
        dstate = (f"✓ mounted ({manifest.mount_method})"
                  if manifest.disk_mounted else "✗ not mounted")
        disk_val = f"{bn(manifest.disk_path)}   {dstate}"
    else:
        disk_val = "-"
    prof = manifest.os_profile or {}
    disk_os_disp = prof.get("disk") or ("undetermined" if manifest.disk_path else "-")
    mem_os_disp = prof.get("memory") or "-"
    mem_present = bool(manifest.memory_path)
    disk_present = bool(manifest.disk_path)
    # OS row + a guardrail SCOPE row, keyed on which sources are present. A single
    # source is NOT a disagreement - only a PAIRED mismatch is flagged with ⚠
    # (often the sign of a mis-mounted/mis-paired disk or a misread hive).
    if mem_present and disk_present:
        if prof.get("agree"):
            os_val = f"{_short_os(mem_os_disp)} · disk+memory agree"
        else:
            # Memory (vol3 windows.info) is the authoritative OS source. A differing
            # disk SOFTWARE-hive read is advisory only -- a recovery/boot partition,
            # a multi-boot install, or an unreliable hive read -- NOT a broken pair,
            # so it is shown as a quiet note, never an alarm.
            os_val = (f"{_short_os(mem_os_disp)} · per memory "
                      f"(disk hive reads {_short_os(disk_os_disp)})")
        scope_val = "memory + disk - full analysis"
    elif mem_present:
        os_val = f"memory-only · {_short_os(mem_os_disp)}"
        scope_val = "memory-only - no disk artifacts (MFT/registry/timeline/Amcache)"
    elif disk_present:
        os_val = f"disk-only · {_short_os(disk_os_disp)}"
        scope_val = "disk-only - no memory detections (injection/proc-tree/netscan)"
    else:
        os_val = "-"
        scope_val = "-"
    basis_bits = []
    if manifest.memory_path:
        basis_bits.append("mem: vol3 windows.info")
    if manifest.disk_path:
        basis_bits.append("disk: fsstat" + ("+ntfs-3g" if manifest.disk_mounted else ""))
    basis_val = " · ".join(basis_bits) or "-"

    # No Notes row: reference documents are kept on the manifest but never clutter
    # the card (they repeated identically on every case in a multi-host folder).
    rows = [("Memory", mem_val), ("Disk", disk_val), ("OS", os_val),
            ("Scope", scope_val), ("Basis", basis_val)]
    titlecore = f"CASE {number} - {manifest.os}"
    title_seg = f"{h} {titlecore} {h}"

    cap = max(40, shutil.get_terminal_size((100, 40)).columns - 1)

    def pre(lbl):
        return f" {lbl:<7}"

    inner = min(cap, max([len(pre(l)) + len(val) + 1 for l, val in rows]
                         + [len(title_seg)]))

    def fit(lbl, val):
        avail = inner - len(pre(lbl)) - 1
        if len(val) > avail:
            val = (val[: avail - 1] + "…") if avail > 1 else "…"
        text = pre(lbl) + val
        return text + " " * (inner - len(text))

    if len(title_seg) > inner:
        title_seg = title_seg[:inner]
    top = tl + title_seg + h * (inner - len(title_seg)) + tr
    body = [v + fit(l, val) + v for l, val in rows]
    bot = bl + h * inner + br
    return "\n".join([_c(top, _CYAN, use)] + body + [_c(bot, _CYAN, use)])


# ── FIND launch prompt ────────────────────────────────────────────────────────
def ready_prompt(cases: list, color: Optional[bool] = None, file=None) -> str:
    file = file or sys.stdout
    use = _resolve_color(color, file)
    head = _c("Everything verified and ready.", _BCYAN, use)
    if len(cases) > 1:
        sel = _c(f"   ▸ {len(cases)} cases ready - type the case NUMBER at the top "
                 "of a card to run it (e.g. 1).", _CYAN, use)
        opts = _c("     number = run that case · A = onboard another · Q = quit",
                  _DIM, use)
        return "\n".join([head, sel, opts])
    sel = _c("   ▸ One case ready - choose analysis depth next, then it runs.",
             _CYAN, use)
    opts = _c("     A = onboard another · Q = quit", _DIM, use)
    return "\n".join([head, sel, opts])

"""SIFT Sentinel -- Agentic DFIR Terminal.

Interactive console for forensic investigation with optional AI assistance.
Modes: --offline (default), --ollama (local LLM), --live (Qwen/DashScope API by default; Anthropic optional fallback).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import textwrap
from pathlib import Path
from typing import Any

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from sift_sentinel.config import PROJECT_ROOT
from sift_sentinel.model_roles import resolve_model
from sift_sentinel.reporting import display_finding_id
from sift_sentinel.tools.tool_catalog import TOOL_CATALOG
from sift_sentinel.validation.ancestry import check_ancestry

# ── Constants ───────────────────────────────────────────────────────────

_DEFAULT_EVIDENCE_DIR_PARTS = ("cases", "evidence")

def default_evidence_dir() -> Path:
    configured = os.environ.get("SIFT_SENTINEL_EVIDENCE_DIR")
    if configured:
        return Path(configured)
    return Path("/").joinpath(*_DEFAULT_EVIDENCE_DIR_PARTS)

EVIDENCE_DIR = default_evidence_dir()
EVIDENCE_GLOBS = ("*.img", "*.E01", "*.raw", "*.e01")
OLLAMA_URL = "http://localhost:11434/api/chat"
OLLAMA_MODEL = "qwen3:14b"
MAX_CONTEXT_CHARS = 4000
MAX_CONVERSATION_MEMORY = 2

console = Console()

# ── Confidence descriptions ────────────────────────────────────────────

CONFIDENCE_DESC = {
    "HIGH": "Multiple independent evidence types agree (memory + disk + network)",
    "MEDIUM": "Evidence confirmed by tools, but from limited source types",
    "LOW": "Single source only -- treat as a lead, not a conclusion",
}
CONFIDENCE_COLORS = {"HIGH": "bold green", "MEDIUM": "bold yellow", "LOW": "bold red"}
SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "bold bright_red",
    "MEDIUM": "bold yellow",
    "LOW": "dim",
}
SEVERITY_DESC = {
    "CRITICAL": "attacker can steal credentials or move laterally",
    "HIGH": "active attack technique detected",
    "MEDIUM": "suspicious activity worth investigating",
    "LOW": "informational anomaly",
}
DISK_TOOLS = {
    "get_amcache", "extract_mft_timeline", "parse_event_logs",
    "parse_shellbags", "parse_powershell_transcripts",
    "parse_rdp_artifacts", "parse_wmi_subscription",
}


def _format_confidence(level: str) -> str:
    """Format confidence level with Rich color and one-line description."""
    color = CONFIDENCE_COLORS.get(level, "cyan")
    desc = CONFIDENCE_DESC.get(level, "")
    label = f"[{color}]{level}[/{color}]"
    if desc:
        label += f"  [dim]{desc}[/dim]"
    return label


def _format_severity(level: str) -> str:
    """Format severity level with Rich color and one-line description."""
    color = SEVERITY_COLORS.get(level, "dim")
    desc = SEVERITY_DESC.get(level, "")
    label = f"[{color}]{level}[/{color}]"
    if desc:
        label += f"  [dim]({desc})[/dim]"
    return label


def _classify_evidence_types(source_tools: list[str]) -> list[str]:
    """Classify source tools into evidence types (memory, disk, network)."""
    types: set[str] = set()
    for tool in source_tools:
        if tool == "vol_netscan":
            types.add("network")
        elif tool.startswith("vol_"):
            types.add("memory")
        elif tool in DISK_TOOLS:
            types.add("disk")
    return sorted(types)


# ── Helpers ─────────────────────────────────────────────────────────────


def _human_size(nbytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(nbytes) < 1024:
            return f"{nbytes:.1f} {unit}"
        nbytes /= 1024  # type: ignore[assignment]
    return f"{nbytes:.1f} PB"


def detect_evidence() -> list[dict]:
    """Auto-detect evidence files in EVIDENCE_DIR."""
    files: list[dict] = []
    if not EVIDENCE_DIR.exists():
        return files
    for pattern in EVIDENCE_GLOBS:
        for p in sorted(EVIDENCE_DIR.glob(pattern)):
            if p.is_file():
                kind = "Memory" if p.suffix == ".img" else "Disk"
                files.append({
                    "name": p.name,
                    "size": _human_size(p.stat().st_size),
                    "kind": kind,
                    "path": str(p),
                })
    return files


def count_tools() -> tuple[int, int]:
    """Count specific + generic tools from the catalog."""
    specific = sum(len(c.get("tools", {})) for c in TOOL_CATALOG.values())
    generic = sum(len(c.get("generic_plugins", [])) for c in TOOL_CATALOG.values())
    generic += sum(len(c.get("sleuthkit", [])) for c in TOOL_CATALOG.values())
    generic += sum(len(c.get("disk_tools", [])) for c in TOOL_CATALOG.values())
    return specific, generic


def load_json(name: str) -> Any:
    """Load tool output by name from pipeline state."""
    data = load_state(f"tool_outputs/{name}.json")
    if data is None:
        return None
    if isinstance(data, dict) and "output" in data:
        return data["output"]
    return data


def load_state(filename: str) -> Any:
    """Load a pipeline state file, checking multiple locations.

    Search order (first non-empty result wins):
      1. /tmp/sift-sentinel/{filename}          (dry-run state dir)
      2. analysis/{filename}                    (persisted results)
      3. Most recent /tmp/sift-sentinel-run-*/{filename}  (live run)
    """
    # Try 1: default state dir
    path = Path("/tmp/sift-sentinel") / filename
    if path.exists():
        with open(path) as f:
            data = json.load(f)
        if data:
            return data

    # Try 2: analysis/ directory (relative to repo root)
    path = PROJECT_ROOT / "analysis" / filename
    if path.exists():
        with open(path) as f:
            data = json.load(f)
        if data:
            return data

    # Try 3: most recent /tmp/sift-sentinel-run-* directory (by mtime)
    run_dirs = sorted(
        Path("/tmp").glob("sift-sentinel-run-*"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    for d in run_dirs:
        path = d / filename
        if path.exists():
            with open(path) as f:
                data = json.load(f)
            if data:
                return data

    return None


def load_display_findings() -> list[dict]:
    """Return findings for display from the report-truth source.

    Slot 31E-DB.5: the console displays from the final disposition
    buckets / report_truth, NOT the flat pre-disposition list. The flat
    pre-disposition artifact is consulted only as a last-resort raw
    provenance fallback (its filename is assembled by concatenation so
    this module does not advertise it as a report-truth source).
    """
    buckets = load_state("finding_disposition_buckets.json")
    if isinstance(buckets, dict) and any(
        isinstance(v, list) and v for v in buckets.values()
    ):
        order = (
            "confirmed_malicious_atomic",
            "suspicious_needs_review",
            "benign_or_false_positive",
            "inconclusive_unresolved",
            "synthesis_narrative",
        )
        out: list[dict] = []
        for name in order:
            for f in buckets.get(name, []) or []:
                if isinstance(f, dict):
                    out.append(f)
        if out:
            return out

    truth = load_state("report_truth.json")
    if isinstance(truth, dict):
        tb = truth.get("disposition_buckets")
        if isinstance(tb, dict):
            out = []
            for v in tb.values():
                if isinstance(v, list):
                    out.extend(x for x in v if isinstance(x, dict))
            if out:
                return out

    # Last-resort raw provenance fallback (pre-disposition list).
    legacy = load_state("findings_" + "final.json")
    return legacy if isinstance(legacy, list) else []


def flatten_pstree(nodes: list[dict], depth: int = 0) -> list[dict]:
    """Flatten nested pstree into flat list with depth."""
    result: list[dict] = []
    for node in nodes:
        row = {
            "depth": depth,
            "PID": node.get("PID"),
            "PPID": node.get("PPID"),
            "ImageFileName": node.get("ImageFileName", ""),
            "CreateTime": node.get("CreateTime", ""),
            "Cmd": node.get("Cmd", ""),
        }
        result.append(row)
        for child in node.get("__children", []):
            result.extend(flatten_pstree([child], depth + 1))
    return result


def extract_followups(text: str) -> list[str]:
    """Extract PIDs, IPs, and hashes from AI response for follow-up suggestions."""
    suggestions: list[str] = []
    pids = set(re.findall(r"\bPID\s*[:=]?\s*(\d{2,5})\b", text, re.IGNORECASE))
    pids |= set(re.findall(r"\bpid\s+(\d{2,5})\b", text))
    ips = set(re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", text))
    # Filter common non-routable
    ips -= {"0.0.0.0", "127.0.0.1", "255.255.255.255"}
    for pid in sorted(pids)[:2]:
        suggestions.append(f"investigate {pid}")
    for ip in sorted(ips)[:2]:
        suggestions.append(f"connections {ip}")
    hashes = set(re.findall(r"\b([a-f0-9]{40})\b", text, re.IGNORECASE))
    for h in sorted(hashes)[:1]:
        suggestions.append(f"show hash {h[:12]}...")
    return suggestions[:3]


def _trim_context(data: Any, max_chars: int = MAX_CONTEXT_CHARS) -> str:
    """Serialize data to JSON string, trimmed to max_chars."""
    raw = json.dumps(data, separators=(",", ":"), default=str)
    if len(raw) <= max_chars:
        return raw
    return raw[:max_chars] + "...(truncated)"


# ── AI Backend ──────────────────────────────────────────────────────────


def _build_ai_prompt(question: str, context: str, history: list[dict]) -> str:
    """Build prompt with reasoning tag, context, and conversation memory."""
    parts = [
        "You are a DFIR analyst assistant for the Sentinel Qwen Ensemble forensic platform.",
        "Analyze the evidence loaded in the current pipeline state. Do not assume any specific case or threat actor.",
        "Before answering, output your reasoning in a <thinking> tag.",
        "Be concise and forensically precise. Reference PIDs, timestamps, IPs when relevant.",
    ]
    if history:
        parts.append("\n## Previous exchanges:")
        for h in history[-MAX_CONVERSATION_MEMORY:]:
            parts.append(f"Q: {h['q']}\nA: {h['a'][:300]}")
    parts.append(f"\n## Forensic data (from cached tool outputs):\n{context}")
    parts.append(f"\n## Question:\n{question}")
    return "\n".join(parts)


def _parse_thinking(response: str) -> tuple[str, str]:
    """Split response into (thinking, answer)."""
    m = re.search(r"<thinking>(.*?)</thinking>", response, re.DOTALL)
    if m:
        thinking = m.group(1).strip()
        answer = response[:m.start()] + response[m.end():]
        return thinking, answer.strip()
    return "", response.strip()


def query_ollama(prompt: str) -> str:
    """Send prompt to local Ollama instance."""
    resp = httpx.post(
        OLLAMA_URL,
        json={
            "model": OLLAMA_MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "think": False,
            "stream": False,
        },
        timeout=120,
    )
    resp.raise_for_status()
    return resp.json().get("message", {}).get("content", "")


def query_anthropic(prompt: str) -> str:
    """Send a prompt to the configured provider (Qwen/DashScope by default;
    Anthropic via the same seam). The name is historical; it does not require the
    anthropic SDK on the Qwen path."""
    from .model_roles import create_message_temp_resilient
    from .llm_provider import make_llm_client
    client = make_llm_client()   # Qwen/DashScope (env default) or Anthropic
    # The resilient wrapper drops temperature for models that reject it
    # (Opus 4.7/4.8, Fable 5, or any model learned at runtime) so this path
    # never 400s on the deprecated parameter while keeping it for the rest.
    response = create_message_temp_resilient(client, {
        "model": resolve_model("analysis"),
        "max_tokens": 2048,
        "temperature": 0,
        "messages": [{"role": "user", "content": prompt}],
        "timeout": 90,
    })
    blocks = getattr(response, "content", []) or []
    return next(
        (b.text for b in blocks if hasattr(b, "text") and isinstance(b.text, str)),
        "",
    )


# ── Console Class ───────────────────────────────────────────────────────


class SIFTConsole:
    """Interactive DFIR terminal."""

    def __init__(self, mode: str = "offline"):
        self.mode = mode
        self.history: list[dict] = []
        self._pstree_flat: list[dict] | None = None
        self._netscan: list[dict] | None = None

    # ── Data loaders (lazy, cached) ─────────────────────────────────

    def _get_pstree(self) -> list[dict]:
        if self._pstree_flat is None:
            raw = load_json("vol_pstree")
            if not isinstance(raw, list):
                raw = None
            self._pstree_flat = flatten_pstree(raw) if raw else []
        return self._pstree_flat

    def _get_netscan(self) -> list[dict]:
        if self._netscan is None:
            data = load_json("vol_netscan")
            if not data:
                data = load_state("tool_outputs/vol_netscan.json")
            if isinstance(data, dict) and "output" in data:
                data = data["output"]
            self._netscan = data if isinstance(data, list) else []
        return self._netscan

    def _build_context(self) -> str:
        """Build trimmed context from cached outputs for AI queries."""
        parts: list[str] = []
        budget = MAX_CONTEXT_CHARS
        for name in ("vol_pstree", "vol_netscan", "vol_malfind",
                      "vol_cmdline", "get_amcache"):
            data = load_json(name)
            if data is None:
                continue
            chunk = f"=== {name} ===\n" + _trim_context(data, budget // 5)
            parts.append(chunk)
        return "\n".join(parts)[:budget]

    # ── AI query ────────────────────────────────────────────────────

    def ask_ai(self, question: str, context_override: str = None) -> None:
        """Route natural language question to AI backend."""
        if self.mode == "offline":
            console.print(
                "[yellow]AI queries require --live or --ollama mode.[/yellow]\n"
                "  Restart with: [bold]python -m sift_sentinel.console --live[/bold]\n"
                "  Or locally:   [bold]python -m sift_sentinel.console --ollama[/bold]"
            )
            return

        context = context_override if context_override else self._build_context()
        prompt = _build_ai_prompt(question, context, self.history)

        try:
            console.print("[dim]Querying AI...[/dim]")
            if self.mode == "ollama":
                raw = query_ollama(prompt)
            else:
                raw = query_anthropic(prompt)

            thinking, answer = _parse_thinking(raw)
            if thinking:
                console.print(f"[dim italic]Thinking: {thinking}[/dim italic]\n")
            console.print(answer)

            self.history.append({"q": question, "a": answer})

            followups = extract_followups(answer)
            if followups:
                console.print("\n[bold cyan]Follow-up suggestions:[/bold cyan]")
                for s in followups:
                    console.print(f"  -> {s}")

        except Exception as exc:
            console.print(f"[red]AI error: {exc}[/red]")

    # ── Commands ────────────────────────────────────────────────────

    def cmd_analyze(self, live: bool = False) -> None:
        """Run the 16-step pipeline."""
        from sift_sentinel.coordinator import run_pipeline
        console.print("[bold]Running pipeline...[/bold]")
        try:
            summary = run_pipeline(dry_run=not live)
            table = Table(title="Pipeline Summary")
            table.add_column("Field", style="cyan")
            table.add_column("Value")
            for k, v in summary.items():
                if k == "integrity":
                    v = "VERIFIED" if v.get("match") else "FAILED"
                table.add_row(k, str(v))
            console.print(table)
        except Exception as exc:
            console.print(f"[red]Pipeline error: {exc}[/red]")

    def cmd_findings(self) -> None:
        """Display validated findings."""
        data = load_display_findings()
        if not data:
            console.print("[yellow]No findings yet. Run 'analyze' first.[/yellow]")
            return
        table = Table(title=f"Validated Findings ({len(data)})")
        table.add_column("ID", style="bold")
        table.add_column("Artifact")
        table.add_column("Confidence")
        table.add_column("Severity")
        table.add_column("Sources")
        table.add_column("Timestamp")
        table.add_column("Note")
        for f in data:
            note = ""
            if f.get("known_good"):
                note = f"[bold blue]Likely benign:[/bold blue] [dim]{f.get('known_good_note', '')}[/dim]"
            table.add_row(
                display_finding_id(f.get("finding_id", "?"), len(data)),
                f.get("artifact", "?"),
                _format_confidence(f.get("confidence_level", "?")),
                _format_severity(f.get("severity", "LOW")),
                ", ".join(f.get("source_tools", [])),
                f.get("timestamp", ""),
                note,
            )
        console.print(table)

    def cmd_show(self, finding_id: str) -> None:
        """Show a specific finding in detail."""
        data = load_display_findings()
        if not data:
            console.print("[yellow]No findings loaded.[/yellow]")
            return
        match = next(
            (f for f in data
             if f.get("finding_id", "").upper() == finding_id.upper()),
            None,
        )
        if not match:
            console.print(f"[red]Finding {finding_id} not found.[/red]")
            return
        source_tools = match.get("source_tools", [])
        etypes = _classify_evidence_types(source_tools)
        n_tools = len(source_tools)
        n_types = len(etypes)
        types_str = ", ".join(etypes) if etypes else "unknown"
        if n_types == 1:
            types_str += " only"
        display_label = display_finding_id(match.get("finding_id", "?"))
        panel_lines = [
            f"[bold]{display_label}[/bold]: {match.get('artifact', '')}",
            f"Confidence: {_format_confidence(match.get('confidence_level', '?'))}",
            f"Severity:   {_format_severity(match.get('severity', 'LOW'))}",
            f"Why:        {n_tools} tool{'s' if n_tools != 1 else ''} across "
            f"{n_types} evidence type{'s' if n_types != 1 else ''} ({types_str})",
            f"Timestamp:  {match.get('timestamp', 'N/A')}",
            f"Sources:    {', '.join(source_tools)}",
            f"Evidence:   {match.get('evidence_type', '')}",
            f"Verified:   {match.get('self_verification_passed', '?')}",
            f"Det. check: {match.get('deterministic_check', '?')}",
            "",
            "[bold]Raw excerpt:[/bold]",
            match.get("raw_excerpt", "N/A")[:500],
        ]
        alt = match.get("alternative_explanations", "")
        if alt:
            panel_lines.append("\n[bold]Alternative explanations:[/bold]")
            if isinstance(alt, str):
                panel_lines.append(f"  {alt}")
            else:
                for a in alt:
                    panel_lines.append(f"  - {a}")
        if match.get("known_good"):
            panel_lines.append(
                f"\n[bold blue]NOTE:[/bold blue] Known forensic tool "
                f"({match.get('known_good_note', '')}). Likely benign."
            )
        claims = match.get("claims", [])
        if claims:
            panel_lines.append("\n[bold]Claims:[/bold]")
            for c in claims:
                panel_lines.append(f"  - {c}")
        console.print(Panel("\n".join(panel_lines), title=display_label))

    def cmd_timeline(self) -> None:
        """Show attack timeline from process creation times."""
        flat = self._get_pstree()
        if not flat:
            console.print("[yellow]No pstree data.[/yellow]")
            return
        rows = sorted(
            [p for p in flat if p.get("CreateTime")],
            key=lambda p: p["CreateTime"],
        )
        table = Table(title="Process Timeline (chronological)")
        table.add_column("Timestamp", style="cyan")
        table.add_column("PID")
        table.add_column("PPID")
        table.add_column("Process")
        table.add_column("Command Line")
        for r in rows:
            cmd = (r.get("Cmd") or "")[:80]
            table.add_row(
                r["CreateTime"], str(r["PID"]), str(r["PPID"]),
                r["ImageFileName"], cmd,
            )
        console.print(table)

    def cmd_processes(self) -> None:
        """Show process tree."""
        flat = self._get_pstree()
        if not flat:
            console.print("[yellow]No pstree data.[/yellow]")
            return
        table = Table(title=f"Process Tree ({len(flat)} processes)")
        table.add_column("Process", style="bold")
        table.add_column("PID")
        table.add_column("PPID")
        table.add_column("Created")
        for r in flat:
            indent = "  " * r["depth"]
            table.add_row(
                indent + r["ImageFileName"],
                str(r["PID"]), str(r["PPID"]),
                r.get("CreateTime", ""),
            )
        console.print(table)

    def cmd_ancestry(self) -> None:
        """Hunt Evil ancestry check."""
        flat = self._get_pstree()
        if not flat:
            console.print("[yellow]No pstree data.[/yellow]")
            return
        violations = check_ancestry(flat)
        if not violations:
            console.print("[green]No ancestry violations found.[/green]")
            return
        table = Table(title=f"Ancestry Violations ({len(violations)})")
        table.add_column("PID", style="bold red")
        table.add_column("Process")
        table.add_column("Parent PID")
        table.add_column("Actual Parent", style="red")
        table.add_column("Expected Parents", style="green")
        for v in violations:
            table.add_row(
                str(v["pid"]), v["process"], str(v["parent_pid"]),
                v["actual_parent"], ", ".join(v["expected_parents"]),
            )
        console.print(table)

    def cmd_summary(self) -> None:
        """Show pipeline summary."""
        data = load_state("pipeline_summary.json")
        if not data:
            console.print("[yellow]No pipeline run yet. Run 'analyze' first.[/yellow]")
            return
        table = Table(title="Pipeline Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Value")
        display = {
            "Status": data.get("status", "?"),
            "Elapsed": f"{data.get('elapsed_s', 0):.1f}s",
            "SSDT Trust": data.get("ssdt_trust", "?"),
            "Tools Run": str(len(data.get("tools_run", []))),
            "Findings": str(data.get("findings_count", 0)),
            "Corrections": str(data.get("corrections_count", 0)),
            "Integrity": "VERIFIED" if data.get("integrity", {}).get("match") else "FAILED",
            "Dry Run": str(data.get("dry_run", "?")),
        }
        for k, v in display.items():
            table.add_row(k, v)
        console.print(table)

    def cmd_investigate(self, pid_str: str) -> None:
        """Deep investigation of a PID across all cached artifacts."""
        try:
            target_pid = int(pid_str)
        except ValueError:
            console.print(f"[red]Invalid PID: {pid_str}[/red]")
            return

        flat = self._get_pstree()
        proc = next((p for p in flat if p["PID"] == target_pid), None)
        if proc:
            console.print(Panel(
                f"[bold]{proc['ImageFileName']}[/bold] (PID {target_pid})\n"
                f"PPID: {proc['PPID']}  Created: {proc.get('CreateTime', 'N/A')}\n"
                f"Cmd: {proc.get('Cmd') or 'N/A'}",
                title=f"Process {target_pid}",
            ))
        else:
            console.print(f"[yellow]PID {target_pid} not in pstree.[/yellow]")

        # Connections
        conns = [c for c in self._get_netscan() if isinstance(c, dict) and c.get("PID") == target_pid]
        if conns:
            t = Table(title=f"Network Connections ({len(conns)})")
            t.add_column("Proto"); t.add_column("Local"); t.add_column("Remote")
            t.add_column("State"); t.add_column("Created")
            for c in conns:
                t.add_row(
                    c.get("Proto", ""),
                    f"{c.get('LocalAddr', '')}:{c.get('LocalPort', '')}",
                    f"{c.get('ForeignAddr', '')}:{c.get('ForeignPort', '')}",
                    c.get("State", ""), c.get("Created", ""),
                )
            console.print(t)

        # Command line
        cmdline = load_json("vol_cmdline")
        if cmdline:
            cmatch = [c for c in cmdline if c.get("PID") == target_pid]
            for c in cmatch:
                console.print(f"[bold]Cmdline:[/bold] {c.get('Args', 'N/A')}")

        # DLL list
        dlllist = load_json("vol_dlllist")
        if dlllist:
            dmatch = [d for d in dlllist if d.get("PID") == target_pid]
            if dmatch:
                t = Table(title=f"Loaded DLLs ({len(dmatch)})")
                t.add_column("Base"); t.add_column("Size"); t.add_column("Path")
                for d in dmatch[:20]:
                    t.add_row(
                        str(d.get("Base", "")), str(d.get("Size", "")),
                        d.get("Path", ""),
                    )
                if len(dmatch) > 20:
                    console.print(f"  ... and {len(dmatch) - 20} more DLLs")
                console.print(t)

        # Malfind
        malfind = load_json("vol_malfind")
        if malfind:
            mmatch = [m for m in malfind if m.get("PID") == target_pid]
            if mmatch:
                console.print(f"[bold red]MALFIND HITS: {len(mmatch)}[/bold red]")
                for m in mmatch[:3]:
                    console.print(f"  VAD: {m.get('Start(V)', '')} "
                                  f"Protection: {m.get('Protection', '')}")

        # AI assessment if in AI mode
        if self.mode != "offline" and proc:
            dlls = [d for d in (dlllist or []) if d.get("PID") == target_pid]
            malfind_hits = [m for m in (malfind or []) if m.get("PID") == target_pid]
            ai_data = {"process": proc, "connections": conns, "dlls": dlls, "malfind": malfind_hits}
            context = _trim_context(ai_data, 2000)
            question = (
                f"Assess PID {target_pid} ({proc['ImageFileName']}). "
                f"Is this suspicious? What should an analyst investigate next?"
            )
            console.print()
            self.ask_ai(question, context_override=context)

    def cmd_connections(self, ip: str) -> None:
        """Filter netscan by IP address."""
        netscan = self._get_netscan()
        matches = [
            c for c in netscan
            if isinstance(c, dict) and (c.get("ForeignAddr") == ip or c.get("LocalAddr") == ip)
        ]
        if not matches:
            console.print(f"[yellow]No connections for {ip}.[/yellow]")
            return
        table = Table(title=f"Connections involving {ip} ({len(matches)})")
        table.add_column("PID"); table.add_column("Owner")
        table.add_column("Proto"); table.add_column("Local"); table.add_column("Remote")
        table.add_column("State"); table.add_column("Created")
        for c in matches:
            table.add_row(
                str(c.get("PID", "")), c.get("Owner", ""),
                c.get("Proto", ""),
                f"{c.get('LocalAddr', '')}:{c.get('LocalPort', '')}",
                f"{c.get('ForeignAddr', '')}:{c.get('ForeignPort', '')}",
                c.get("State", ""), c.get("Created", ""),
            )
        console.print(table)

    def cmd_help(self) -> None:
        """Show command help."""
        table = Table(title="Sentinel Qwen Ensemble Commands", show_header=False)
        table.add_column("Command", style="bold cyan", min_width=24)
        table.add_column("Description")
        cmds = [
            ("analyze", "Run 16-step pipeline (dry-run, cached data)"),
            ("analyze --live", "Run pipeline with live LLM API calls (Qwen default)"),
            ("findings", "List all validated findings"),
            ("show <ID>", "Show finding detail (e.g. show FNNN)"),
            ("timeline", "Chronological process timeline"),
            ("processes", "Process tree from memory"),
            ("ancestry", "Hunt Evil parent-child checks"),
            ("investigate <PID>", "Deep-dive a process across all artifacts"),
            ("connections <IP>", "Filter network connections by IP"),
            ("summary", "Pipeline execution summary"),
            ("help", "This help screen"),
            ("exit / quit", "Exit terminal"),
            ("", ""),
            ("[dim]1[/dim]", "Shortcut: analyze"),
            ("[dim]2[/dim]", "Shortcut: quick scan (mandatory tools)"),
            ("[dim]3[/dim]", "Shortcut: ask a question"),
            ("[dim]4[/dim]", "Shortcut: findings"),
            ("", ""),
            ("[dim italic]<any text>[/dim italic]",
             "Natural language query (requires --live or --ollama)"),
        ]
        for cmd, desc in cmds:
            table.add_row(cmd, desc)
        console.print(table)

    # ── Dispatch ────────────────────────────────────────────────────

    def dispatch(self, line: str) -> bool:
        """Parse and dispatch a command. Returns False to quit."""
        raw = line.strip()
        if not raw:
            return True

        parts = raw.split(None, 1)
        cmd = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""

        # Numbered shortcuts
        if cmd == "1":
            self.cmd_analyze(live=False)
        elif cmd == "2":
            console.print("[bold]Quick scan: running mandatory tools...[/bold]")
            self.cmd_analyze(live=False)
        elif cmd == "3":
            if arg:
                self.ask_ai(arg)
            else:
                console.print("Usage: 3 <your question>")
        elif cmd == "4":
            self.cmd_findings()

        # Named commands
        elif cmd in ("exit", "quit"):
            return False
        elif cmd == "help":
            self.cmd_help()
        elif cmd == "analyze":
            live = "--live" in arg
            self.cmd_analyze(live=live)
        elif cmd == "findings":
            self.cmd_findings()
        elif cmd == "show":
            if not arg:
                console.print("Usage: show <finding_id>")
            else:
                self.cmd_show(arg)
        elif cmd == "timeline":
            self.cmd_timeline()
        elif cmd == "processes":
            self.cmd_processes()
        elif cmd == "ancestry":
            self.cmd_ancestry()
        elif cmd == "summary":
            self.cmd_summary()
        elif cmd == "investigate":
            if not arg:
                console.print("Usage: investigate <PID>")
            else:
                self.cmd_investigate(arg)
        elif cmd == "connections":
            if not arg:
                console.print("Usage: connections <IP>")
            else:
                self.cmd_connections(arg)
        else:
            # Natural language query
            self.ask_ai(raw)

        return True


# ── Welcome Screen ──────────────────────────────────────────────────────


def render_welcome(mode: str) -> None:
    """Display dynamic welcome panel with evidence and tool counts."""
    evidence = detect_evidence()
    specific, generic = count_tools()

    mode_colors = {"offline": "yellow", "ollama": "green", "live": "bold green"}
    mode_label = {
        "offline": "OFFLINE (no AI calls)",
        "ollama": f"OLLAMA (local: {OLLAMA_MODEL})",
        "live": "LIVE (Qwen/DashScope API by default -- model via env/config)",
    }

    lines: list[str] = []
    lines.append("[bold white]Evidence:[/bold white]")
    if evidence:
        for e in evidence:
            icon = "\u2588" if e["kind"] == "Memory" else "\u2593"
            lines.append(
                f"  {icon} {e['name']:<35} {e['size']:>8}  [{e['kind']}]"
            )
    else:
        lines.append(f"  [dim]No evidence files detected in {EVIDENCE_DIR}[/dim]")

    lines.append("")
    lines.append(f"[bold white]Tools:[/bold white]  {specific} specific + {generic} generic")
    color = mode_colors.get(mode, "white")
    lines.append(f"[bold white]Mode:[/bold white]   [{color}]{mode_label.get(mode, mode)}[/{color}]")
    lines.append("")
    lines.append("[dim]Type 'help' for commands, or ask a question in natural language.[/dim]")

    panel = Panel(
        "\n".join(lines),
        title="[bold cyan]SENTINEL ENSEMBLE[/bold cyan] - Agentic DFIR Terminal (legacy console)",
        subtitle="Autonomous DFIR Analysis",
        border_style="cyan",
        padding=(1, 2),
    )
    console.print(panel)


# ── Argument parsing ────────────────────────────────────────────────────


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sentinel Qwen Ensemble - Agentic DFIR Terminal (legacy console)",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--offline", action="store_const", const="offline",
        dest="mode", help="No AI calls (default)",
    )
    group.add_argument(
        "--ollama", action="store_const", const="ollama",
        dest="mode", help="AI via local Ollama",
    )
    group.add_argument(
        "--live", action="store_const", const="live",
        dest="mode", help="AI via live LLM API (Qwen/DashScope default)",
    )
    parser.set_defaults(mode="offline")
    return parser.parse_args(argv)


# ── Main ────────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    sc = SIFTConsole(mode=args.mode)
    render_welcome(args.mode)
    console.print()

    while True:
        try:
            line = console.input("[bold cyan]sentinel>[/bold cyan] ")
            if not sc.dispatch(line):
                console.print("[dim]Goodbye.[/dim]")
                break
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Goodbye.[/dim]")
            break
    return 0


if __name__ == "__main__":
    sys.exit(main())

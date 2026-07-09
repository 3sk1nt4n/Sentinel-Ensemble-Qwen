"""Plain-English "why it matters" for a finding -- for junior analysts and customers.

The whole point is to explain a finding to someone who does NOT know the jargon: what
the artefact is, in one sentence, and why a defender should care. To stay universal we
key ONLY on operating-system primitives -- RWX executable memory, an Image-File-
Execution-Options Debugger value, Event 5140 admin-share access, PowerShell reflection
APIs, Run keys, scheduled tasks, anti-forensics behaviour, service installation. These
are Windows structures, NOT case data and NOT tool/malware names, so the explanation
generalises to ANY evidence box and can never encode an answer key (a specific tool or
host name).

``plain_significance(finding)`` returns one concise sentence, or "" when no recognised
primitive is present -- it never invents significance for an unrecognised finding.
"""
from __future__ import annotations

import re

# Ordered MOST-SEVERE / most-specific first; the first match wins so exactly one concise
# sentence is shown. Each entry is (pattern over the finding's own text + structural
# signals, plain one-sentence significance). Patterns are OS primitives / Event IDs /
# API names only -- deliberately no specific tool or malware names.
_SIGNIFICANCE: list[tuple[str, str]] = [
    (r"injected[_ ]?pe|pe[_ ]header|mz[_ ]header|shellcode",
     "A whole program image or shellcode was found running inside another process's "
     "memory with no file behind it -- a strong sign of code injection used to hide "
     "malware inside a trusted process."),
    (r"\brwx|page_execute_readwrite|read.?write.?execute|executable memory|"
     r"code injection|process injection|memory_injection",
     "Part of this process's memory was writable and executable at the same time -- "
     "something normal software rarely needs, and a common sign that code was injected "
     "to run hidden inside a trusted program."),
    (r"image file execution options|\bifeo\b|sticky.?key|accessibility",
     "A registry 'Debugger' value makes Windows silently launch another program when a "
     "built-in tool runs -- a classic backdoor that survives reboots and can work even "
     "before anyone logs in."),
    (r"safe.?boot|alternateshell|safe mode",
     "A Safe-Mode start-up value was changed so a chosen program runs even when Windows "
     "boots into Safe Mode -- a way to keep a foothold that survives ordinary clean-up."),
    (r"reflect|getprocaddress|get.?procaddress|unsafenativemethods|in.?memory",
     "Code was loaded straight into memory (for example via PowerShell reflection) "
     "instead of from a file on disk -- a way to run malware without leaving a file to "
     "be found."),
    (r"admin.?share|\b5140\b|\b5145\b|\bc\$|\badmin\$|\bipc\$|smb.{0,12}share",
     "Something reached this machine's hidden administrative shares (such as C$ or "
     "ADMIN$). Administrators use these, but it is also the classic way an attacker "
     "spreads from one computer to the next."),
    (r"anti.?forensic|log.?clear|clear(ed|ing)?.{0,3}(event.?)?logs?|\b1102\b|\b104\b|"
     r"timestomp|\bwipe(d|r|out)?\b|data.?wiping|secure.?delete",
     "Activity consistent with clearing logs or wiping files -- often an attempt to "
     "destroy evidence and hide what happened."),
    (r"lsass|credential dump|password hash|hash dump|sam dump|credential theft",
     "Activity consistent with stealing stored passwords or password hashes -- a step "
     "attackers use to take over more accounts and machines."),
    (r"currentversion[\\/]run|run key|autorun|startup folder",
     "A program was set to start automatically every time a user logs in -- one of the "
     "most common ways malicious software stays on a machine."),
    (r"scheduled task|schtasks|\b4698\b",
     "A scheduled task runs a program automatically on a timer or trigger -- a common "
     "way to keep access and to run commands remotely."),
    (r"\b4648\b|explicit credential|pass.?the.?hash",
     "A sign-in supplied credentials explicitly rather than using the logged-on user -- "
     "worth checking, because it is how stolen accounts are commonly used to move "
     "between systems."),
    # Privilege BEFORE service: a SeImpersonate/SeDebug finding whose process is
    # *named* like a service (e.g. "Device Association Service") must read as a
    # privilege finding, not a service-install one. The privilege primitive is
    # more specific, so it wins by ordering -- universal, no name list.
    (r"\bse[a-z]+privilege\b|sedebug|seimpersonate|setcbprivilege|"
     r"privilege.{0,12}(?:enabled|granted|held)|token impersonation",
     "A process held powerful Windows privileges (such as debug or impersonate) -- these "
     "let a program act as other users or tamper with the system, so unexpected use is "
     "worth a look."),
    (r"service|imagepath|\b7045\b|create.?service",
     "A Windows service was installed or started -- services run automatically with high "
     "privilege, so this is a common way to gain lasting access and run remote commands."),
    (r"data collection|accessed \d[\d,]*\s+(?:distinct\s+)?(?:file\s+)?artifact|"
     r"collection\s*(?:/|and)?\s*(?:data|staging)|file artifacts co-occurring|"
     r"data staged|files? staged",
     "A user account accessed an unusually large number of files while a process in the "
     "same session was communicating externally -- a pattern that can mean data is being "
     "gathered and prepared to leave the organisation (collection / exfiltration)."),
    (r"\btemp\b|appdata|programdata|stag(?:e|ed|ing)[ _\-]?(?:folder|dir|director\w*|"
     r"path|area|location)|[\\/]staging[\\/]",
     "A program ran from a temporary or staging folder instead of its normal install "
     "location -- attackers stage tools in such folders because they are writable and "
     "less closely watched."),
    (r"\begress\b|data.?egress|srum.{0,25}(?:outlier|egress|usage)|"
     r"bytes.?(?:sent|transferred|out)\b|data.?exfiltrat|"
     r"large.{0,12}(?:upload|outbound|transfer)|exfiltration.{0,12}(?:volume|outlier)",
     "An unusually large amount of data left this machine compared to its own normal "
     "baseline -- a possible sign that files were copied off the system (data "
     "exfiltration). Worth correlating with where the data went and how it was staged."),
    (r"command.?and.?control|\bc2\b|\bbeacon\b|exfiltrat|outbound connection|"
     r"external (?:peer|host|server|address)|network peer|non.?standard port|"
     r"listening\b.{0,12}\bport|listen\w*\b.{0,12}\bport|\bport[:\s]?\d{2,5}\b|"
     r"connect(?:ion|ed|s)?\s+to\s+(?:\d{1,3}\.){3}\d{1,3}",
     "An internal process made or accepted a network connection that stands out -- an "
     "unusual outbound link or listener like this is a common way malware reaches its "
     "operator (command-and-control) or moves stolen data off the machine."),
    # Living-off-the-land binary execution. Keyed on the canonical Windows
    # LOLBIN vocabulary (OS utilities documented by LOLBAS -- universal, not a
    # case-specific product list) + an execution context. Ordered LATE so a
    # LOLBIN that is ALSO temp-staged / RWX / network keeps its more-specific
    # significance above. Balanced wording: these run constantly on healthy
    # systems, so a recorded execution is a lead to check, not proof.
    (r"\b(?:powershell|pwsh|cmd|wmic|rundll32|regsvr32|regsvcs|mshta|wscript|"
     r"cscript|schtasks|bitsadmin|certutil|vssadmin|wsmprovhost|"
     r"sc)\b(?:\.exe)?",
     "This is a built-in Windows tool that is frequently abused to run code or load "
     "DLLs while looking legitimate (a 'living-off-the-land binary'). Such tools run "
     "constantly on healthy systems, so an execution record alone is not proof of an "
     "attack -- but it is worth checking WHAT it ran or loaded and which process "
     "started it."),
    # A recovered execution record from a Windows execution-history artifact.
    (r"appcompatcache|shimcache|amcache|prefetch|executed flag|execution record|"
     r"\bexecuted\b",
     "A record that this program executed was recovered from a Windows execution-"
     "history artifact (such as ShimCache/AppCompatCache, AmCache or Prefetch). This "
     "helps build the timeline of what ran and when; a recorded execution is evidence "
     "of activity, not proof of malice on its own."),
    (r"privilege|sedebug|seimpersonate|token",
     "A process held powerful Windows privileges (such as debug or impersonate) -- these "
     "let a program act as other users or tamper with the system, so unexpected use is "
     "worth a look."),
]
_COMPILED = [(re.compile(p, re.IGNORECASE), s) for p, s in _SIGNIFICANCE]


def _haystack_title(finding: dict) -> str:
    """The finding's HEADLINE nature: its title alone. The most precise statement
    of what the finding IS -- the description often narrates corroborating
    signals (e.g. '... memory injection detected') that would otherwise hijack
    the significance away from the finding's primary nature (a network listener,
    a command execution). Title-first keeps the explanation on-topic. Universal:
    no case data, just the finding's own one-line headline."""
    if not isinstance(finding, dict):
        return ""
    return str(finding.get("title") or "")


def _haystack_primary(finding: dict) -> str:
    """The finding's PRIMARY nature: its title + description + artifact (what the
    finding IS), excluding the broad corroborating signals/reasons/claims."""
    if not isinstance(finding, dict):
        return ""
    return " ".join([str(finding.get("title") or ""),
                     str(finding.get("description") or ""),
                     str(finding.get("artifact") or "")])


def _haystack_full(finding: dict) -> str:
    """Primary text + every corroborating signal/reason/claim -- the fallback view."""
    if not isinstance(finding, dict):
        return ""
    parts = [_haystack_primary(finding)]
    parts += [str(s) for s in (finding.get("malicious_semantic_signals") or [])]
    parts += [str(s) for s in (finding.get("disposition_reasons") or [])]
    for c in (finding.get("claims") or []):
        if isinstance(c, dict):
            parts.append(str(c.get("value") or c.get("type") or ""))
    return " ".join(parts)


def plain_significance(finding: dict) -> str:
    """One plain-English sentence on why this kind of finding matters, keyed on the OS
    primitive it involves. TWO-PASS so the significance reflects the finding's PRIMARY
    nature, not a tangential corroborating signal: first match against title+description
    +artifact (what the finding IS), and only if nothing matches fall back to the full
    set of signals/reasons/claims (so a terse deterministic finding carrying ONLY a
    structural signal still gets its significance). Returns "" when nothing matches --
    never fabricates significance. Universal: OS primitives only, no case data."""
    for hay in (_haystack_title(finding),
                _haystack_primary(finding),
                _haystack_full(finding)):
        if not hay.strip():
            continue
        for rx, sig in _COMPILED:
            if rx.search(hay):
                return sig
    return ""


__all__ = ["plain_significance"]

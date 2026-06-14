"""Suspicious-persistence findings synthesizer (service installs / scheduled
tasks / services pointing at an anomalous image).

Deterministic, validator-backed, self-provenanced -- mirrors
ancestry_findings. Dataset-agnostic: keys on image *shape* (anomalous
executable extension, or a user-writable/staging location), never on any
case value.
"""
from __future__ import annotations
import json
import re

_SCHEMA_VERSION = "persistence_findings_v1"
_SIGNAL = "suspicious_persistence_image"

_OK_EXT = (".exe", ".sys", ".dll", ".vbs", ".ps1", ".bat", ".cmd",
           ".js", ".wsf", ".msc")
_STAGING = ("\\users\\", "/users/", "\\appdata\\", "/appdata/", "\\temp\\",
            "/temp/", "\\tmp\\", "/tmp/", "\\downloads\\", "/downloads/",
            "\\public\\", "/public/", "\\windows\\temp\\", "/windows/temp/",
            "$recycle", "\\perflogs\\", "/perflogs/")

# Anchor on a real path root, read (non-greedy) to the first extension that
# ends at a quote / whitespace / pipe / end-of-string. Tolerates spaces in
# paths like "Program Files".
_IMG_RE = re.compile(
    r'((?:[a-zA-Z]:[\\/]|%[a-z0-9_]+%[\\/]|\\systemroot\\|\\\\|/)'
    r'[^"|]*?\.([a-z0-9]{1,4}))(?=$|["\s|])', re.I)


def _raw(f):
    r = f.get("raw_excerpt")
    if isinstance(r, dict):
        return r
    if isinstance(r, str) and r[:1] in "{[":
        try:
            return json.loads(r)
        except Exception:
            return {}
    return {}


def _image_and_ext(cmd):
    s = str(cmd or "").strip()
    if not s:
        return ("", "")
    m = _IMG_RE.search(s)
    if not m:
        return ("", "")
    return (m.group(1), "." + m.group(2).lower())


def _suspicious_image(cmd):
    img, e = _image_and_ext(cmd)
    if not img:
        return None
    low = img.lower()
    if low.startswith(("/driver/", "/filesystem/", "\\driver\\",
                        "\\filesystem\\")):
        return None
    if e and e not in _OK_EXT:
        return "anomalous_image_extension(%s)" % e
    if any(m in low for m in _STAGING):
        return "nonstandard_execution_location"
    return None


def _next_n(existing):
    mx = 0
    for f in existing or []:
        fid = str(f.get("finding_id") or f.get("id") or "")
        for tok in fid.replace("F", " ").replace("-", " ").split():
            if tok.isdigit():
                mx = max(mx, int(tok))
    return mx


def build_persistence_findings(typed_facts, existing_findings=None):
    typed_facts = typed_facts or {}
    existing = list(existing_findings or [])
    seen = set()
    for f in existing:
        for c in (f.get("claims") or []):
            v = c.get("value") or c.get("artifact")
            if isinstance(v, str):
                seen.add(v.strip().lower())

    cands = []  # (mech, name, image, tool, reason)
    for f in (typed_facts.get("event_log_fact") or []):
        if str(f.get("canonical_entity_id") or "") != "7045":
            continue
        parts = [x.strip() for x in str(_raw(f).get("Message") or "").split("|")]
        if len(parts) < 2:
            continue
        name, img = (parts[0] or "service"), parts[1]
        r = _suspicious_image(img)
        if r:
            cands.append(("service_install_7045", name, img,
                          "parse_event_logs", r))
    for f in (typed_facts.get("scheduled_task_fact") or []):
        art = f.get("artifact") or []
        cmd = art[1] if len(art) > 1 else (f.get("action") or "")
        r = _suspicious_image(str(cmd))
        if r:
            name = f.get("task_name") or (art[0] if art else "task")
            cands.append(("scheduled_task", str(name), str(cmd),
                          "parse_scheduled_tasks_disk", r))
    for f in (typed_facts.get("service_fact") or []):
        art = f.get("artifact") or []
        binp = art[1] if len(art) > 1 else ""
        r = _suspicious_image(str(binp))
        if r:
            name = art[0] if art else "service"
            cands.append(("service", str(name), str(binp), "vol_svcscan", r))

    out = []
    n = _next_n(existing)
    for mech, name, img, tool, reason in cands:
        key = str(img).strip().lower()
        if key in seen:
            continue
        seen.add(key)
        n += 1
        fid = "F%03d" % n
        pimg, _e = _image_and_ext(img)
        out.append({
            "finding_id": fid, "id": fid,
            "title": ("Anomalous persistence (%s): %s -> %s"
                      % (mech, name, img)),
            "description": ("%s '%s' resolves to image %s flagged as %s -- "
                            "outside normal service/task launch patterns. "
                            "Reported for analyst review; validator-backed by "
                            "collected %s facts, not an LLM assertion."
                            % (mech, name, img, reason, tool)),
            "severity": "MEDIUM", "confidence": "MEDIUM",
            "confidence_level": "MEDIUM",
            "source_tools": [tool], "tool_call_ids": [tool],
            "deterministic_finding": True,
            "deterministic_kind": _SIGNAL,
            "schema_version": _SCHEMA_VERSION,
            "persistence_mechanism": mech,
            "persistence_name": name,
            "persistence_image_path": img,
            "persistence_anomaly": reason,
            "malicious_semantic_signals": [_SIGNAL],
            "malicious_semantic_provenance": {
                _SIGNAL: {"source": "persistence_synthesizer",
                          "source_tool": tool, "mechanism": mech,
                          "name": name, "image_path": img, "anomaly": reason}},
            "claims": [
                {"type": "path", "path": pimg, "value": pimg},
                {"type": "artifact", "value": img, "artifact": img},
                {"type": "raw", "value": str(name)},
            ],
        })
    return out


__all__ = ["build_persistence_findings"]

"""Document-guard + nested-evidence regression + advisor public API.

A .pptx dropped beside the evidence must be kept as a reference document - NOT
exploded into 98 parts, NOT probed, and NOT sent to the advisor. A genuine
evidence zip(7z(raw)) must still extract to its raw image.
"""
from __future__ import annotations

import os
import subprocess
import uuid
import zipfile

import pytest

from sift_sentinel.onboard import archive
from sift_sentinel.onboard.engine import Phase, Probes, Status, onboard

_SEVENZ = __import__("shutil").which("7z") or __import__("shutil").which("7za")


class CountingAdvisor:
    def __init__(self):
        self.calls = 0

    def available(self):
        return True

    def advise(self, question, evidence, choices=None, timeout=30):
        self.calls += 1
        return {"suggestion": "insufficient_evidence", "confidence": 0.1}


class DocTestProbes(Probes):
    """Real archive/document detection (archive.py), content-based evidence
    probes (no sudo/vol)."""

    def discover(self, p):
        return [os.path.join(r, f)
                for r, _d, fs in os.walk(p) for f in sorted(fs)]

    def archive_kind(self, p):
        return archive.detect_archive(p)        # documents -> None (kept)

    def extract(self, p):
        return archive.extract_all(p)

    def has_filesystem(self, p):
        try:
            with open(p, "rb") as fh:
                boot = fh.read(512)
        except OSError:
            return False
        return len(boot) >= 512 and boot[510:512] == b"\x55\xaa" and b"FAT" in boot

    def fs_facts(self, p):
        return {"fstype": "FAT", "volume": "", "version": ""}

    def memory_info(self, p):
        try:
            with open(p, "rb") as fh:
                head = fh.read(64)
        except OSError:
            return None
        return ({"NtMajorVersion": "10", "NtMinorVersion": "0"}
                if b"MEMDUMP" in head else None)

    def mount(self, disk, method, mp):
        return False, "test image - not mounted"

    def health(self, mem):
        return True, [], {}

    def cleanup(self):
        pass


def _make_pptx(path):
    """Minimal OpenXML: a ZIP carrying the [Content_Types].xml marker."""
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("ppt/presentation.xml", "<p/>")


def test_pptx_is_document_not_extracted_no_advisor(tmp_path, monkeypatch):
    monkeypatch.setenv("SIFT_ONBOARD_IMAGE_FLOOR_MB", "0")
    case = tmp_path / "acme_case"
    case.mkdir()
    _make_pptx(case / "ACME-BACKGROUND.pptx")
    (case / f"{uuid.uuid4().hex[:8]}.raw").write_bytes(
        b"MEMDUMP-NTKRNL\x00" + b"\x00" * 8192)

    events = []
    advisor = CountingAdvisor()
    cases = onboard(str(case), on_event=events.append, ai=advisor,
                    probes=DocTestProbes())

    assert len(cases) == 1
    c = cases[0]
    # pptx is a kept reference document...
    doc_events = [e for e in events
                  if e.phase == Phase.CLASSIFY and e.data.get("role") == "DOC"]
    assert any("ACME-BACKGROUND.pptx" in e.data.get("name", "") for e in doc_events)
    assert any("ACME-BACKGROUND.pptx" in os.path.basename(d) for d in c.documents)
    # ...never extracted (no EXTRACT event mentions it)...
    assert not any("ACME-BACKGROUND" in str(e.data)
                   for e in events if e.phase == Phase.EXTRACT)
    # ...and the advisor was never consulted.
    assert advisor.calls == 0
    assert c.ai_consultations == []
    assert c.memory_path is not None       # the real memory still onboarded


def test_pptx_detected_by_marker_without_extension(tmp_path):
    # Even named .zip, the OOXML marker makes it a document (not extracted).
    p = tmp_path / "deck.zip"
    _make_pptx(p)
    assert archive.is_document(str(p)) is True
    assert archive.detect_archive(str(p)) is None


@pytest.mark.skipif(not _SEVENZ, reason="needs 7z to build zip(7z(raw))")
def test_nested_evidence_zip_7z_raw_still_extracts(tmp_path, monkeypatch):
    monkeypatch.setenv("SIFT_ONBOARD_IMAGE_FLOOR_MB", "0")
    stage = tmp_path / "stage"
    stage.mkdir()
    raw_name = f"{uuid.uuid4().hex[:8]}.raw"
    (stage / raw_name).write_bytes(b"MEMDUMP-X\x00" + b"\x00" * 8192)
    subprocess.run([_SEVENZ, "a", "-y", "inner.7z", raw_name],
                   cwd=str(stage), capture_output=True)
    case = tmp_path / "case"
    case.mkdir()
    with zipfile.ZipFile(case / "evidence.zip", "w") as z:
        z.write(stage / "inner.7z", "inner.7z")

    cases = onboard(str(case), on_event=lambda e: None, ai=None,
                    probes=DocTestProbes())
    assert len(cases) == 1
    assert cases[0].memory_path is not None
    assert os.path.basename(cases[0].memory_path) == raw_name


def test_advisor_public_api(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("SIFT_ONBOARD_AI", raising=False)
    from sift_sentinel.onboard import ai_advisor
    assert callable(ai_advisor.available) and callable(ai_advisor.advise)
    assert ai_advisor.available() is False          # no key -> False, fast
    assert ai_advisor.advise("q", {"a": 1}, None) == {}

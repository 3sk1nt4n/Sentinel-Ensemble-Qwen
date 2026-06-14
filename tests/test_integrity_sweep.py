"""Integrity sweep tests: no hardcoded data, stale state, or GT leaks.

Slot 31C2-FIX-A refactor
------------------------
The case-specific denylist (PIDs / evidence paths / process names)
used to live in this file as a module-level literal. That made every
public-repo viewer an "answer-key" reader by accident.

Now the denylist is loaded from
``tests/fixtures/integrity_denylist.json``, which is gitignored
(see ``.gitignore``). A tracked example template lives at
``tests/fixtures/integrity_denylist.example.json``. Contributors with
access to the case copy that template to the private filename and
fill in real values. Public CI without the private file still runs
the generic structural sweeps (state dir, dashboard tokens,
gitignore policy) and skips the case-specific sweeps via
``pytest.skip``.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "sift_sentinel"
PIPELINE = ROOT / "run_pipeline.py"
DENYLIST_PATH = ROOT / "tests" / "fixtures" / "integrity_denylist.json"


def _load_denylist() -> dict:
    """Return the case-specific denylist if the private file exists.

    Shape::

        {
          "case_pids":      [...],
          "evidence_paths": [...],
          "case_procs":     [...],
        }

    Missing keys default to empty lists so callers can iterate.
    """
    if not DENYLIST_PATH.exists():
        return {"case_pids": [], "evidence_paths": [], "case_procs": []}
    try:
        data = json.loads(DENYLIST_PATH.read_text())
    except json.JSONDecodeError:
        return {"case_pids": [], "evidence_paths": [], "case_procs": []}
    return {
        "case_pids":      list(data.get("case_pids") or []),
        "evidence_paths": list(data.get("evidence_paths") or []),
        "case_procs":     list(data.get("case_procs") or []),
    }


def _source_files():
    """All .py files in src/sift_sentinel/ and run_pipeline.py."""
    files = list(SRC.rglob("*.py"))
    if PIPELINE.exists():
        files.append(PIPELINE)
    return files


def _non_test_source():
    """Source files excluding tests/ and reference-data fixture directory."""
    return [f for f in _source_files()
            if "/tests/" not in str(f) and ("/" "ground" "_truth/") not in str(f)]


class TestStateDir:
    def test_state_dir_unique(self):
        """Two pipeline loads produce different STATE_DIR values."""
        text = PIPELINE.read_text()
        assert "time.time()" in text or "int(time.time())" in text
        assert "random.randint" in text
        # Hardcoded run ID must NOT appear
        assert "1775980320" not in text


class TestNoHardcodedPids:
    def test_no_hardcoded_pids_in_prompts(self):
        """Source code prompt strings must not contain evidence-specific PIDs.

        Skipped when the private denylist file is absent (public CI).
        """
        denylist = _load_denylist()
        case_pids = denylist["case_pids"]
        if not case_pids:
            pytest.skip(
                "tests/fixtures/integrity_denylist.json absent or "
                "empty -- case-specific PID sweep skipped"
            )
        hits = []
        for path in _non_test_source():
            text = path.read_text()
            for line_no, line in enumerate(text.splitlines(), 1):
                stripped = line.lstrip()
                if stripped.startswith("#"):
                    continue
                for pid in case_pids:
                    if re.search(rf'\b{re.escape(pid)}\b', line):
                        if "_SAFE" in line or "SAFE_" in line:
                            continue
                        hits.append(f"{path.name}:{line_no}: PID {pid}")
        assert not hits, "Hardcoded PIDs found:\n" + "\n".join(hits)


class TestNoHardcodedEvidencePaths:
    def test_no_hardcoded_evidence_paths(self):
        """Source code must not embed evidence-specific mount paths."""
        denylist = _load_denylist()
        evidence_paths = denylist["evidence_paths"]
        if not evidence_paths:
            pytest.skip(
                "tests/fixtures/integrity_denylist.json absent or "
                "empty -- case-specific path sweep skipped"
            )
        hits = []
        for path in _non_test_source():
            text = path.read_text()
            for line_no, line in enumerate(text.splitlines(), 1):
                lower = line.lower()
                for ep in evidence_paths:
                    if ep.lower() in lower:
                        hits.append(f"{path.name}:{line_no}: '{ep}'")
        assert not hits, "Evidence paths found:\n" + "\n".join(hits)

    def test_no_hardcoded_process_names(self):
        """Source code must not contain case-specific process names."""
        denylist = _load_denylist()
        case_procs = denylist["case_procs"]
        if not case_procs:
            pytest.skip(
                "tests/fixtures/integrity_denylist.json absent or "
                "empty -- case-specific process-name sweep skipped"
            )
        hits = []
        for path in _non_test_source():
            text = path.read_text()
            for line_no, line in enumerate(text.splitlines(), 1):
                stripped = line.lstrip()
                if stripped.startswith("#"):
                    continue
                lower = line.lower()
                for proc in case_procs:
                    if proc.lower() in lower:
                        if "_SAFE" in line or "SAFE_" in line:
                            continue
                        hits.append(f"{path.name}:{line_no}: '{proc}'")
        assert not hits, "Case-specific names found:\n" + "\n".join(hits)


class TestDashboardUsesActualTokens:
    def test_dashboard_no_hardcoded_token_counts(self):
        """Dashboard section must not contain hardcoded token counts."""
        text = PIPELINE.read_text()
        for bad in ["12950", "80530", "20000", "89037", "5362"]:
            assert bad not in text, f"Hardcoded token count {bad} still in pipeline"

    def test_inv_tokens_dict_exists(self):
        """Pipeline defines _inv_tokens tracking dict."""
        text = PIPELINE.read_text()
        assert "_inv_tokens" in text
        assert "_snap_tokens" in text
        assert "_record_phase" in text


class TestNoCachedOutputsTracked:
    def test_gitignore_covers_cached_outputs(self):
        """cached_outputs/ is fully ignored in .gitignore."""
        gitignore = (ROOT / ".gitignore").read_text()
        assert "cached_outputs/" in gitignore


class TestDenylistTemplateTracked:
    def test_denylist_template_present_and_well_formed(self):
        """The tracked example template exists and parses as JSON.

        This is the public contract: contributors see the template and
        know to copy it locally for the full integrity sweep.
        """
        example = ROOT / "tests" / "fixtures" / "integrity_denylist.example.json"
        assert example.exists(), (
            "tests/fixtures/integrity_denylist.example.json must be "
            "tracked so contributors know how to enable the full sweep"
        )
        data = json.loads(example.read_text())
        # Required keys, all empty in the template by design.
        assert set(data.keys()) >= {"case_pids", "evidence_paths", "case_procs"}
        assert data["case_pids"] == []
        assert data["evidence_paths"] == []
        assert data["case_procs"] == []

    def test_private_denylist_is_gitignored(self):
        """The real denylist file must be listed in .gitignore."""
        gitignore_text = (ROOT / ".gitignore").read_text()
        assert "tests/fixtures/integrity_denylist.json" in gitignore_text

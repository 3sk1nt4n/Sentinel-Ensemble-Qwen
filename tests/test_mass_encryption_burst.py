"""#1 mass-encryption burst (T1486) — the vocabulary-free ransomware lever.

In-place ransomware encryption leaves a corpus fingerprint: one FOREIGN extension
appended across MANY files of DIVERSE original data types (report.docx.<enc>,
sheet.xlsx.<enc>, ...). Detected at candidate-build, self-relative count
(mean+2sigma) + FP-bounded by type-diversity (>=3 distinct data types, vs a single
app's double-extension), emitted as a synthetic validation-ready candidate that
RIDES the gen-fix -> deterministic finding -> needs-review (human triages mass-
backup vs encryption). Dataset-agnostic: universal file-type vocabulary only, no
ransomware family names, no case paths.
"""
from __future__ import annotations

from sift_sentinel.analysis.malicious_semantics import (
    MALICIOUS_SEMANTIC_SIGNALS,
    match_mass_encryption_burst,
)
from sift_sentinel.analysis.candidate_observations import (
    build_candidate_observations,
    _candidate_type,
)


def _fs(path):
    return {"fact_type": "filesystem_timeline_fact", "type": "filesystem_timeline_fact",
            "fact_id": "fst-%d" % (abs(hash(path)) % 100000),
            "path": path, "normalized_path": path.lower()}


def _db(facts):
    typed: dict = {}
    for f in facts:
        typed.setdefault(f["fact_type"], []).append(f)
    return {"typed_facts": typed}


# ── matcher (per-file recognition) ──────────────────────────────────────
def test_matcher_fires_on_appended_foreign_extension():
    assert match_mass_encryption_burst({"normalized_path": "c:/u/x/report.docx.locked"})
    assert match_mass_encryption_burst({"path": "D:/data/sheet.xlsx.crypt"})


def test_matcher_ignores_legit_files():
    assert not match_mass_encryption_burst({"normalized_path": "c:/u/x/report.docx"})    # single ext
    assert not match_mass_encryption_burst({"normalized_path": "c:/u/x/report.docx.pdf"})  # data->data
    assert not match_mass_encryption_burst({"normalized_path": "c:/u/x/app.dll"})


def test_registered_non_weak():
    spec = MALICIOUS_SEMANTIC_SIGNALS.get("mass_encryption_burst")
    assert spec and callable(spec.get("matcher")) and spec.get("required_fact_types")


# ── corpus-level burst -> synthetic validation-ready candidate ──────────
def test_burst_emits_synthetic_validation_ready_candidate():
    # one appended ext (.locked) across diverse data types, many files
    facts = []
    for i in range(40):
        ext = ["docx", "xlsx", "pdf", "jpg", "txt"][i % 5]
        facts.append(_fs("c:/users/fred/docs/file%d.%s.locked" % (i, ext)))
    # plus benign baseline files (no double-ext) and a small unrelated double-ext
    facts += [_fs("c:/windows/system32/x%d.dll" % i) for i in range(10)]
    payload = build_candidate_observations(_db(facts))
    burst = [c for c in payload["candidates"]
             if "mass_encryption_burst" in (c.get("signals") or [])]
    assert len(burst) == 1, [c["entity_key"] for c in burst]
    assert burst[0]["validation_ready"] is True
    assert burst[0]["candidate_type"] == "ransomware_mass_encryption"
    assert burst[0]["entity_key"] == "encryption_burst:locked"


def test_no_burst_when_extension_not_diverse():
    # 40 files but all the SAME original type -> diversity<3 -> not a burst
    # (could be one app writing many .docx.tmp); FP-bound holds.
    facts = [_fs("c:/u/fred/d/file%d.docx.bak" % i) for i in range(40)]
    payload = build_candidate_observations(_db(facts))
    burst = [c for c in payload["candidates"]
             if "mass_encryption_burst" in (c.get("signals") or [])]
    assert burst == []


def test_candidate_type_mapping():
    assert _candidate_type({"mass_encryption_burst"}) == "ransomware_mass_encryption"


def test_burst_candidate_rides_genfix_to_multiclaim_finding():
    # End-to-end (unit): the synthetic burst candidate flows through the gen-fix
    # to a deterministic finding carrying per-file path claims (multi-claim ->
    # clears the disposition one-claim gate -> needs-review).
    from sift_sentinel.analysis.candidate_findings import (
        build_candidate_semantic_findings,
    )
    facts = []
    for i in range(40):
        ext = ["docx", "xlsx", "pdf", "jpg", "txt"][i % 5]
        facts.append(_fs("c:/users/fred/docs/file%d.%s.locked" % (i, ext)))
    db = _db(facts)
    obs = build_candidate_observations(db)
    out = build_candidate_semantic_findings(obs, existing_findings=[], evidence_db=db)
    enc = [f for f in out
           if "mass_encryption_burst" in (f.get("malicious_semantic_signals") or [])]
    assert len(enc) == 1, [f.get("malicious_semantic_signals") for f in out]
    assert enc[0]["deterministic_finding"] is True
    assert len(enc[0]["claims"]) >= 2
    # per-file path claims present (multi-claim -> clears the one-claim gate); a
    # universal typed_fact support claim now rides along for binding, so assert the
    # path claims are present rather than that they are the ONLY claim type.
    _types = [c["type"] for c in enc[0]["claims"]]
    assert _types.count("path") >= 2
    assert set(_types) <= {"path", "typed_fact"}

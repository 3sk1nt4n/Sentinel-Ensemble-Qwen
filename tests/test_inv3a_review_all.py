"""inv3a can review ALL findings (SIFT_INV3A_REVIEW_ALL), but proven evil is floored.

The user wants one AI pass (13AA/inv3a) to give a final TP/FP verdict on EVERY
finding, not just the ambiguous middle. SIFT_INV3A_REVIEW_ALL=1 feeds it confirmed +
benign too. Safety: a deterministically-CONFIRMED finding can never be demoted out of
the findings table by the model -- a bad sample cannot bury real evil, so the
confirmed set stays reproducible across PCs. Default OFF = byte-identical legacy.
"""
import json

from sift_sentinel.analysis import inv3a_finalize as i3

C = i3.BUCKET_CONFIRMED
S = i3.BUCKET_SUSPICIOUS
B = i3.BUCKET_BENIGN
I = i3.BUCKET_INCONCLUSIVE


def _adj(verdicts):
    def _fn(_prompt):
        return json.dumps({"verdicts": verdicts})
    return _fn


def _bucket_of(buckets, fid):
    for bk, items in buckets.items():
        for f in items:
            if isinstance(f, dict) and i3._finding_id(f) == fid:
                return bk
    return None


# ---- input set ----
def test_default_excludes_confirmed_and_benign(monkeypatch):
    monkeypatch.delenv("SIFT_INV3A_REVIEW_ALL", raising=False)
    buckets = {C: [{"finding_id": "Fc"}], S: [{"finding_id": "Fs"}], B: [{"finding_id": "Fb"}]}
    ids = {i3._finding_id(f) for f in i3.select_ambiguous(buckets)}
    assert ids == {"Fs"}                       # only the ambiguous middle


def test_review_all_includes_everything(monkeypatch):
    monkeypatch.setenv("SIFT_INV3A_REVIEW_ALL", "1")
    buckets = {C: [{"finding_id": "Fc"}], S: [{"finding_id": "Fs"}], B: [{"finding_id": "Fb"}]}
    ids = {i3._finding_id(f) for f in i3.select_ambiguous(buckets)}
    assert ids == {"Fc", "Fs", "Fb"}          # inv3a now SEES all


# ---- the proven-evil floor ----
def test_confirmed_is_never_demoted_by_inv3a(monkeypatch):
    monkeypatch.setenv("SIFT_INV3A_REVIEW_ALL", "1")
    buckets = {C: [{"finding_id": "Fc"}], S: [{"finding_id": "Fs"}], B: [], I: []}
    # adjudicator tries to call the confirmed finding a false_positive
    adj = _adj([{"finding_id": "Fc", "disposition": "false_positive", "reason": "x"},
                {"finding_id": "Fs", "disposition": "false_positive", "reason": "y"}])
    out, ledger = i3.finalize_dispositions(buckets, adj)
    assert _bucket_of(out, "Fc") == C          # proven evil STAYS confirmed (floored)
    assert _bucket_of(out, "Fs") == B          # the ambiguous one CAN be benign'd


def test_launcher_enables_review_all_and_enrich():
    import step0_onboard as s
    for key in ("1", "2"):
        env = s.mode_launch_env(s.ANALYSIS_MODES[key])
        assert env.get("SIFT_INV3A_REVIEW_ALL") == "1"
        assert env.get("SIFT_INV3A_ENRICH") == "1"


def test_xref_profile_is_case_neutral():
    # the big-picture cross-check carries ONLY integer counts -> universal, no case data
    import json, re
    prof = i3.build_xref_profiles([{
        "finding_id": "F1", "description": "p.exe in c:/windows/temp/perfmon",
        "source_tools": ["vol_malfind", "get_amcache"], "severity": "HIGH"}])
    blob = json.dumps(prof)
    assert not re.search(r"p\.exe|perfmon|windows|\d{1,3}(?:\.\d{1,3}){3}", blob)
    p1 = prof.get("F1", {})
    assert set(p1) <= {"tools", "domains", "weak", "strong", "parked"}
    assert all(isinstance(p1.get(k), int) for k in ("tools", "domains", "weak", "strong"))


def test_review_all_does_not_promote_without_eligibility(monkeypatch):
    monkeypatch.setenv("SIFT_INV3A_REVIEW_ALL", "1")
    buckets = {C: [], S: [{"finding_id": "Fs"}], B: [], I: []}
    adj = _adj([{"finding_id": "Fs", "disposition": "confirmed", "reason": "z"}])
    out, _ = i3.finalize_dispositions(buckets, adj, eligibility_fn=lambda f: False)
    assert _bucket_of(out, "Fs") == S          # clamp: never fabricate a confirm

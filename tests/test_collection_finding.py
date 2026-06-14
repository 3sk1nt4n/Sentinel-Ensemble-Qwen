"""#4: surface the rich collection evidence as a TABLE finding.

The per-user narrative attributed bobby's 1057 accessed file artifacts but they
never became a finding. synthesize_collection_findings emits ONE data_collection
finding per user whose accessed-asset count is high AND co-occurs with an
external channel in the same user context (collection + egress = staging/exfil).
GATED on has_channel so a user merely opening their own files is NOT flagged.
Reuses the validatable user_account claim. Universal: keyed on the profile-path
segment + channel co-occurrence, no case names/paths.
"""
from sift_sentinel.analysis.user_account_synthesizer import (
    synthesize_collection_findings,
)


def _tf(n_assets=30, channel_pid=1248, owned=(1248,)):
    assets = [{"path": "C:\\Users\\bobby\\Dropbox\\file_%d.xlsx" % i}
              for i in range(n_assets)]
    return {
        "user_account_fact": [{"username": "bobby", "domain": "DOM",
                               "sid": "S-1-5-21-1", "owned_pids": list(owned),
                               "source_tools": ["vol_getsids"], "fact_id": "uf-0"}],
        "lnk_execution_fact": assets,
        "network_connection_fact": (
            [{"pid": channel_pid, "dst_ip": "203.0.113.9"}] if channel_pid else []),
    }


def test_emits_when_high_collection_and_channel():
    out = synthesize_collection_findings(_tf(n_assets=30, channel_pid=1248))
    assert len(out) == 1
    f = out[0]
    assert f["finding_type"] == "data_collection"
    assert "30 file artifacts" in f["title"]
    assert f["claims"][0]["type"] == "user_account"   # validatable claim
    assert "DOM\\bobby" in f["artifact"]


def test_no_channel_does_not_emit():
    # collection WITHOUT an external channel = user opening own files -> not flagged.
    out = synthesize_collection_findings(_tf(n_assets=30, channel_pid=None))
    assert out == []


def test_below_threshold_does_not_emit():
    out = synthesize_collection_findings(_tf(n_assets=5, channel_pid=1248))
    assert out == []


def test_channel_pid_not_owned_does_not_emit():
    # the externally-communicating PID must be OWNED by this user.
    out = synthesize_collection_findings(_tf(n_assets=30, channel_pid=9999, owned=(1248,)))
    assert out == []


def test_malformed_input_never_raises():
    assert synthesize_collection_findings(None) == []
    assert synthesize_collection_findings({}) == []
    assert synthesize_collection_findings({"user_account_fact": ["x", None]}) == []


def test_reuses_validatable_claim_shape():
    f = synthesize_collection_findings(_tf())[0]
    c = f["claims"][0]
    assert c["username"] == "bobby" and c["owned_pids"] == [1248]
    assert f["validator_fact_refs"][0]["fact_type"] == "user_account_fact"

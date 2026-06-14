"""Report enrichment, all universal (no case values):
 - IOC column: entity-typed labels (user:/service:/event:/port:) + friendly
   Windows Event-ID descriptions, so bare 'jdoe'/'5140'/'PSEXESVC' read clearly.
 - Details: clipped on a sentence/word boundary, never mid-word.
 - Finding column: a titleless row shows a human label, not its own ID twice.
 - Tool cell: ReAct cross-check tools colored green, box stays aligned when wrapped.
"""
import re
import sift_sentinel.reporting.customer_findings_table_bucket_faithful as R


def test_username_field_becomes_user_prefix():
    f = {"finding_id": "F059", "title": "lateral movement",
         "claims": [{"type": "user_account", "username": "jdoe"}]}
    assert "user:jdoe" in R._ioc_bits(f)


def test_service_name_becomes_service_prefix():
    f = {"finding_id": "F015", "title": "PsExec service",
         "claims": [{"type": "service", "service_name": "PSEXESVC"}]}
    assert "service:PSEXESVC" in R._ioc_bits(f)


def test_event_id_field_gets_friendly_label():
    f = {"finding_id": "F054", "title": "lateral movement",
         "claims": [{"type": "event_log", "event_id": 5140}]}
    out = R._ioc_bits(f)
    assert "event:5140" in out and "network share accessed" in out


def test_bare_event_number_in_value_is_classified():
    f = {"finding_id": "F056", "title": "lateral movement",
         "claims": [{"type": "path", "value": "5140"}]}
    out = R._ioc_bits(f)
    assert "event:5140" in out and "network share accessed" in out


def test_ip_and_port_combine():
    f = {"finding_id": "F1", "title": "net",
         "claims": [{"type": "conn", "remote_ip": "10.0.0.5", "remote_port": 445}]}
    assert "10.0.0.5:445" in R._ioc_bits(f)


def test_details_clip_is_sentence_or_word_complete():
    long = ("The process exhibited suspicious behavior. It allocated executable "
            "memory and then began listening for remote access on port 32768 which "
            "is well above the ephemeral range and therefore notable for analysts.") * 2
    out = R._clip_sentence(long, 120)
    assert len(out) <= 121
    # never ends mid-word: last visible char is sentence punctuation or ellipsis,
    # and the tail before any ellipsis is a whole word
    assert out.endswith((".", "!", "?", "…"))
    core = out.rstrip("…").rstrip()
    assert not core.endswith(("port 3", "on port 3"))  # no mid-number cut


def test_titleless_self_corrected_shows_label_not_id():
    R._C = R._B = R._X = R._G = R._M = ""  # plain palette
    sc = {"finding_id": "F010", "self_corrected": True,
          "claims": [{"type": "pid", "pid": 1, "process": "p.exe"}]}
    out = R.render_findings_terminal({"benign_or_false_positive": [sc]}, summary={})
    assert "self-corrected" in out.lower()
    # the Finding cell is not just the ID repeated
    row = next(l for l in out.splitlines() if "F010" in l and l.startswith("│"))
    assert row.count("F010") == 1


def test_react_tools_colored_green_and_box_aligned(tmp_path):
    R._C, R._G, R._B, R._X, R._M = "\033[96m", "\033[92m", "\033[1m", "\033[0m", "\033[95m"
    # craft an inv3 turn file in the REAL coordinator format
    # ("Turn N: <tool> on PID X -> Y records") so _react_tool_stats reports the
    # cross-check tool NAMES (not the record counts).
    (tmp_path / "inv3_F001_turn1.md").write_text(
        "Turn 1: vol_ldrmodules on PID 6036 -> 5 records\n"
        "Turn 1: vol_psxview on PID 6036 -> 3 records\n")
    f = {"finding_id": "F001", "title": "memory injection in a process",
         "source_tools": ["vol_malfind", "vol_pstree"],
         "claims": [{"type": "pid", "pid": 6036, "process": "UpdaterUI.exe"}]}
    out = R.render_findings_terminal({"confirmed_malicious_atomic": [f]},
                                     summary={}, state_dir=str(tmp_path))
    assert "+ReAct:" in out
    assert "vol_ldrmodules" in out      # the cross-check tool NAME renders
    assert "\033[92m" in out            # green present on the cross-check tools
    rows = [l for l in out.splitlines() if l.startswith("│")]
    widths = {len(re.sub(r"\x1b\[[0-9;]*m", "", l)) for l in rows}
    assert len(widths) == 1, widths  # box stays aligned despite color + wrapping


def test_srum_egress_row_renders_human_readable():
    # a raw SRUM usage row (CSV cells) -> a readable egress figure, by SHAPE only
    f = {"finding_id": "F044", "title": "egress outlier",
         "artifact": ["{973f5d5c-1d90-4944-be8e-24b94231a174}", "appid:1", "",
                      "2020-11-16 02:44", "64410159574", "srudb.dat"]}
    out = R._ioc_bits(f)
    assert "64.4 GB" in out and "appid:1" in out and "2020-11-16" in out
    assert "64410159574" not in out  # the raw byte dump is gone


def test_non_srum_list_artifact_unchanged():
    f = {"finding_id": "F1", "title": "x", "artifact": ["a.exe", "b.dll"]}
    out = R._ioc_bits(f)
    assert "a.exe" in out  # plain list still rendered raw

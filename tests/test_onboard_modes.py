"""Analysis-depth modes (Heavy/Light), card-number selection, and the launch env.
Pure, testable pieces of the fancy launch flow. No model literal is hardcoded in
the test — we assert SHAPE (force-model env set, ensemble flag), not exact ids.
"""
import step0_onboard as s
from sift_sentinel.onboard.engine import CaseManifest


def _m(**kw):
    base = dict(case_id="c", os="Win10 (NT 10.0)", os_source="memory",
                memory_path="/ev/mem.raw", memory_health="HEALTHY",
                memory_health_facts={}, disk_path="/ev/disk.e01", disk_mounted=True,
                mount_method="raw@0", mount_path="/mnt/c", reference_docs=[])
    base.update(kw)
    return CaseManifest(**base)


# ── modes ────────────────────────────────────────────────────────────────
def test_two_modes_with_cost():
    assert set(s.ANALYSIS_MODES) == {"1", "2"}
    assert s.ANALYSIS_MODES["1"]["key"] == "heavy"
    assert s.ANALYSIS_MODES["2"]["key"] == "light"
    for m in s.ANALYSIS_MODES.values():
        assert "$" in m["cost"]                       # an approximate cost is shown


def test_parse_mode_choice():
    assert s.parse_mode_choice("1")["key"] == "heavy"
    assert s.parse_mode_choice("2")["key"] == "light"
    assert s.parse_mode_choice("heavy")["key"] == "heavy"
    assert s.parse_mode_choice("light")["key"] == "light"
    assert s.parse_mode_choice("banana") is None


def test_both_modes_use_the_ensemble():
    # Heavy AND Light both run the 4-model ensemble -- only the model differs.
    assert s.ANALYSIS_MODES["1"]["ensemble"] is True
    assert s.ANALYSIS_MODES["2"]["ensemble"] is True
    assert "--inv2-ensemble" in s.build_find_command(_m(), ensemble=True)
    assert "--inv2-ensemble" not in s.build_find_command(_m(), ensemble=False)


def test_mode_launch_env_forces_model_whole_run_both_ensembles():
    heavy = s.mode_launch_env(s.ANALYSIS_MODES["1"])
    light = s.mode_launch_env(s.ANALYSIS_MODES["2"])
    for env in (heavy, light):
        assert env["SIFT_FORCE_MODEL"]                    # whole-run override set
        assert "SIFT_INV2_ENSEMBLE_FORCE_MODEL" in env    # ensemble forced too
    # same env shape, different model: Heavy = Opus 4.8, Light = Haiku
    assert "opus" in heavy["SIFT_FORCE_MODEL"].lower()
    assert "haiku" in light["SIFT_FORCE_MODEL"].lower()
    assert heavy["SIFT_FORCE_MODEL"] != light["SIFT_FORCE_MODEL"]


def test_mode_launch_env_enables_universal_fixes():
    # onboarded runs must turn on inv3a (Step 13AA, the consolidated FP-sweep) and
    # the two deterministic FP gates, regardless of depth -- so the launcher line
    # actually exercises them (the live acme run omitted SIFT_INV3A_FINALIZE).
    for key in ("1", "2"):
        env = s.mode_launch_env(s.ANALYSIS_MODES[key])
        assert env.get("SIFT_INV3A_FINALIZE") == "1"
        assert env.get("SIFT_JIT_RWX") == "1"
        assert env.get("SIFT_TOOL_STATUS_NOISE") == "1"
        # A1 (2026-06-10): cross-bucket dedup on for onboarded runs so the same
        # event/artifact surfacing in confirmed + needs-review collapses to one.
        assert env.get("SIFT_XBUCKET_DEDUP") == "1"


def test_choose_mode_default_is_heavy():
    assert s.choose_mode(input_fn=lambda _p: "")["key"] == "heavy"     # Enter = Heavy
    assert s.choose_mode(input_fn=lambda _p: "2")["key"] == "light"


# ── card-number selection ────────────────────────────────────────────────
def test_parse_card_choice():
    assert s.parse_card_choice("11", 20) == 11        # 'just give the number'
    assert s.parse_card_choice("1", 3) == 1
    assert s.parse_card_choice("a", 3) == "a"
    assert s.parse_card_choice("Q", 3) == "q"
    assert s.parse_card_choice("99", 3) is None       # out of range -> re-ask
    assert s.parse_card_choice("banana", 3) is None


# ── Light (option 2) goes all the way: full Haiku ensemble, every stage ─────
def test_light_model_is_haiku_heavy_is_opus():
    # HEAVY defaults to Opus 4.8 (Fable 5 trial refused the Inv2 prompt;
    # SIFT_HEAVY_MODEL re-enables it for A/B). LIGHT stays Haiku.
    assert "haiku" in s.ANALYSIS_MODES["2"]["model"].lower()
    assert "opus" in s.ANALYSIS_MODES["1"]["model"].lower()


def test_light_env_forces_haiku_with_ensemble():
    # Light is a FULL ensemble too -- 4x Haiku 4.5 (ensemble forced onto Haiku).
    env = s.mode_launch_env(s.ANALYSIS_MODES["2"])
    assert "haiku" in env["SIFT_FORCE_MODEL"].lower()
    assert "haiku" in env["SIFT_INV2_ENSEMBLE_FORCE_MODEL"].lower()
    assert "--inv2-ensemble" in s.build_find_command(
        _m(), ensemble=s.ANALYSIS_MODES["2"]["ensemble"])


def test_force_model_reaches_every_pipeline_stage(monkeypatch):
    # The whole-run force (what Light/Heavy set) must win for EVERY stage role,
    # so a Light run is haiku from Inv1 through ReAct, report and self-correction.
    from sift_sentinel import model_roles as mr
    monkeypatch.delenv("SIFT_DEFAULT_MODEL", raising=False)
    for role in ("inv1_primary", "inv1_retry", "analysis", "react",
                 "report", "self_correction"):
        monkeypatch.delenv(mr.ROLE_ENV[role], raising=False)  # no per-role override
    forced = "claude-haiku" + "-4-5-20251001"
    monkeypatch.setenv("SIFT_FORCE_MODEL", forced)
    for role in ("inv1_primary", "inv1_retry", "analysis", "react",
                 "report", "self_correction"):
        assert mr.resolve_model(role) == forced, role   # every stage = haiku


def test_per_role_override_would_beat_force(monkeypatch):
    # Documented precedence: a role-specific SIFT_MODEL_<ROLE> wins over the force.
    from sift_sentinel import model_roles as mr
    monkeypatch.setenv("SIFT_FORCE_MODEL", "claude-haiku" + "-4-5-20251001")
    monkeypatch.setenv("SIFT_MODEL_REACT", "some-other-model")
    assert mr.resolve_model("react") == "some-other-model"   # the one escape hatch
    assert mr.resolve_model("analysis") != "some-other-model"


# ── escapes: no prompt can trap the user (back / quit / stray keypress) ─────
def test_choose_mode_has_escapes():
    assert s.choose_mode(input_fn=lambda _p: "q") is None        # Q -> quit
    assert s.choose_mode(input_fn=lambda _p: "quit") is None
    assert s.choose_mode(input_fn=lambda _p: "b") == "back"       # B -> back a step
    assert s.choose_mode(input_fn=lambda _p: "back") == "back"
    assert s.choose_mode(input_fn=lambda _p: "a") == "back"       # 'another' steps back
    assert s.choose_mode(input_fn=lambda _p: None) is None        # EOF -> quit


def test_clean_input_strips_escape_sequences():
    # Delete key sends '\x1b[3~'; arrows send '\x1b[A' etc. -> must not wedge a prompt
    assert s._clean_input("\x1b[3~q") == "q"
    assert s._clean_input("\x1b[A") == ""
    assert s._clean_input("1") == "1"


def test_choose_mode_recovers_from_stray_keypress():
    feed = iter(["\x1b[3~", "1"])      # a Delete keypress, then a real choice
    assert s.choose_mode(input_fn=lambda _p: next(feed))["key"] == "heavy"


def test_mode_env_overrides_per_role_pins():
    # The bug: Heavy ran Haiku because the shell pinned SIFT_MODEL_INV1_PRIMARY.
    # The mode must override EVERY per-stage pin so the depth choice is authoritative.
    env = s.mode_launch_env(s.ANALYSIS_MODES["1"])           # heavy -> opus 4.8
    model = env["SIFT_FORCE_MODEL"]
    assert "opus" in model.lower()
    for rolevar in ("SIFT_MODEL_INV1_PRIMARY", "SIFT_MODEL_INV1_RETRY",
                    "SIFT_MODEL_ANALYSIS", "SIFT_MODEL_REACT",
                    "SIFT_MODEL_SELF_CORRECTION", "SIFT_MODEL_REPORT"):
        assert env[rolevar] == model                         # every stage overridden
    assert env["SIFT_DEFAULT_MODEL"] == model

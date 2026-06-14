from __future__ import annotations

import importlib
from pathlib import Path

import pytest


def test_run_yara_missing_rules_path_explains_zero_result(tmp_path: Path) -> None:
    import sift_sentinel.tools.generic as gen

    gen = importlib.reload(gen)
    target = tmp_path / "target.bin"
    target.write_bytes(b"synthetic target only")

    result = gen.run_yara(str(tmp_path / "missing-rules"), str(target))

    assert result["record_count"] == 0
    assert result["output"] == []
    assert result["failure_mode"] == "rules_path_invalid"
    assert result["rules_file_count"] == 0
    assert result["rules_loaded_count"] == 0
    assert result["rules_loaded"] is False
    assert result["yara_rules_loaded_gate"] == "FAIL"
    assert result["yara_match_count"] == 0
    assert result["zero_result_meaning"] == "rules_not_loaded"


def test_run_yara_empty_rules_directory_does_not_execute_and_explains_zero(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import sift_sentinel.tools.generic as gen

    gen = importlib.reload(gen)
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    target = tmp_path / "target.bin"
    target.write_bytes(b"synthetic target only")

    calls: list[object] = []

    def fake_run(*args: object, **kwargs: object) -> object:
        calls.append((args, kwargs))
        raise AssertionError("YARA subprocess should not run without rule files")

    monkeypatch.setattr("subprocess.run", fake_run)

    result = gen.run_yara(str(rules_dir), str(target))

    assert calls == []
    assert result["record_count"] == 0
    assert result["failure_mode"] == "no_rules_loaded"
    assert result["rules_file_count"] == 0
    assert result["yara_rules_loaded_gate"] == "FAIL"
    assert result["zero_result_meaning"] == "rules_not_loaded"


def test_run_yara_loaded_rules_no_hits_is_distinct_from_no_rules(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import sift_sentinel.tools.generic as gen

    gen = importlib.reload(gen)
    rule = tmp_path / "rule.yar"
    rule.write_text("rule SyntheticNoHit { condition: false }\n")
    target = tmp_path / "target.bin"
    target.write_bytes(b"synthetic target only")

    class Completed:
        returncode = 0
        stdout = ""
        stderr = ""

    captured: list[list[str]] = []

    def fake_run(cmd: list[str], *args: object, **kwargs: object) -> Completed:
        captured.append(cmd)
        return Completed()

    monkeypatch.setattr("subprocess.run", fake_run)

    result = gen.run_yara(str(rule), str(target))

    assert captured
    assert result["record_count"] == 0
    assert result["output"] == []
    assert "failure_mode" not in result
    assert result["rules_file_count"] == 1
    assert result["rules_loaded_count"] == 1
    assert result["rules_loaded"] is True
    assert result["yara_rules_loaded_gate"] == "PASS"
    assert result["yara_match_count"] == 0
    assert result["zero_result_meaning"] == "rules_loaded_no_matches"


def test_run_yara_match_retains_existing_output_shape(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import sift_sentinel.tools.generic as gen

    gen = importlib.reload(gen)
    rule = tmp_path / "rule.yar"
    rule.write_text("rule SyntheticHit { condition: true }\n")
    target = tmp_path / "target.bin"
    target.write_bytes(b"synthetic target only")

    class Completed:
        returncode = 0
        stdout = "SyntheticHit /tmp/sift-target.bin\n"
        stderr = ""

    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: Completed())

    result = gen.run_yara(str(rule), str(target))

    assert result["record_count"] == 1
    assert result["output"] == [{"rule": "SyntheticHit", "target": "/tmp/sift-target.bin"}]
    assert result["rules_file_count"] == 1
    assert result["rules_loaded_count"] == 1
    assert result["yara_rules_loaded_gate"] == "PASS"
    assert result["yara_match_count"] == 1
    assert result["zero_result_meaning"] == "rules_loaded_matches_found"


def test_run_yara_directory_rule_count_is_recursive(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import sift_sentinel.tools.generic as gen

    gen = importlib.reload(gen)
    rules_dir = tmp_path / "rules"
    nested = rules_dir / "nested"
    nested.mkdir(parents=True)
    (rules_dir / "a.yar").write_text("rule A { condition: false }\n")
    (nested / "b.yara").write_text("rule B { condition: false }\n")
    (nested / "ignore.txt").write_text("not a rule\n")
    target = tmp_path / "target.bin"
    target.write_bytes(b"synthetic target only")

    class Completed:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: Completed())

    result = gen.run_yara(str(rules_dir), str(target))

    assert result["rules_file_count"] == 2
    assert result["rules_loaded_count"] == 2
    assert result["yara_rules_loaded_gate"] == "PASS"
    assert result["zero_result_meaning"] == "rules_loaded_no_matches"


def test_run_yara_capability_declares_no_rules_loaded_failure_mode() -> None:
    import sift_sentinel.coordinator as c

    cap = c.get_capability("run_yara")
    assert cap is not None
    assert "no_rules_loaded" in cap["failure_modes"]

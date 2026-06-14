from sift_sentinel.validation.typed_validator import (
    TypedEvidenceDB,
    typed_check_claim,
    _TYPED_CHECKERS,
)


def _db():
    return {
        "typed_facts": {
            "handle_fact": [
                {
                    "fact_id": "handle_fact-1",
                    "fact_type": "handle_fact",
                    "pid": 1234,
                    "process_name": "alpha.exe",
                    "handle_type": "file",
                    "handle_name": r"\Device\HarddiskVolume1\Users\Public\artifact.bin",
                    "granted_access": 120089,
                    "handle_value": 88,
                },
                {
                    "fact_id": "handle_fact-2",
                    "fact_type": "handle_fact",
                    "fields": {
                        "pid": 2222,
                        "process_name": "beta.exe",
                        "handle_type": "key",
                        "handle_name": r"MACHINE\Software\Vendor",
                    },
                },
            ]
        },
        "indexes": {
            "by_pid": {
                "1234": ["handle_fact-1"],
                "2222": ["handle_fact-2"],
            }
        },
    }


def test_process_handle_checker_registered():
    assert "process_handle" in _TYPED_CHECKERS
    assert "process_handle_type" in _TYPED_CHECKERS
    assert "process_handle_contains" in _TYPED_CHECKERS


def test_process_handle_exact_type_and_name_matches():
    out = typed_check_claim(
        {
            "type": "process_handle",
            "pid": 1234,
            "process": "alpha.exe",
            "handle_type": "file",
            "handle_name": r"\Device\HarddiskVolume1\Users\Public\artifact.bin",
        },
        TypedEvidenceDB(_db()),
    )
    assert out and out[0] == "MATCH"


def test_process_handle_type_matches():
    out = typed_check_claim(
        {
            "type": "process_handle_type",
            "pid": 2222,
            "process": "beta.exe",
            "handle_type": "key",
        },
        TypedEvidenceDB(_db()),
    )
    assert out and out[0] == "MATCH"


def test_process_handle_contains_matches():
    out = typed_check_claim(
        {
            "type": "process_handle_contains",
            "pid": 1234,
            "contains": "artifact.bin",
        },
        TypedEvidenceDB(_db()),
    )
    assert out and out[0] == "MATCH"


def test_process_handle_process_mismatch_refutes():
    out = typed_check_claim(
        {
            "type": "process_handle",
            "pid": 1234,
            "process": "wrong.exe",
            "handle_type": "file",
        },
        TypedEvidenceDB(_db()),
    )
    assert out and out[0] == "MISMATCH"


def test_process_handle_constraint_mismatch_refutes():
    out = typed_check_claim(
        {
            "type": "process_handle_type",
            "pid": 1234,
            "handle_type": "mutant",
        },
        TypedEvidenceDB(_db()),
    )
    assert out and out[0] == "MISMATCH"


def test_process_handle_no_facts_falls_back():
    out = typed_check_claim(
        {
            "type": "process_handle",
            "pid": 9999,
            "handle_type": "file",
        },
        TypedEvidenceDB(_db()),
    )
    assert out is None

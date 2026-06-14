"""A LOLBIN execution finding (rundll32 / regsvr32 / mshta ... recorded in
AppCompatCache/ShimCache) must get a plain-English 'why it matters', not an
empty Details cell. Universal: keyed on the repo's canonical LOLBIN matcher +
the OS execution-artifact vocabulary -- no case data; relabel paths -> unchanged.
"""
from sift_sentinel.reporting.finding_significance import plain_significance


def test_lolbin_execution_record_gets_significance():
    f = {"title": "rundll32.exe execution recorded in AppCompatCache",
         "description": "execution records for rundll32.exe; Executed flag TRUE"}
    sig = plain_significance(f)
    assert sig, "LOLBIN execution finding must not have an empty significance"
    assert "living-off-the-land" in sig.lower() or "built-in windows tool" in sig.lower()


def test_lolbin_significance_is_balanced_not_alarmist():
    f = {"title": "regsvr32.exe execution from System32 and SysWOW64"}
    sig = plain_significance(f).lower()
    # honest: acknowledges these run on healthy systems, points to next step
    assert "not proof" in sig or "often" in sig or "healthy" in sig


def test_execution_artifact_record_without_lolbin_gets_timeline_significance():
    f = {"title": "Program execution recorded in ShimCache",
         "description": "AppCompatCache shows an Executed flag for the binary"}
    sig = plain_significance(f)
    assert sig
    assert "execution" in sig.lower() and ("timeline" in sig.lower()
                                           or "history" in sig.lower())


def test_more_specific_significance_still_wins_over_lolbin():
    # a LOLBIN that ALSO ran from temp keeps the staging significance (ordered
    # more-specific-first); a LOLBIN with RWX keeps the injection significance.
    f_temp = {"title": "powershell.exe staged in temp directory and executed"}
    assert "temporary or staging folder" in plain_significance(f_temp)
    f_rwx = {"title": "rundll32.exe with RWX memory injection"}
    assert "writable and executable" in plain_significance(f_rwx)


def test_non_lolbin_non_artifact_still_returns_empty():
    f = {"title": "Some unrelated observation about a config value"}
    assert plain_significance(f) == ""

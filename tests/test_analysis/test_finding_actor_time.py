"""Universal WHO/WHEN attribution for findings -- dataset-agnostic, path-SHAPE
based. Cases mirror the Acme live run (users jay-r/bobby, forward-slash IOC
paths, an MFT date in free text)."""

from sift_sentinel.analysis.finding_actor_time import (
    derive_actor, derive_when, actor_time_label,
)


def _f(**kw):
    return dict(kw)


class TestWho:
    def test_user_from_backslash_path_claim(self):
        f = _f(claims=[{"type": "path", "value": r"C:\Users\bobby\Downloads\sdelete.exe"}])
        assert derive_actor(f) == "bobby"

    def test_user_from_forward_slash_ioc(self):
        # Live-run shape: IOC rendered with forward slashes + hyphenated user.
        f = _f(iocs=["users/jay-r/downloads/sdelete64.exe"])
        assert derive_actor(f) == "jay-r"

    def test_user_from_user_account_claim(self):
        f = _f(claims=[{"type": "user_account", "username": "j.doe$"}])
        assert derive_actor(f) == "j.doe$"

    def test_public_profile_is_not_an_actor(self):
        f = _f(claims=[{"type": "path", "value": r"C:\Users\Public\Downloads\x.exe"}])
        assert derive_actor(f) == ""

    def test_system_service_rejected(self):
        f = _f(claims=[{"type": "user_account", "username": "SYSTEM"}])
        assert derive_actor(f) == ""

    def test_no_user_is_honest_blank(self):
        f = _f(claims=[{"type": "path", "value": r"C:\Windows\System32\rundll32.exe"}])
        assert derive_actor(f) == ""

    def test_garbage_username_rejected(self):
        f = _f(claims=[{"type": "path", "value": "/users/a b'; DROP/x"}])
        # "a b'; DROP" fails the username sanity regex -> blank.
        assert derive_actor(f) == ""


class TestWhen:
    def test_structured_timestamp_field_preferred(self):
        f = _f(claims=[{"type": "timestamp", "timestamp": "2020-11-16T14:23:05Z"}])
        assert derive_when(f) == "2020-11-16T14:23:05"

    def test_date_shape_in_free_text(self):
        # Live-run F058: "...executed with command 'D:\\Tools\\MRC.exe' on 2020-11-16".
        f = _f(description="MRC.exe executed on 2020-11-16 with null command line")
        assert derive_when(f) == "2020-11-16"

    def test_no_date_is_honest_blank(self):
        f = _f(description="rundll32.exe LOLBIN execution, no time available")
        assert derive_when(f) == ""

    def test_finding_level_timestamp_field(self):
        # Live-run shape: the finding's OWN top-level execution timestamp
        # (e.g. sdelete exec time). Claims carry no time, only a path.
        f = _f(timestamp="2020-11-11T08:13:00Z",
               claims=[{"type": "path", "value": "users/bobby/downloads/sdelete.exe"}])
        assert derive_when(f) == "2020-11-11T08:13:00"

    def test_finding_level_timestamp_alternate_field_names(self):
        assert derive_when(_f(create_time="2020-11-14T04:58:58.000Z")) == "2020-11-14T04:58:58"
        assert derive_when(_f(event_time="2020-11-16 02:29:33")) == "2020-11-16 02:29:33"

    def test_finding_level_timestamp_takes_priority_over_free_text(self):
        # The curated finding time wins over an incidental date in prose.
        f = _f(timestamp="2020-11-11T08:13:00Z",
               description="first seen around 2019-01-01 in an old log")
        assert derive_when(f) == "2020-11-11T08:13:00"


class TestLabel:
    def test_combined_label(self):
        f = _f(claims=[
            {"type": "path", "value": r"C:\Users\bobby\Downloads\sdelete.exe"},
            {"type": "timestamp", "timestamp": "2020-11-16 14:23"},
        ])
        assert actor_time_label(f) == "Who: bobby · When: 2020-11-16 14:23 UTC"

    def test_who_only(self):
        f = _f(iocs=["users/jay-r/downloads/sdelete64.exe"])
        assert actor_time_label(f) == "Who: jay-r"

    def test_empty_when_neither(self):
        f = _f(claims=[{"type": "path", "value": r"C:\Windows\System32\cmd.exe"}])
        assert actor_time_label(f) == ""

    def test_non_dict_safe(self):
        assert actor_time_label(None) == ""
        assert derive_actor("x") == ""
        assert derive_when([]) == ""

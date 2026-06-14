"""D4: the inv3a reasoning header must name the ACTUAL adjudicating model, not a
hardcoded one. A live run showed 'Opus re-judged ...' while the call went to a
Haiku model id -- a false audit-trail label.

Universal: the display name is DERIVED from the runtime model id's own grammar
(family token + version digits) -- no model name-list, so any future model id
renders correctly. Synthetic inputs only.
"""
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.model_roles import model_display_name  # noqa: E402
from sift_sentinel.reporting.inv3a_reasoning import render_inv3a_reasoning  # noqa: E402

_V = [{"finding_id": "X001", "from": "inconclusive_unresolved",
       "to": "suspicious_needs_review", "disposition": "needs_review",
       "reason": "synthetic reason", "moved": True}]


def test_display_name_derived_from_id_grammar():
    # family token capitalized + dotted version digits, straight from the id
    assert model_display_name("claude-haiku-4-5-20251001") == "Haiku 4.5"
    assert model_display_name("claude-opus-4-8") == "Opus 4.8"
    assert model_display_name("claude-fable-5") == "Fable 5"
    # unknown/future ids degrade gracefully to the id itself, never crash
    assert model_display_name("vendor-new-model-7-1") != ""
    assert model_display_name("") == ""


def test_header_names_actual_model_not_hardcoded():
    out = render_inv3a_reasoning(_V, color=False,
                                 model="claude-haiku-4-5-20251001")
    assert "Haiku 4.5" in out
    assert "Opus" not in out          # the old hardcoded label must be gone


def test_header_generic_when_model_unknown():
    out = render_inv3a_reasoning(_V, color=False)
    assert "re-judged" in out
    assert "Opus" not in out          # never claim a model we cannot prove

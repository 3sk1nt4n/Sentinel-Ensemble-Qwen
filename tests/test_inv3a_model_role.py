"""D8-B: the single inv3a finalize call gets its own model override
(SIFT_MODEL_INV3A) WITHOUT touching label_to_role -- resolve_model raises
ModelNotConfiguredError for unknown roles (no react fallback), so a new role
would turn an unset env into a silent INV3A_FINALIZE=SKIPPED. Instead the
override is resolved in model_for_label: set -> that model for the inv3a label
only; unset -> byte-identical legacy react routing.

Why: inv3a is ONE discriminative call deciding the final FP sweep -- the
cheapest place to buy the strongest model without dragging every ReAct probe
with it. Synthetic env dicts only; no case data.
"""
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.model_roles import model_for_label  # noqa: E402

_BASE = {
    "SIFT_MODEL_REACT": "synthetic-react-model",
    "SIFT_MODEL_ANALYSIS": "synthetic-analysis-model",
}


def test_unset_falls_through_to_react_unchanged():
    assert model_for_label("Inv3a (finalize)", env=dict(_BASE)) == "synthetic-react-model"


def test_set_overrides_only_inv3a():
    env = dict(_BASE, SIFT_MODEL_INV3A="synthetic-strong-model")
    assert model_for_label("Inv3a (finalize)", env=env) == "synthetic-strong-model"
    # every OTHER label is untouched by the inv3a override
    assert model_for_label("Inv3 ReAct probe", env=env) == "synthetic-react-model"
    assert model_for_label("Inv2 (analysis)", env=env) == "synthetic-analysis-model"


def test_blank_value_treated_as_unset():
    env = dict(_BASE, SIFT_MODEL_INV3A="   ")
    assert model_for_label("Inv3a (finalize)", env=env) == "synthetic-react-model"

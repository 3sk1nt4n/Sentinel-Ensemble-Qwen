import importlib
import sift_sentinel.correction.strategies as st
def test_all_strategy_templates_format_cleanly():
    importlib.reload(st)
    kw = dict(finding_id='F', validation_error='E', failed_claim='C', context_dossier='D')
    for k, s in st.STRATEGIES.items():
        s['template'].format(**kw)

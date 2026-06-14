"""C28 V3 side-test: real-data render non-regression.

Property-based per slot 28. Loads v2 findings_final.json, verifies
every finding renders with non-blank title. No hardcoded finding
IDs, PIDs, or artifact text.
"""
import pytest
import os
import json

STATE_DIR = os.environ.get("SIFT_TEST_STATE_DIR", "")
FF_PATH = f'{STATE_DIR}/findings_final.json'

pytestmark = pytest.mark.skipif(
    not os.path.exists(FF_PATH),
    reason='Run 12-v2 state dir not present',
)


def test_real_v2_findings_all_render_with_content():
    """Property: every v2 finding produces non-blank non-sentinel title."""
    from sift_sentinel.reporting import finding_title

    ff = json.load(open(FF_PATH))
    assert ff, 'findings_final.json empty'

    blank_findings = []
    sentinel_findings = []
    for f in ff:
        title = finding_title(f)
        if not title or not title.strip():
            blank_findings.append(f.get('finding_id', '?'))
        if title == '(no description available)':
            sentinel_findings.append(f.get('finding_id', '?'))

    assert not blank_findings, f'blank titles: {blank_findings}'
    assert not sentinel_findings, (
        f'sentinel rendered for findings that had real content: {sentinel_findings}'
    )


def test_real_v2_html_report_no_empty_h3():
    """Property: rendered HTML has no empty <h3></h3> tags."""
    from sift_sentinel.generate_report import generate_html_report

    ff = json.load(open(FF_PATH))
    html = generate_html_report(ff, {})
    assert '<h3></h3>' not in html, 'empty h3 tags in rendered HTML'
    assert '<h3> </h3>' not in html
    assert '<h3>  </h3>' not in html


def test_real_v2_connection_claims_render_canonical_keys():
    """C27 follow-up property: connection claim badges render foreign_addr:foreign_port,
    never '?:?' placeholder from legacy keys."""
    from sift_sentinel.generate_report import _claim_spans

    ff = json.load(open(FF_PATH))
    conn_claims_found = False
    for f in ff:
        claims = f.get('claims', [])
        conn = [c for c in claims if c.get('type') == 'connection']
        if conn:
            conn_claims_found = True
            html = _claim_spans(conn)
            assert '?:?' not in html, (
                f'C27 follow-up regression on {f.get("finding_id")}: legacy keys rendered {html!r}'
            )
    # Not asserting conn_claims_found because v2 findings collapsed to pid-only post-SC;
    # this test still validates that IF connection claims exist, they render cleanly.

"""C27 V3 side-test: real-data non-regression for connection schema alignment.

Property-based per slot 28. Loads connection from Run 12-v2 reference_set.
No hardcoded IPs, PIDs, ports. Proves end-to-end AI claim -> normalize ->
_check_connection MATCH against real reference set.
"""
import pytest
import os
import json

STATE_DIR = os.environ.get("SIFT_TEST_STATE_DIR", "")
REF_PATH = f'{STATE_DIR}/reference_set.json'

pytestmark = pytest.mark.skipif(
    not os.path.exists(REF_PATH),
    reason='Run 12-v2 state dir not present',
)


def test_real_remote_ip_normalizes_and_matches_validator():
    """AI-style remote_ip claim normalizes to foreign_addr AND matches
    _check_connection against real Run 12-v2 reference_set."""
    from sift_sentinel.validation.normalize_claims import normalize_claims
    from sift_sentinel.validation.validator import _check_connection

    ref = json.load(open(REF_PATH))
    connections = ref.get('connections', {})
    assert connections, "reference_set.json has no connections"

    # Parse real connection key format:
    # "{pid}:{local_addr}:{local_port}->{foreign_addr}:{foreign_port}"
    sample_key = next(iter(connections.keys()))
    owner = connections[sample_key]
    local_part, foreign_part = sample_key.split('->')
    pid = int(local_part.split(':')[0])
    foreign_addr = foreign_part.rsplit(':', 1)[0]

    # AI produces claim using Inv2 legacy alias (pre-C27 drift pattern)
    ai_claim = {
        "type": "connection",
        "pid": pid,
        "process": owner,
        "remote_ip": foreign_addr,
    }

    normalized = normalize_claims([{"claims": [ai_claim]}])[0]["claims"][0]

    # Property 1: alias bridged, legacy key removed
    assert normalized.get("foreign_addr") == foreign_addr, (
        f"remote_ip not bridged to foreign_addr: {normalized}"
    )
    assert "remote_ip" not in normalized, "legacy remote_ip key leaked"

    # Property 2: end-to-end match against real reference set
    # _check_connection returns dict with keys {'claim', 'result', 'detail'}
    result = _check_connection(normalized, ref)
    assert result.get("result") == "MATCH", (
        f"C27 end-to-end failed on real ref: {result}"
    )

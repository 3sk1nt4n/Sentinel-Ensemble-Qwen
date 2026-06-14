"""external_inbound_to_sensitive_listener: a sensitive remote-access listener
on this host with an EXTERNAL foreign peer is the inbound-exposure signal.
Internal peers and benign outbound clients must NOT fire. Dataset-agnostic:
structural port-class + external-IP test, no endpoints."""
import json as J
from sift_sentinel.analysis.malicious_semantics import (
    match_external_inbound_to_sensitive_listener as m)
def _nf(localport, foreignaddr, localaddr="192.168.1.5"):
    return {"fact_type":"network_connection_fact","canonical_entity_id":"pid:1",
            "localport":localport,"foreignaddr":foreignaddr,"localaddr":localaddr,
            "raw_excerpt":J.dumps({"LocalPort":localport,"ForeignAddr":foreignaddr,"LocalAddr":localaddr})}
def test_external_peer_on_sensitive_listener_fires():
    assert m(_nf(3389,"8.8.8.8")) is True
    assert m(_nf(445,"1.1.1.1")) is True
    assert m(_nf(5985,"9.9.9.9")) is True
def test_internal_peer_does_not_fire():
    assert m(_nf(3389,"192.168.1.20")) is False
    assert m(_nf(3389,"10.0.0.5")) is False
    assert m(_nf(3389,"127.0.0.1")) is False
def test_outbound_client_shape_does_not_fire():
    assert m(_nf(61809,"13.107.136.254")) is False
    assert m(_nf(0,"*")) is False
def test_non_network_fact_ignored():
    assert m({"fact_type":"handle_fact","localport":3389,"foreignaddr":"8.8.8.8"}) is False

"""Reasoning-model response extraction (Fable 5 ThinkingBlock).

Fable 5 emits extended-thinking blocks BEFORE the answer text block. A blind
``response.content[0].text`` AttributeErrors on the ThinkingBlock ('ThinkingBlock'
object has no attribute 'text') -- which is exactly what killed all 4 Inv2
ensemble members on the first working Fable 5 run (0 findings).

extract_response_text() must skip any non-text block (thinking, redacted
thinking, tool_use) and return the concatenated answer text, for ANY model.
"""
import types

from sift_sentinel.model_roles import extract_response_text


def _thinking_block():
    # mirrors anthropic.types.ThinkingBlock: has .thinking + .type, NO .text
    return types.SimpleNamespace(type="thinking", thinking="let me reason...")


def _redacted_thinking_block():
    return types.SimpleNamespace(type="redacted_thinking", data="xx")


def _text_block(s):
    return types.SimpleNamespace(type="text", text=s)


def _resp(blocks):
    return types.SimpleNamespace(content=blocks)


def test_thinking_first_then_text_does_not_crash():
    # the exact Fable 5 shape: thinking block at index 0, answer after.
    resp = _resp([_thinking_block(), _text_block('{"findings": []}')])
    assert extract_response_text(resp) == '{"findings": []}'


def test_redacted_thinking_skipped():
    resp = _resp([_redacted_thinking_block(), _text_block("answer")])
    assert extract_response_text(resp) == "answer"


def test_multiple_text_blocks_concatenated():
    resp = _resp([_thinking_block(), _text_block("a"), _text_block("b")])
    assert extract_response_text(resp) == "ab"


def test_plain_text_only_unchanged():
    resp = _resp([_text_block("hello")])
    assert extract_response_text(resp) == "hello"


def test_empty_content_returns_empty_string():
    assert extract_response_text(_resp([])) == ""
    assert extract_response_text(types.SimpleNamespace(content=None)) == ""


def test_old_blind_index0_would_have_crashed():
    # documents the bug: content[0].text raises on the thinking block.
    resp = _resp([_thinking_block(), _text_block("x")])
    import pytest
    with pytest.raises(AttributeError):
        _ = resp.content[0].text
    # the helper does not.
    assert extract_response_text(resp) == "x"

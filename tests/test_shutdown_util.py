"""Graceful Ctrl-C: the MCP server subprocess and the local-first parser workers each
receive SIGINT at the same instant as the launcher (one foreground process group). anyio
wraps the resulting cancellation / closed-pipe errors in a BaseExceptionGroup. This
predicate lets those subprocesses recognise a pure shutdown and exit QUIETLY instead of
dumping a traceback over the launcher's 'Goodbye'. Universal: type-name based, no case
data.
"""
from sift_sentinel.shutdown_util import is_benign_shutdown_exc


def test_keyboard_interrupt_is_benign():
    assert is_benign_shutdown_exc(KeyboardInterrupt()) is True


def test_broken_pipe_is_benign():
    assert is_benign_shutdown_exc(BrokenPipeError()) is True


def test_cancelled_error_is_benign():
    import asyncio
    assert is_benign_shutdown_exc(asyncio.CancelledError()) is True


def test_real_error_is_not_benign():
    assert is_benign_shutdown_exc(ValueError("boom")) is False
    assert is_benign_shutdown_exc(RuntimeError("nope")) is False


def test_group_all_benign_is_benign():
    g = BaseExceptionGroup("shutdown", [BrokenPipeError(), KeyboardInterrupt()])
    assert is_benign_shutdown_exc(g) is True


def test_group_with_one_real_error_is_not_benign():
    g = BaseExceptionGroup("mixed", [BrokenPipeError(), ValueError("boom")])
    assert is_benign_shutdown_exc(g) is False


def test_nested_group_all_benign_is_benign():
    inner = BaseExceptionGroup("inner", [BrokenPipeError()])
    outer = BaseExceptionGroup("outer", [inner, KeyboardInterrupt()])
    assert is_benign_shutdown_exc(outer) is True


def test_none_is_not_benign():
    assert is_benign_shutdown_exc(None) is False

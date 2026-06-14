"""Graceful Ctrl-C must STOP the running tools, not just print 'Goodbye'.

The MCP tool server is spawned start_new_session=True (its own session/group), so a
terminal Ctrl-C reaches only the launcher's foreground group -- never the detached server
or the Volatility subprocesses it launched. Without an explicit reap, those keep grinding
the remaining tool batch to completion after the launcher has exited (the symptom: vol
tools logging for ~90s after 'Goodbye'). kill_child_process_trees() reaps the whole
descendant tree. Universal: structural process-tree walk, no case data.
"""
import subprocess
import sys
import time

import psutil

from sift_sentinel.proc_cleanup import kill_child_process_trees


def test_no_children_returns_zero():
    # nothing spawned -> nothing to kill (must not raise)
    assert kill_child_process_trees(grace_seconds=0.2) == 0


def test_kills_detached_child_and_grandchild_tree():
    # a DETACHED child (own session, like the MCP server) that itself spawns a
    # grandchild (like a vol.py subprocess). Terminal signals would not reach these.
    child = subprocess.Popen(
        [sys.executable, "-c",
         "import subprocess,sys,time;"
         "subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);"
         "time.sleep(60)"],
        start_new_session=True,
    )
    try:
        time.sleep(0.6)  # let the grandchild spawn
        grandkids = psutil.Process(child.pid).children(recursive=True)
        assert grandkids, "expected a grandchild to exist before kill"

        killed = kill_child_process_trees(grace_seconds=1.0)
        assert killed >= 2  # child + grandchild

        # we are the child's parent -> reap it and confirm it terminated
        assert child.wait(timeout=5) is not None

        # the grandchild (reparented to init) must be gone within a moment
        deadline = time.time() + 3
        while time.time() < deadline and any(
                g.is_running() and g.status() != psutil.STATUS_ZOMBIE for g in grandkids):
            time.sleep(0.1)
        for g in grandkids:
            assert (not g.is_running()) or g.status() == psutil.STATUS_ZOMBIE
    finally:
        try:
            child.kill()
        except Exception:
            pass

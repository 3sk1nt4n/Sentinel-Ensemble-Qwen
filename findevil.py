#!/usr/bin/env python3
"""findevil - the Sentinel Qwen Ensemble pipeline starter.

The one front door for users. It delegates 1:1 to the conversational
onboarding (step0_onboard.py) so there is exactly one launch flow to
maintain; every flag below is step0_onboard's flag.

  ./findevil.py                       ask one question: where is the evidence
  ./findevil.py /evidence             start directly on a path
  ./findevil.py --demo                synthetic walkthrough (no evidence, no API key)
  ./findevil.py --dry-run /evidence   full onboarding + printed FIND plan, no pipeline

findevil is LIVE by default: typing FIND at the ready prompt launches the
real pipeline. (Developers can stage the launch with SIFT_FIND_WIRED=0, or
invoke step0_onboard.py directly, which stays staged unless --wire.)
"""

import os
import sys

_REPO_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _REPO_DIR)

# Windows consoles/pipes can default to a legacy codepage (cp1252) that cannot
# print the onboarding's arrows/checkmarks - a junior's first `--demo` would
# crash with UnicodeEncodeError. Force UTF-8 with safe replacement instead.
if os.name == "nt":
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass

# If ./setup.sh --native created .venv but this file was launched as a script
# with a DIFFERENT interpreter (e.g. `python3 findevil.py --demo` in a fresh
# shell), re-exec into the venv python so the installed dependencies are found
# with NO manual activation. `__name__` keeps this import-safe: it never fires
# when a test (or anything else) imports this module. sys.prefix identifies
# the running venv even when .venv/bin/python3 is a symlink to the system
# binary. A venv the user activated themselves (VIRTUAL_ENV) is respected.
# SIFT_NO_VENV_REEXEC=1 opts out (developers testing against another env).
_VENV_DIR = os.path.join(_REPO_DIR, ".venv")
_VENV_PY = os.path.join(_VENV_DIR, "bin", "python3")
if (
    __name__ == "__main__"
    and os.name != "nt"
    and not os.environ.get("VIRTUAL_ENV")
    and not os.environ.get("SIFT_NO_VENV_REEXEC")
    and os.access(_VENV_PY, os.X_OK)
    and os.path.realpath(sys.prefix) != os.path.realpath(_VENV_DIR)
):
    os.environ["SIFT_NO_VENV_REEXEC"] = "1"  # belt + suspenders vs. exec loops
    # Mirror what activation would do, so venv-installed CLIs (e.g. vol) are
    # also findable by the re-exec'd process and its children.
    os.environ["VIRTUAL_ENV"] = _VENV_DIR
    os.environ["PATH"] = (
        os.path.join(_VENV_DIR, "bin") + os.pathsep + os.environ.get("PATH", "")
    )
    os.execv(_VENV_PY, [_VENV_PY, os.path.abspath(__file__)] + sys.argv[1:])

import step0_onboard


def main(argv=None) -> int:
    # Customer front door = live FIND, no developer flags needed.
    # setdefault so an explicit SIFT_FIND_WIRED=0 still stages the launch.
    os.environ.setdefault("SIFT_FIND_WIRED", "1")
    return step0_onboard.main(argv)


if __name__ == "__main__":
    sys.exit(main())

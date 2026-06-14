#!/usr/bin/env python3
"""findevil — the Sentinel Ensemble pipeline starter.

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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import step0_onboard


def main(argv=None) -> int:
    # Customer front door = live FIND, no developer flags needed.
    # setdefault so an explicit SIFT_FIND_WIRED=0 still stages the launch.
    os.environ.setdefault("SIFT_FIND_WIRED", "1")
    return step0_onboard.main(argv)


if __name__ == "__main__":
    sys.exit(main())

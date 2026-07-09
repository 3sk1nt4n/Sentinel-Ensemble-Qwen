#!/usr/bin/env python3
"""Isolated subprocess worker for heavy local-first parsers.

Launched via subprocess (NOT multiprocessing spawn) so it runs as its own
__main__ and never re-imports the orchestrator __main__ (run_pipeline.py),
which is not import-safe and would re-run the entire pipeline.

Protocol: read one JSON object from stdin -> {"target":"<module>.<qualname>",
"kwargs":{...}}; import target, call it, write the JSON result to stdout.
All logging goes to stderr so stdout carries only JSON.
"""
import os, sys, json, importlib, logging
from pathlib import Path

_SRC = Path(__file__).resolve().parents[2]   # tools -> sift_sentinel -> src
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

logging.basicConfig(stream=sys.stderr, level=logging.INFO,
                    format="%(asctime)s %(name)s %(levelname)s %(message)s")


def _resolve(target):
    mod_name, _, qual = target.rpartition(".")
    if not mod_name:
        raise ValueError("bad target: %r" % target)
    obj = importlib.import_module(mod_name)
    for part in qual.split("."):
        obj = getattr(obj, part)
    return obj


def main():
    raw = sys.stdin.read()
    try:
        req = json.loads(raw) if raw.strip() else {}
    except Exception as exc:
        json.dump({"output": [], "record_count": 0,
                   "error": "worker bad request json: %s" % exc,
                   "failure_mode": "bad_request"}, sys.stdout)
        return 0
    target = req.get("target", "")
    kwargs = req.get("kwargs", {}) or {}
    try:
        fn = _resolve(target)
        result = fn(**kwargs)
        if not isinstance(result, dict):
            result = {"output": [], "record_count": 0,
                      "error": "target returned non-dict",
                      "failure_mode": "bad_result"}
    except Exception as exc:
        logging.getLogger("evtx_worker").exception("target failed")
        result = {"output": [], "record_count": 0,
                  "error": "%s: %s" % (type(exc).__name__, exc),
                  "failure_mode": "worker_exception"}
    json.dump(result, sys.stdout, default=str)
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        # Ctrl-C reaches the whole foreground process group; this worker gets SIGINT at
        # the same instant as the launcher. Exit quietly (130) without dumping a traceback
        # over the launcher's shutdown message -- the parent treats a missing/short result
        # as a normal degrade. os._exit avoids a second broken-pipe flush on the way out.
        os._exit(130)

"""SIFT-Sentinel Step-Zero onboarding.

engine.py    -- deterministic, headless probe orchestration that emits
                structured PhaseEvents (no rendering, no TTY).
presenter.py -- pure-stdlib terminal rendering that subscribes to those
                events. Engine works without the presenter; the presenter
                never touches evidence.
"""

# Artifacts

This package provides the typed, append-only-ish artifact store for multi-agent runs.

Key files:
- `schema.py` - Typed artifact models (code review notes, hypotheses, PoC recipe, validation, report).
- `store.py` - Filesystem-backed store with `index.json` and `events.jsonl`. Thread-safe via `threading.Lock` for parallel file-level hypothesis scanning.

The store writes to `output/<run_id>/` and records per-agent trajectories, logs, and produced artifacts (PoC input, generator script, report).

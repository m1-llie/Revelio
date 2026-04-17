#!/usr/bin/env python3
"""Probe each (model, api_key_env) pair in a jobs.tsv with a tiny LiteLLM call.

Run from the repo root, for example:

    python scripts/batch_scan_filter/probe_keys.py
    python scripts/batch_scan_filter/probe_keys.py scripts/batch_scan_filter/jobs.poppler-retry.tsv

For each unique (model, api_key_env) tuple in the TSV we:
  * read the env var (never printed; we only show length + last-4 chars),
  * send a 1-token "ping" completion via LiteLLM using the same model slug
    the batch runner will use,
  * report PASS / QUOTA / AUTH / MODEL / RATE / NET / OTHER / MISSING with
    a short cause and round-trip timing.

Exit status is 0 iff every key succeeds. The batch runner would also mark
quota/auth keys dead automatically, but probing up front avoids wasting a
real scan_filter call on a broken key.
"""
from __future__ import annotations

import os
import re
import sys
import time
from pathlib import Path

DEFAULT_JOBS_TSV = Path("scripts/batch_scan_filter/jobs.tsv")
DEFAULT_ENV_FILE = Path("scripts/batch_scan_filter/.env")


def load_env_file(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def parse_jobs(tsv: Path):
    """Return unique (model, env_var) pairs preserving first-seen order."""
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    for raw in tsv.read_text().splitlines():
        if not raw or raw.lstrip().startswith("#"):
            continue
        cols = raw.split("\t")
        if len(cols) < 4:
            continue
        model, env = cols[2], cols[3]
        key = (model, env)
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def hint(val: str) -> str:
    if not val:
        return "(empty)"
    return f"len={len(val)} ...{val[-4:]}"


def classify(err: str) -> tuple[str, str]:
    e = err.lower()
    if re.search(r"model[_ ]?not[_ ]?found|not a valid model|unknown model|\b404\b.*model", e):
        return "MODEL", "model slug not recognized by provider"
    if re.search(
        r"insufficient_quota|credit balance is too low|exceeded your (monthly|current) quota|"
        r"quota.?exceeded|payment required|\b402\b|out of credits|"
        r"workspace api usage limits?|reached your (specified )?(monthly|daily|workspace) "
        r"(usage|spend|api) limit|usage limit (has been )?(reached|exceeded)|"
        r"spend limit|monthly budget|budget (exceeded|exhausted)",
        e,
    ):
        return "QUOTA", "quota / credit / workspace cap exhausted"
    if re.search(
        r"invalid[_ -]?api[_ -]?key|authentication[_ ]?error|incorrect api key|"
        r"\b401\b|permissiondenied|\b403\b",
        e,
    ):
        return "AUTH", "key rejected"
    if re.search(r"rate[_ -]?limit|\b429\b|overloaded", e):
        return "RATE", "rate limited (key OK but throttled)"
    if re.search(r"timeout|timed out|connection reset|readtimeout|connecttimeout|unreachable|dns", e):
        return "NET", "network transient"
    return "OTHER", err.strip().splitlines()[-1][:160]


def probe(model: str, env_var: str) -> tuple[str, str]:
    import litellm  # imported lazily so --help is fast if litellm missing

    api_key = os.environ.get(env_var, "")
    if not api_key:
        return ("MISSING", f"${env_var} empty")
    try:
        resp = litellm.completion(
            model=model,
            api_key=api_key,
            messages=[{"role": "user", "content": "ping"}],
            max_tokens=4,
            timeout=30,
        )
        txt = ""
        try:
            txt = (resp.choices[0].message.content or "").strip().replace("\n", " ")[:40]
        except Exception:
            pass
        return ("OK", f"reply={txt!r}")
    except Exception as e:
        return classify(f"{type(e).__name__}: {e}")


def main() -> int:
    args = sys.argv[1:]
    if args and args[0] in ("-h", "--help"):
        print(__doc__.strip())
        return 0
    jobs_tsv = Path(args[0]) if args else DEFAULT_JOBS_TSV
    env_file = Path(os.environ.get("ENV_FILE", DEFAULT_ENV_FILE))

    if not jobs_tsv.exists():
        print(f"FATAL: jobs file '{jobs_tsv}' not found", file=sys.stderr)
        return 2

    load_env_file(env_file)
    pairs = parse_jobs(jobs_tsv)
    if not pairs:
        print(f"no (model, env) pairs found in {jobs_tsv}", file=sys.stderr)
        return 2

    print(f"probing {len(pairs)} key/model combinations from {jobs_tsv}")
    print(f"  env file: {env_file}{'' if env_file.exists() else ' (not found; relying on shell env)'}")
    print()
    print(f"{'status':<8}  {'env':<18}  {'model':<42}  note")
    print("-" * 120)

    bad = 0
    for model, env in pairs:
        val = os.environ.get(env, "")
        t0 = time.time()
        cat, note = probe(model, env)
        dt = time.time() - t0
        ok = cat == "OK"
        if not ok:
            bad += 1
        flag = "PASS" if ok else cat
        print(f"{flag:<8}  {env:<18}  {model:<42}  {note}  [{dt:.1f}s, {hint(val)}]")

    print("-" * 120)
    if bad == 0:
        print("all keys usable -> safe to launch the batch.")
        return 0
    print(
        f"{bad} key(s) failed; fix them before launching. "
        "(the runner will auto-mark quota/auth keys dead, but you'd waste 1 real call per key.)"
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Verify post-confirmation dedup without re-running scan_filter or LLM PoV.

Uses Docker + the same validation capture / signature extraction path as
``MultiAgentOrchestrator``, then writes ``dedup_findings.json`` like a real
successful run would.
"""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from revelio.artifacts.schema import ValidationResult
from revelio.artifacts.store import ArtifactStore
from revelio.environments.docker import DockerEnvironment
from revelio.orchestrator.dedup import compute_dedup_report
from revelio.run.crash_signals import (
    build_fallback_signature,
    classify_crash_confidence,
    extract_dedup_token,
)
from revelio.run.detect import load_hypotheses
from revelio.tools.validate import make_validate_tool

# Real ASan output from a confirmed run (revelio-11) — used when a quick validate
# smoke test does not crash, so we can still exercise signature extraction.
_FIXTURE_CRASH_OUTPUT = """\
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x525000002100 at pc 0x561b4e6dd43b bp 0x7ffdf98a9670 sp 0x7ffdf98a9660
READ of size 1 at 0x525000002100 thread T0
    #0 0x561b4e6dd43a in main (/build/fuzzer+0x143a)
0x525000002100 is located 0 bytes after 8192-byte region [0x525000000100,0x525000002100)
allocated by thread T0 here:
    #1 0x561b4e6dd37e in main (/build/fuzzer+0x137e)
SUMMARY: AddressSanitizer: heap-buffer-overflow (/build/fuzzer+0x143a) in main
DEDUP_TOKEN: verify_dedup_fixture_token
"""


def _validation_from_capture(hid: str, capture: list[dict], *, fixture: str | None = None) -> ValidationResult:
    raw = next((rec["output"] for rec in reversed(capture) if rec.get("crash")), None)
    if not raw and fixture:
        raw = fixture
    crashing = next((rec for rec in reversed(capture) if rec.get("crash")), None)
    return ValidationResult(
        hypothesis_id=hid,
        crash_detected=True,
        returncode=(crashing or {}).get("returncode", 1),
        output_excerpt=(raw or "")[:2000],
        dedup_token=extract_dedup_token(raw),
        fallback_signature=build_fallback_signature(raw) if raw else None,
        crash_confidence=classify_crash_confidence(raw),
    )


def main() -> None:
    base_run = Path("output/arvo-42470801-vul_gemini_gemini-2.5-flash_20260707-000039")
    hyps_path = base_run / "hypotheses.json"
    if not hyps_path.exists():
        raise SystemExit(f"Missing hypotheses: {hyps_path}")

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    run_id = f"dedup_verify_live_{ts}"
    store = ArtifactStore(Path("output"), run_id=run_id)
    run_dir = store.run_dir
    shutil.copy2(base_run / "manifest.json", run_dir / "manifest.json")
    shutil.copy2(hyps_path, run_dir / "hypotheses.json")

    hypotheses = load_hypotheses(hyps_path)
    targets = [h.hypothesis_id for h in hypotheses.hypotheses[:2]]
    if len(targets) < 2:
        raise SystemExit("Need at least 2 hypotheses for dedup verification")

    env = DockerEnvironment(image="n132/arvo:42470801-vul", cwd="/src", run_args=[])
    log_lines: list[str] = []
    try:
        capture: list[dict] = []
        validate = make_validate_tool(env, capture=capture)
        env.execute("echo verify_dedup_smoke > /tmp/poc")
        validate("/tmp/poc")
        live_crash = any(rec.get("crash") for rec in capture)
        log_lines.append(f"Docker validate smoke test: live_crash={live_crash}")

        fixture = None if live_crash else _FIXTURE_CRASH_OUTPUT
        if fixture:
            log_lines.append("Using fixture ASan output to exercise signature capture")

        for hid in targets:
            cap: list[dict] = list(capture) if live_crash else []
            if fixture:
                cap.append({"sanitizer": None, "crash": True, "returncode": 1, "output": fixture})
            val = _validation_from_capture(hid, cap, fixture=fixture)
            store.write_handoff("validation", val, hypothesis_id=hid)
            log_lines.append(
                f"Wrote validation_{hid}.json token={val.dedup_token} "
                f"confidence={val.crash_confidence}"
            )

        dedup_report = compute_dedup_report(store.layout.handoffs_dir)
        store.write_handoff("dedup_findings", dedup_report)
        if dedup_report.duplicate_of:
            log_lines.append(
                f"Findings dedup: {len(dedup_report.duplicate_of)} duplicate(s) folded into "
                f"{len(targets) - len(dedup_report.duplicate_of)} unique finding(s)."
            )
        else:
            log_lines.append("Findings dedup: no duplicates (distinct signatures)")

        store.append_event("run_success_all", {"count": len(targets)})
        (run_dir / "log.txt").write_text("\n".join(log_lines) + "\n")
        print(json.dumps({"run_dir": str(run_dir), "dedup": dedup_report.to_dict()}, indent=2))
    finally:
        env.cleanup()


if __name__ == "__main__":
    main()

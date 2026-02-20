"""Filesystem-backed artifact store for multi-agent runs.

Layout (per run_id):
  run_id/
    manifest.json
    events.jsonl         # real-time append-only event log
    log.txt              # human-readable log
    trajectory.json      # aggregated per-agent trajectories
    artifacts/
      handoffs/          # deterministic inter-agent handoff records
      deliverables/      # final outputs: reports, PoC scripts, PoC inputs
"""

from __future__ import annotations

import json
import shutil
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vulagent.artifacts.schema import ArtifactMeta, serialize_artifact


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_run_id(prefix: str | None = None) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    suffix = uuid.uuid4().hex[:8]
    return f"{prefix + '-' if prefix else ''}{ts}-{suffix}"


@dataclass
class RunLayout:
    run_dir: Path
    artifacts_dir: Path
    handoffs_dir: Path
    deliverables_dir: Path


class ArtifactStore:
    """Append-only artifact store with event log and deterministic handoff records."""

    def __init__(self, root: Path | str, run_id: str | None = None):
        self.root = Path(root).resolve()
        self.run_id = run_id or new_run_id("run")
        self.run_dir = (self.root / self.run_id).resolve()
        self.layout = self._init_layout(self.run_dir)
        self._events_path = self.run_dir / "events.jsonl"
        self._manifest_path = self.run_dir / "manifest.json"
        self._trajectory_path = self.run_dir / "trajectory.json"

    def _init_layout(self, run_dir: Path) -> RunLayout:
        artifacts = run_dir / "artifacts"
        layout = RunLayout(
            run_dir=run_dir,
            artifacts_dir=artifacts,
            handoffs_dir=artifacts / "handoffs",
            deliverables_dir=artifacts / "deliverables",
        )
        for d in (layout.artifacts_dir, layout.handoffs_dir, layout.deliverables_dir):
            d.mkdir(parents=True, exist_ok=True)
        return layout

    # ── manifest ──

    def save_manifest(self, manifest: dict[str, Any]) -> Path:
        self._manifest_path.write_text(json.dumps(manifest, indent=2))
        return self._manifest_path

    # ── events (real-time append-only record) ──

    def append_event(self, event_type: str, payload: dict[str, Any] | None = None) -> None:
        record = {
            "timestamp": _now_utc_iso(),
            "event": event_type,
            "payload": payload or {},
        }
        with self._events_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

    # ── handoffs (deterministic inter-agent data) ──

    def _handoff_path(self, stage: str, hypothesis_id: str | None = None, attempt: int | None = None) -> Path:
        parts = [stage]
        if hypothesis_id:
            parts.append(hypothesis_id)
        if attempt is not None:
            parts.append(f"attempt{attempt}")
        return self.layout.handoffs_dir / f"{'_'.join(parts)}.json"

    def write_handoff(
        self,
        stage: str,
        data: Any,
        *,
        hypothesis_id: str | None = None,
        attempt: int | None = None,
    ) -> Path:
        """Write an inter-agent handoff record to disk."""
        path = self._handoff_path(stage, hypothesis_id, attempt)
        content = {
            "stage": stage,
            "hypothesis_id": hypothesis_id,
            "attempt": attempt,
            "created_at": _now_utc_iso(),
            "data": serialize_artifact(data),
        }
        path.write_text(json.dumps(content, indent=2))
        return path

    def read_handoff(
        self,
        stage: str,
        *,
        hypothesis_id: str | None = None,
        attempt: int | None = None,
    ) -> dict[str, Any] | None:
        """Read an inter-agent handoff record from disk. Returns None if not found."""
        path = self._handoff_path(stage, hypothesis_id, attempt)
        if not path.exists():
            return None
        return json.loads(path.read_text())

    # ── deliverables (reports, PoC scripts, PoC inputs) ──

    def save_deliverable(self, src: Path, *, filename: str | None = None) -> Path:
        """Copy or move a file into the deliverables folder."""
        dest = self.layout.deliverables_dir / (filename or src.name)
        shutil.copy2(src, dest)
        self.append_event("deliverable_saved", {"path": str(dest.name)})
        return dest

    def save_report_meta(self, data: Any, *, hypothesis_id: str, meta: ArtifactMeta | None = None) -> Path:
        """Save structured report metadata as JSON."""
        path = self.layout.deliverables_dir / f"report_{hypothesis_id}.json"
        content = {
            "meta": meta.to_dict() if meta else {"artifact_type": "BugReport"},
            "data": serialize_artifact(data),
        }
        path.write_text(json.dumps(content, indent=2))
        return path

    # ── trajectory ──

    def write_aggregated_trajectory(self, trajectories: dict[str, Any]) -> Path:
        self._trajectory_path.write_text(json.dumps(trajectories, indent=2))
        return self._trajectory_path

    # ── external file registration (records in event log) ──

    def register_artifact(self, path: Path, *, artifact_type: str) -> None:
        """Record that an external file (e.g. copied from container) now lives in the run dir."""
        try:
            rel = path.resolve().relative_to(self.run_dir)
        except ValueError:
            rel = path
        self.append_event("artifact_registered", {
            "type": artifact_type,
            "path": str(rel),
        })

    # ── raw text (for parse-failure debugging) ──

    def save_raw_output(self, text: str, *, stage: str, hypothesis_id: str | None = None) -> Path:
        parts = ["raw", stage]
        if hypothesis_id:
            parts.append(hypothesis_id)
        path = self.layout.artifacts_dir / f"{'_'.join(parts)}.txt"
        path.write_text(text)
        return path

    # ── properties ──

    @property
    def manifest_path(self) -> Path:
        return self._manifest_path

    @property
    def events_path(self) -> Path:
        return self._events_path

    @property
    def aggregated_trajectory_path(self) -> Path:
        return self._trajectory_path

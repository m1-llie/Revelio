"""Filesystem-backed artifact store for multi-agent runs.

Layout (per run_id):
  run_id/
    manifest.json
    index.json
    events.jsonl
    artifacts/
      code_review/
      hypotheses/
      poc/
      validation/
      reports/
      trajectories/
      logs/
    trajectory.json   # aggregated per-agent trajectories (optional)
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import asdict, dataclass, field
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
    code_review_dir: Path
    hypotheses_dir: Path
    poc_dir: Path
    validation_dir: Path
    reports_dir: Path
    trajectories_dir: Path
    logs_dir: Path


@dataclass
class IndexEntry:
    artifact_type: str
    path: str
    created_at: str
    meta: dict[str, Any] = field(default_factory=dict)


class ArtifactStore:
    """Append-only-ish artifact store with JSON index and event log."""

    def __init__(self, root: Path | str, run_id: str | None = None):
        self.root = Path(root)
        self.run_id = run_id or new_run_id("run")
        self.run_dir = self.root / self.run_id
        self.layout = self._init_layout(self.run_dir)
        self._index_path = self.run_dir / "index.json"
        self._events_path = self.run_dir / "events.jsonl"
        self._manifest_path = self.run_dir / "manifest.json"
        self._trajectory_path = self.run_dir / "trajectory.json"
        self._init_index()

    def _init_layout(self, run_dir: Path) -> RunLayout:
        artifacts = run_dir / "artifacts"
        layout = RunLayout(
            run_dir=run_dir,
            artifacts_dir=artifacts,
            code_review_dir=artifacts / "code_review",
            hypotheses_dir=artifacts / "hypotheses",
            poc_dir=artifacts / "poc",
            validation_dir=artifacts / "validation",
            reports_dir=artifacts / "reports",
            trajectories_dir=artifacts / "trajectories",
            logs_dir=artifacts / "logs",
        )
        for path in asdict(layout).values():
            Path(path).mkdir(parents=True, exist_ok=True)
        return layout

    def _init_index(self) -> None:
        if self._index_path.exists():
            return
        data = {
            "run_id": self.run_id,
            "created_at": _now_utc_iso(),
            "counters": {},
            "artifacts": {},
        }
        self._index_path.write_text(json.dumps(data, indent=2))

    def _read_index(self) -> dict[str, Any]:
        return json.loads(self._index_path.read_text())

    def _write_index(self, data: dict[str, Any]) -> None:
        self._index_path.write_text(json.dumps(data, indent=2))

    def _next_id(self, category: str) -> int:
        index = self._read_index()
        counters = index.setdefault("counters", {})
        next_id = int(counters.get(category, 0)) + 1
        counters[category] = next_id
        self._write_index(index)
        return next_id

    def _register(self, category: str, entry: IndexEntry) -> None:
        index = self._read_index()
        artifacts = index.setdefault("artifacts", {})
        artifacts.setdefault(category, []).append(asdict(entry))
        self._write_index(index)

    def save_manifest(self, manifest: dict[str, Any]) -> Path:
        self._manifest_path.write_text(json.dumps(manifest, indent=2))
        return self._manifest_path

    def append_event(self, event_type: str, payload: dict[str, Any] | None = None) -> None:
        record = {
            "timestamp": _now_utc_iso(),
            "event": event_type,
            "payload": payload or {},
        }
        with self._events_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")

    def append_log_line(self, message: str, *, agent: str | None = None, event: str | None = None) -> Path:
        ts = _now_utc_iso()
        parts = [ts]
        if agent:
            parts.append(f"agent={agent}")
        if event:
            parts.append(f"event={event}")
        line = " | ".join(parts) + f" | message={message}"
        log_path = self.layout.logs_dir / "run.log"
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        return log_path

    def append_json_artifact(
        self,
        category: str,
        data: Any,
        *,
        name: str | None = None,
        meta: ArtifactMeta | None = None,
    ) -> Path:
        artifact_id = self._next_id(category)
        filename = name or f"{artifact_id:04d}_{meta.artifact_type if meta else 'artifact'}.json"
        path = (self.layout.artifacts_dir / category / filename).resolve()
        payload = serialize_artifact(data)
        content = {
            "meta": (meta.to_dict() if meta else {"artifact_type": meta.artifact_type if meta else category}),
            "data": payload,
        }
        path.write_text(json.dumps(content, indent=2))
        entry = IndexEntry(
            artifact_type=(meta.artifact_type if meta else category),
            path=str(path.relative_to(self.run_dir)),
            created_at=_now_utc_iso(),
            meta=meta.to_dict() if meta else {},
        )
        self._register(category, entry)
        return path

    def append_text_artifact(
        self,
        category: str,
        text: str,
        *,
        name: str,
        meta: ArtifactMeta | None = None,
    ) -> Path:
        artifact_id = self._next_id(category)
        filename = f"{artifact_id:04d}_{name}"
        path = (self.layout.artifacts_dir / category / filename).resolve()
        path.write_text(text)
        entry = IndexEntry(
            artifact_type=(meta.artifact_type if meta else category),
            path=str(path.relative_to(self.run_dir)),
            created_at=_now_utc_iso(),
            meta=meta.to_dict() if meta else {},
        )
        self._register(category, entry)
        return path

    def append_blob_artifact(
        self,
        category: str,
        data: bytes,
        *,
        name: str,
        meta: ArtifactMeta | None = None,
    ) -> Path:
        artifact_id = self._next_id(category)
        filename = f"{artifact_id:04d}_{name}"
        path = (self.layout.artifacts_dir / category / filename).resolve()
        path.write_bytes(data)
        entry = IndexEntry(
            artifact_type=(meta.artifact_type if meta else category),
            path=str(path.relative_to(self.run_dir)),
            created_at=_now_utc_iso(),
            meta=meta.to_dict() if meta else {},
        )
        self._register(category, entry)
        return path

    def append_trajectory(self, agent_name: str, trajectory: dict[str, Any]) -> Path:
        meta = ArtifactMeta(artifact_type="Trajectory", agent_name=agent_name)
        name = f"trajectory_{agent_name}.json"
        return self.append_json_artifact("trajectories", trajectory, name=name, meta=meta)

    def register_existing(
        self,
        category: str,
        path: Path,
        *,
        artifact_type: str | None = None,
        meta: ArtifactMeta | None = None,
    ) -> None:
        """Register an existing file in the index (no copying)."""
        rel_path = path.resolve().relative_to(self.run_dir)
        entry = IndexEntry(
            artifact_type=artifact_type or (meta.artifact_type if meta else category),
            path=str(rel_path),
            created_at=_now_utc_iso(),
            meta=meta.to_dict() if meta else {},
        )
        self._register(category, entry)

    def write_aggregated_trajectory(self, trajectories: dict[str, Any]) -> Path:
        self._trajectory_path.write_text(json.dumps(trajectories, indent=2))
        return self._trajectory_path

    @property
    def manifest_path(self) -> Path:
        return self._manifest_path

    @property
    def index_path(self) -> Path:
        return self._index_path

    @property
    def events_path(self) -> Path:
        return self._events_path

    @property
    def aggregated_trajectory_path(self) -> Path:
        return self._trajectory_path

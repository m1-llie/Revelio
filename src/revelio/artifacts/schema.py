"""Typed artifact schemas for multi-agent vulnerability detection runs."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _as_dict(obj: Any) -> dict[str, Any]:
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    if hasattr(obj, "__dataclass_fields__"):
        return asdict(obj)
    if isinstance(obj, dict):
        return obj
    return {"value": obj}


@dataclass
class ArtifactMeta:
    """Metadata recorded for every stored artifact."""

    artifact_type: str
    created_at: str = field(default_factory=_now_utc_iso)
    agent_name: str | None = None
    hypothesis_id: str | None = None
    notes: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RunManifest:
    """Basic information about a run and its target."""

    run_id: str
    target_type: str  # "arvo" or "project"
    target_ref: str   # image tag or local path
    created_at: str = field(default_factory=_now_utc_iso)
    config_path: str | None = None
    model_name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CodeReference:
    file_path: str
    line_start: int | None = None
    line_end: int | None = None
    function: str | None = None
    context: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CodeReviewNotes:
    summary: str
    files_reviewed: list[str] = field(default_factory=list)
    harness_entry: str | None = None
    call_chains: list[str] = field(default_factory=list)
    hotspots: list[CodeReference] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["hotspots"] = [h.to_dict() for h in self.hotspots]
        return data


@dataclass
class VulnHypothesis:
    hypothesis_id: str
    title: str
    description: str
    file_path: str | None = None
    function: str | None = None
    trigger: str | None = None
    preconditions: list[str] = field(default_factory=list)
    expected_crash: str | None = None
    confidence: float = 0.0
    references: list[CodeReference] = field(default_factory=list)
    # Triage metadata set by the Stage 2 classifier / Stage 2 reachability pass.
    # All optional for backward compatibility with older hypotheses.json files.
    severity: str = "none"               # none | low | medium | high | critical
    primitive: str = "none"              # oob-write | oob-read | uaf | double-free |
                                         # type-confusion | int-overflow | uninit |
                                         # deref | none
    attacker_controls: str = "none"      # input | api | none
    sanitizers: list[str] = field(default_factory=list)  # subset of {asan,ubsan,msan}
    cwe_ids: list[str] = field(default_factory=list)
    reachable: bool | None = None        # None=unknown; True/False from `arvo targets`
    fuzz_targets: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["references"] = [r.to_dict() for r in self.references]
        return data


@dataclass
class VulnHypotheses:
    hypotheses: list[VulnHypothesis]
    generation_notes: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypotheses": [h.to_dict() for h in self.hypotheses],
            "generation_notes": self.generation_notes,
        }


@dataclass
class PoCRecipe:
    hypothesis_id: str
    script_path: str
    input_path: str
    expected_signal: str | None = None
    generation_steps: list[str] = field(default_factory=list)
    reproduction_command: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ValidationResult:
    hypothesis_id: str
    crash_detected: bool
    returncode: int | None = None
    output_excerpt: str | None = None
    indicators: list[str] = field(default_factory=list)
    reproduction_command: str | None = None
    logs_path: str | None = None
    evidence_paths: list[str] = field(default_factory=list)
    # Crash signature for post-confirmation findings dedup (see orchestrator/dedup.py).
    dedup_token: str | None = None
    crash_summary: str | None = None
    fallback_signature: str | None = None
    # "sanitizer" if a real sanitizer/fuzzer banner fired, "generic" if the crash is a
    # bare signal death or unattributed runtime assertion (see crash_signals.classify_crash_confidence).
    crash_confidence: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BugReport:
    hypothesis_id: str
    report_path: str
    summary: str | None = None
    references: list[CodeReference] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["references"] = [r.to_dict() for r in self.references]
        return data


@dataclass
class DedupGroup:
    """One group of confirmed findings sharing a crash signature."""

    signature_type: str  # "dedup_token" | "fallback"
    signature: str
    canonical_hid: str
    duplicate_hids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DedupReport:
    """Result of grouping a run's confirmed findings by crash signature."""

    groups: list[DedupGroup] = field(default_factory=list)
    duplicate_of: dict[str, str] = field(default_factory=dict)  # hid -> canonical hid

    def to_dict(self) -> dict[str, Any]:
        return {
            "groups": [g.to_dict() for g in self.groups],
            "duplicate_of": dict(self.duplicate_of),
        }


def serialize_artifact(obj: Any) -> dict[str, Any]:
    """Serialize a schema object into a JSON-friendly dict."""
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    if isinstance(obj, dict):
        return obj
    if isinstance(obj, Iterable) and not isinstance(obj, (str, bytes, bytearray)):
        return {"items": [_as_dict(item) for item in obj]}
    return _as_dict(obj)

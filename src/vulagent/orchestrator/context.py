"""Context packet builder for artifact-to-prompt injection."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import yaml

from vulagent.artifacts.schema import serialize_artifact


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)] + "..."


def _trim_list(items: list[Any], limit: int) -> list[Any]:
    if len(items) <= limit:
        return items
    return items[:limit]


def _maybe_dict(obj: Any) -> dict[str, Any]:
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return obj
    return serialize_artifact(obj)


@dataclass
class ContextPacket:
    role: str
    run: dict[str, Any] = field(default_factory=dict)
    hypothesis_id: str | None = None
    sections: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "run": self.run,
            "hypothesis_id": self.hypothesis_id,
            "sections": self.sections,
        }

    def to_yaml(self) -> str:
        return yaml.safe_dump(self.to_dict(), sort_keys=False)


class ContextPacketBuilder:
    """Build compact, role-specific context packets from global artifacts."""

    def __init__(
        self,
        *,
        max_str_len: int = 1200,
        max_list_len: int = 8,
        max_refs: int = 6,
    ):
        self.max_str_len = max_str_len
        self.max_list_len = max_list_len
        self.max_refs = max_refs

    def _compact_refs(self, refs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        trimmed = _trim_list(refs, self.max_refs)
        for ref in trimmed:
            if "context" in ref and isinstance(ref["context"], str):
                ref["context"] = _truncate(ref["context"], self.max_str_len)
        return trimmed

    def _compact_section(self, section: dict[str, Any]) -> dict[str, Any]:
        compacted: dict[str, Any] = {}
        for key, value in section.items():
            if isinstance(value, str):
                compacted[key] = _truncate(value, self.max_str_len)
            elif isinstance(value, list):
                compacted[key] = _trim_list(value, self.max_list_len)
            elif isinstance(value, dict):
                compacted[key] = value
            else:
                compacted[key] = value
        return compacted

    def build(
        self,
        role: str,
        *,
        run_manifest: dict[str, Any] | None = None,
        code_review: Any | None = None,
        hypotheses: Any | None = None,
        hypothesis: Any | None = None,
        poc: Any | None = None,
        validation: Any | None = None,
        report: Any | None = None,
    ) -> ContextPacket:
        run = _maybe_dict(run_manifest)
        sections: dict[str, Any] = {}

        code_review_dict = _maybe_dict(code_review)
        hypotheses_dict = _maybe_dict(hypotheses)
        hypothesis_dict = _maybe_dict(hypothesis)
        poc_dict = _maybe_dict(poc)
        validation_dict = _maybe_dict(validation)
        report_dict = _maybe_dict(report)

        if "hotspots" in code_review_dict and isinstance(code_review_dict["hotspots"], list):
            code_review_dict["hotspots"] = self._compact_refs(code_review_dict["hotspots"])

        if "references" in hypothesis_dict and isinstance(hypothesis_dict["references"], list):
            hypothesis_dict["references"] = self._compact_refs(hypothesis_dict["references"])

        if "references" in report_dict and isinstance(report_dict["references"], list):
            report_dict["references"] = self._compact_refs(report_dict["references"])

        if role == "HypothesisAgent":
            sections["run"] = self._compact_section(run)
        elif role == "PoCBuilderAgent":
            sections["hypothesis"] = self._compact_section(hypothesis_dict)
            sections["code_review"] = self._compact_section(
                {k: code_review_dict.get(k) for k in ["harness_entry", "call_chains", "hotspots"]}
            )
        elif role == "ValidatorAgent":
            sections["hypothesis"] = self._compact_section(hypothesis_dict)
            sections["poc"] = self._compact_section(poc_dict)
        elif role == "ReporterAgent":
            sections["hypothesis"] = self._compact_section(hypothesis_dict)
            sections["poc"] = self._compact_section(poc_dict)
            sections["validation"] = self._compact_section(validation_dict)
            if code_review_dict:
                sections["code_review"] = self._compact_section(
                    {k: code_review_dict.get(k) for k in ["harness_entry", "hotspots"]}
                )
        else:
            if code_review_dict:
                sections["code_review"] = self._compact_section(code_review_dict)
            if hypotheses_dict:
                sections["hypotheses"] = self._compact_section(hypotheses_dict)
            if hypothesis_dict:
                sections["hypothesis"] = self._compact_section(hypothesis_dict)
            if poc_dict:
                sections["poc"] = self._compact_section(poc_dict)
            if validation_dict:
                sections["validation"] = self._compact_section(validation_dict)
            if report_dict:
                sections["report"] = self._compact_section(report_dict)

        hypothesis_id = hypothesis_dict.get("hypothesis_id")

        return ContextPacket(
            role=role,
            run=run,
            hypothesis_id=hypothesis_id,
            sections=sections,
        )


def render_context_packet(packet: ContextPacket) -> str:
    """Render a context packet as YAML for prompt injection."""
    return "CONTEXT_PACKET:\n" + packet.to_yaml().rstrip()

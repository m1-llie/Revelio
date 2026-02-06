"""Parsers for structured agent outputs."""

from __future__ import annotations

import json
from typing import Any

import yaml

from vulagent.artifacts.schema import (
    BugReport,
    CodeReference,
    CodeReviewNotes,
    PoCRecipe,
    ValidationResult,
    VulnHypothesis,
    VulnHypotheses,
)


def _load_structured(text: str) -> dict[str, Any]:
    """Load YAML or JSON; return empty dict on failure."""
    text = text.strip()
    if not text:
        return {}
    try:
        parsed = yaml.safe_load(text)
        if isinstance(parsed, dict):
            return parsed
    except yaml.YAMLError:
        pass
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass
    return {}


def _unwrap_payload(data: dict[str, Any]) -> dict[str, Any]:
    payload = data.get("payload")
    if payload is None:
        return data
    if isinstance(payload, dict):
        return payload
    if isinstance(payload, str):
        return _load_structured(payload)
    return data


def _coerce_refs(items: list[dict[str, Any]] | None) -> list[CodeReference]:
    refs: list[CodeReference] = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        refs.append(
            CodeReference(
                file_path=str(item.get("file_path") or item.get("file") or ""),
                line_start=item.get("line_start"),
                line_end=item.get("line_end"),
                function=item.get("function"),
                context=item.get("context"),
            )
        )
    return refs


def parse_code_review(result: str) -> CodeReviewNotes:
    data = _unwrap_payload(_load_structured(result))
    section = data.get("code_review") if isinstance(data, dict) else {}
    if not section:
        section = data
    if not isinstance(section, dict):
        section = {}
    return CodeReviewNotes(
        summary=str(section.get("summary") or section.get("analysis") or "No summary provided."),
        files_reviewed=list(section.get("files_reviewed") or []),
        harness_entry=section.get("harness_entry"),
        call_chains=list(section.get("call_chains") or []),
        hotspots=_coerce_refs(section.get("hotspots")),
        warnings=list(section.get("warnings") or []),
    )


def parse_hypotheses(result: str) -> VulnHypotheses:
    data = _unwrap_payload(_load_structured(result))
    section = data.get("hypotheses") if isinstance(data, dict) else None
    if section is None:
        section = data.get("vuln_hypotheses") if isinstance(data, dict) else None
    if section is None:
        section = data
    if isinstance(section, dict) and "hypotheses" in section:
        section = section.get("hypotheses")
    if not isinstance(section, list) or not section:
        raise ValueError("No hypotheses found in agent output.")

    hypotheses: list[VulnHypothesis] = []
    for idx, item in enumerate(section, start=1):
        if not isinstance(item, dict):
            continue
        hypothesis_id = str(item.get("hypothesis_id") or item.get("id") or f"H{idx:02d}")
        hypotheses.append(
            VulnHypothesis(
                hypothesis_id=hypothesis_id,
                title=str(item.get("title") or item.get("name") or f"Hypothesis {idx}"),
                description=str(item.get("description") or ""),
                file_path=item.get("file_path"),
                function=item.get("function"),
                trigger=item.get("trigger"),
                preconditions=list(item.get("preconditions") or []),
                expected_crash=item.get("expected_crash"),
                confidence=float(item.get("confidence") or 0.0),
                references=_coerce_refs(item.get("references")),
            )
        )
    return VulnHypotheses(hypotheses=hypotheses, generation_notes=data.get("analysis"))


def parse_poc_recipe(result: str) -> PoCRecipe:
    data = _unwrap_payload(_load_structured(result))
    section = data.get("poc") if isinstance(data, dict) else {}
    if not section:
        section = data.get("poc_recipe") if isinstance(data, dict) else {}
    if not isinstance(section, dict):
        section = {}
    hypothesis_id = str(section.get("hypothesis_id") or data.get("hypothesis_id") or "unknown")
    script_path = section.get("script_path") or section.get("result_script") or "result_script.py"
    input_path = section.get("input_path") or section.get("poc") or "poc"
    if not script_path or not input_path:
        raise ValueError("PoC recipe missing script_path or input_path.")
    return PoCRecipe(
        hypothesis_id=hypothesis_id,
        script_path=str(script_path),
        input_path=str(input_path),
        expected_signal=section.get("expected_signal"),
        generation_steps=list(section.get("generation_steps") or []),
        reproduction_command=section.get("reproduction_command"),
    )


def parse_validation_result(result: str) -> ValidationResult:
    data = _unwrap_payload(_load_structured(result))
    section = data.get("validation") if isinstance(data, dict) else {}
    if not section:
        section = data
    if not isinstance(section, dict):
        section = {}
    hypothesis_id = str(section.get("hypothesis_id") or data.get("hypothesis_id") or "unknown")
    crash_detected = bool(section.get("crash_detected"))
    return ValidationResult(
        hypothesis_id=hypothesis_id,
        crash_detected=crash_detected,
        returncode=section.get("returncode"),
        output_excerpt=section.get("output_excerpt"),
        indicators=list(section.get("indicators") or []),
        reproduction_command=section.get("reproduction_command"),
        logs_path=section.get("logs_path"),
        evidence_paths=list(section.get("evidence_paths") or []),
    )


def parse_bug_report(result: str) -> BugReport:
    data = _unwrap_payload(_load_structured(result))
    section = data.get("report") if isinstance(data, dict) else {}
    if not section:
        section = data
    if not isinstance(section, dict):
        section = {}
    hypothesis_id = str(section.get("hypothesis_id") or data.get("hypothesis_id") or "unknown")
    report_path = section.get("report_path") or section.get("report") or "final_report.md"
    return BugReport(
        hypothesis_id=hypothesis_id,
        report_path=str(report_path),
        summary=section.get("summary"),
        references=_coerce_refs(section.get("references")),
    )

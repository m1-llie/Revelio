#!/usr/bin/env python3
"""Summarize LLM cost and token usage from a vul-agent run directory.

The report is best-effort: direct API cost is recomputed from saved LiteLLM
responses when possible, while cache/uncached splits are estimated from the
usage counters and LiteLLM's model pricing table.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

import litellm


@dataclass
class CostBucket:
    calls: int = 0
    direct_api_cost: float = 0.0
    estimated_token_cost: float = 0.0
    uncached_input_cost: float = 0.0
    cache_write_cost: float = 0.0
    cache_read_cost: float = 0.0
    output_cost: float = 0.0
    input_uncached_tokens: int = 0
    cache_write_tokens: int = 0
    cache_read_tokens: int = 0
    output_tokens: int = 0
    prompt_tokens: int = 0
    total_tokens: int = 0
    missing_cost_calls: int = 0
    aggregate_only_calls: int = 0

    def add(self, other: "CostBucket") -> None:
        for key, value in asdict(other).items():
            setattr(self, key, getattr(self, key) + value)


@dataclass
class CostReport:
    run_path: str
    total: CostBucket = field(default_factory=CostBucket)
    categories: dict[str, CostBucket] = field(default_factory=dict)
    sources: dict[str, CostBucket] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def add_call(self, category: str, source: str, bucket: CostBucket) -> None:
        self.total.add(bucket)
        self.categories.setdefault(category, CostBucket()).add(bucket)
        self.sources.setdefault(source, CostBucket()).add(bucket)


def _load_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def _iter_response_records(obj: Any, source: str, category: str) -> Iterable[tuple[str, str, dict]]:
    """Yield saved LiteLLM/OpenAI-like response dicts from arbitrary trace JSON."""
    if isinstance(obj, dict):
        extra = obj.get("extra")
        if isinstance(extra, dict) and isinstance(extra.get("response"), dict):
            yield category, source, extra["response"]
        for value in obj.values():
            yield from _iter_response_records(value, source, category)
    elif isinstance(obj, list):
        for value in obj:
            yield from _iter_response_records(value, source, category)


def _category_for_trajectory_agent(key: str, agent: dict[str, Any]) -> str:
    info = agent.get("info", {}) if isinstance(agent, dict) else {}
    agent_name = str(info.get("agent_name") or key).lower()
    text = f"{key} {agent_name}".lower()
    if "poc" in text:
        return "poc_generation"
    if "report" in text:
        return "report"
    if "validat" in text:
        return "validation"
    if "hypothesis" in text or "file_hypothesis" in text:
        return "hypothesis"
    return "agent_other"


def _category_for_trace(path: Path) -> str:
    rel = str(path).lower()
    name = path.name.lower()
    if "stage3_filter" in rel:
        return "hypothesis_stage3_filter"
    if name.startswith("stage1_"):
        return "hypothesis_stage1_generation"
    if name.startswith("stage2_"):
        return "hypothesis_stage2_classify_dedup"
    return "trace_other"


def _as_int(value: Any) -> int:
    if value is None:
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _response_model(response: dict) -> str | None:
    model = response.get("model")
    if isinstance(model, str) and model:
        return model
    hidden = response.get("_hidden_params")
    if isinstance(hidden, dict):
        model = hidden.get("model") or hidden.get("custom_llm_provider")
        if isinstance(model, str) and model:
            return model
    return None


def _model_info(model: str | None) -> dict[str, Any]:
    if not model:
        return {}
    candidates = [model]
    if model.startswith("litellm_proxy/"):
        candidates.append(model.removeprefix("litellm_proxy/"))
    if model.startswith("anthropic/"):
        candidates.append(model.removeprefix("anthropic/"))
    else:
        candidates.append(f"anthropic/{model}")
    for candidate in candidates:
        try:
            return litellm.get_model_info(candidate)
        except Exception:
            continue
    return {}


def _completion_cost(response: dict, model: str | None) -> tuple[float, bool]:
    for candidate in [model, None]:
        try:
            kwargs = {"model": candidate} if candidate else {}
            cost = litellm.cost_calculator.completion_cost(response, **kwargs)
            return float(cost or 0.0), False
        except Exception:
            continue
    hidden = response.get("_hidden_params")
    if isinstance(hidden, dict) and hidden.get("response_cost") is not None:
        return float(hidden["response_cost"]), False
    return 0.0, True


def _usage_cost(response: dict) -> CostBucket:
    usage = response.get("usage") or {}
    if not isinstance(usage, dict):
        usage = {}

    prompt_tokens = _as_int(usage.get("prompt_tokens") or usage.get("input_tokens"))
    output_tokens = _as_int(usage.get("completion_tokens") or usage.get("output_tokens"))
    total_tokens = _as_int(usage.get("total_tokens")) or prompt_tokens + output_tokens

    prompt_details = usage.get("prompt_tokens_details") or {}
    if not isinstance(prompt_details, dict):
        prompt_details = {}

    cache_read_tokens = _as_int(
        usage.get("cache_read_input_tokens")
        or prompt_details.get("cached_tokens")
    )
    creation_detail = prompt_details.get("cache_creation_token_details") or {}
    if not isinstance(creation_detail, dict):
        creation_detail = {}
    cache_write_tokens = _as_int(
        usage.get("cache_creation_input_tokens")
        or prompt_details.get("cache_creation_tokens")
        or sum(_as_int(v) for v in creation_detail.values())
    )

    explicit_uncached = usage.get("input_tokens")
    if explicit_uncached is None:
        explicit_uncached = prompt_details.get("text_tokens")
    input_uncached_tokens = (
        _as_int(explicit_uncached)
        if explicit_uncached is not None
        else max(prompt_tokens - cache_read_tokens - cache_write_tokens, 0)
    )

    model = _response_model(response)
    info = _model_info(model)
    input_price = float(info.get("input_cost_per_token") or 0.0)
    output_price = float(info.get("output_cost_per_token") or 0.0)
    cache_write_price = float(info.get("cache_creation_input_token_cost") or input_price)
    cache_read_price = float(info.get("cache_read_input_token_cost") or 0.0)

    direct_api_cost, missing = _completion_cost(response, model)
    uncached_input_cost = input_uncached_tokens * input_price
    cache_write_cost = cache_write_tokens * cache_write_price
    cache_read_cost = cache_read_tokens * cache_read_price
    output_cost = output_tokens * output_price

    return CostBucket(
        calls=1,
        direct_api_cost=direct_api_cost,
        estimated_token_cost=uncached_input_cost + cache_write_cost + cache_read_cost + output_cost,
        uncached_input_cost=uncached_input_cost,
        cache_write_cost=cache_write_cost,
        cache_read_cost=cache_read_cost,
        output_cost=output_cost,
        input_uncached_tokens=input_uncached_tokens,
        cache_write_tokens=cache_write_tokens,
        cache_read_tokens=cache_read_tokens,
        output_tokens=output_tokens,
        prompt_tokens=prompt_tokens,
        total_tokens=total_tokens,
        missing_cost_calls=1 if missing else 0,
    )


def _aggregate_trace_cost(obj: Any) -> CostBucket | None:
    if not isinstance(obj, dict):
        return None
    if not isinstance(obj.get("cost"), (int, float)):
        return None
    calls = _as_int(obj.get("calls"))
    cost = float(obj.get("cost") or 0.0)
    if calls <= 0 and cost <= 0:
        return None
    return CostBucket(
        calls=calls,
        direct_api_cost=cost,
        estimated_token_cost=cost,
        aggregate_only_calls=calls,
    )


def collect_report(path: Path) -> CostReport:
    root = path.resolve()
    report = CostReport(run_path=str(root))

    if root.is_file():
        files = [root]
        run_dir = root.parent
    else:
        run_dir = root
        files = []
        trajectory = run_dir / "trajectory.json"
        if trajectory.exists():
            files.append(trajectory)
        traces = run_dir / "traces"
        if traces.exists():
            files.extend(sorted(traces.rglob("*.json")))

    for file_path in files:
        data = _load_json(file_path)
        if data is None:
            report.notes.append(f"skipped unreadable JSON: {file_path}")
            continue

        if file_path.name == "trajectory.json" and isinstance(data, dict):
            agents = data.get("agents")
            if isinstance(agents, dict):
                for key, agent in agents.items():
                    category = _category_for_trajectory_agent(str(key), agent)
                    source = f"trajectory:{key}"
                    for _, _, response in _iter_response_records(agent, source, category):
                        report.add_call(category, source, _usage_cost(response))
                continue

        category = _category_for_trace(file_path)
        try:
            source = str(file_path.relative_to(run_dir))
        except ValueError:
            source = str(file_path)
        response_count = 0
        for _, _, response in _iter_response_records(data, source, category):
            response_count += 1
            report.add_call(category, source, _usage_cost(response))
        if response_count == 0:
            aggregate = _aggregate_trace_cost(data)
            if aggregate is not None:
                report.add_call(category, source, aggregate)

    if report.total.calls == 0:
        report.notes.append("no saved LLM responses found in trajectory.json or traces/*.json")
    if report.total.missing_cost_calls:
        report.notes.append(
            f"{report.total.missing_cost_calls} call(s) lacked recomputable direct API cost"
        )
    if report.total.aggregate_only_calls:
        report.notes.append(
            f"{report.total.aggregate_only_calls} call(s) came from aggregate trace cost fields; "
            "cache/uncached token split is unavailable for those calls"
        )
    return report


def _round_bucket(bucket: CostBucket) -> dict[str, Any]:
    data = asdict(bucket)
    for key, value in list(data.items()):
        if key.endswith("_cost") or key == "direct_api_cost":
            data[key] = round(float(value), 8)
    data["cached_input_cost"] = round(data["cache_write_cost"] + data["cache_read_cost"], 8)
    data["cached_input_tokens"] = data["cache_write_tokens"] + data["cache_read_tokens"]
    return data


def report_to_dict(report: CostReport) -> dict[str, Any]:
    return {
        "run_path": report.run_path,
        "total": _round_bucket(report.total),
        "categories": {
            key: _round_bucket(value)
            for key, value in sorted(report.categories.items())
        },
        "sources": {
            key: _round_bucket(value)
            for key, value in sorted(report.sources.items())
        },
        "notes": report.notes,
    }


def _fmt_money(value: float) -> str:
    return f"${value:.6f}"


def report_to_markdown(report: CostReport) -> str:
    data = report_to_dict(report)
    lines = [
        "# Cost Report",
        "",
        f"- Run: `{data['run_path']}`",
        f"- Calls: {data['total']['calls']}",
        f"- Direct API cost: {_fmt_money(data['total']['direct_api_cost'])}",
        f"- Estimated token cost: {_fmt_money(data['total']['estimated_token_cost'])}",
        f"- Cached input cost: {_fmt_money(data['total']['cached_input_cost'])}",
        f"- Uncached input cost: {_fmt_money(data['total']['uncached_input_cost'])}",
        f"- Output cost: {_fmt_money(data['total']['output_cost'])}",
        "",
        "## By Category",
        "",
        "| Category | Calls | Direct API | Cached Input | Uncached Input | Output | Cache Read Tok | Cache Write Tok | Uncached Input Tok | Output Tok |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name, bucket in data["categories"].items():
        lines.append(
            f"| {name} | {bucket['calls']} | {_fmt_money(bucket['direct_api_cost'])} | "
            f"{_fmt_money(bucket['cached_input_cost'])} | {_fmt_money(bucket['uncached_input_cost'])} | "
            f"{_fmt_money(bucket['output_cost'])} | {bucket['cache_read_tokens']} | "
            f"{bucket['cache_write_tokens']} | {bucket['input_uncached_tokens']} | {bucket['output_tokens']} |"
        )
    if data["notes"]:
        lines.extend(["", "## Notes", ""])
        lines.extend(f"- {note}" for note in data["notes"])
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate LLM cost report from a vul-agent run directory")
    parser.add_argument("path", help="Run directory, trajectory.json, or trace JSON file")
    parser.add_argument("--write", action="store_true", help="Write cost_report.json and cost_report.md next to the run")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of markdown")
    args = parser.parse_args()

    path = Path(args.path)
    report = collect_report(path)
    data = report_to_dict(report)

    if args.write:
        out_dir = path if path.is_dir() else path.parent
        (out_dir / "cost_report.json").write_text(json.dumps(data, indent=2))
        (out_dir / "cost_report.md").write_text(report_to_markdown(report))

    if args.json:
        print(json.dumps(data, indent=2))
    else:
        print(report_to_markdown(report))


if __name__ == "__main__":
    main()

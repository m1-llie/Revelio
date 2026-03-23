#!/usr/bin/env python3
"""Scan-and-filter pipeline: hypothesis generation -> dedup -> Docker sub-agent filtering.

Given a source file in a repository, this script:
1. Generates vulnerability hypotheses via multi-pass LLM analysis
2. Classifies & deduplicates them
3. Launches parallel Docker sub-agents (mini-SWE style) that spin up a
   container with the full repo, inspect the code around each hypothesis,
   and verdict VALID/INVALID

Core logic is shared with the integrated pipeline via
vulagent.orchestrator.scan_filter_stages.

Examples:
    python -m vulagent.run.scan_and_filter -f src/parser.c \\
        -m claude-haiku-4-5-20251001 --repo /path/to/repo

    python -m vulagent.run.scan_and_filter \\
        -f src/parser.c --repo /path/to/repo \\
        -m litellm_proxy/vertex_ai/claude-haiku-4-5@20251001 \\
        --base-url https://litellm-proxy --api-key sk-... \\
        --filter-model litellm_proxy/vertex_ai/claude-sonnet-4-6@20250514 \\
        --workers 8
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vulagent.orchestrator.scan_filter_stages import (
    FOCUSED_PASSES,
    FILTER_AGENT_SYSTEM,
    FILTER_AGENT_INSTANCE,
    FunctionInfo,
    aggregate_hypotheses,
    classify_hypothesis,
    dedup_hypotheses,
    extract_json_block,
    llm_call,
    make_batches,
    parse_functions,
    phase_analyze_focused,
    phase_analyze_functions,
    phase_analyze_wholefile,
    phase_summarize,
)

logger = logging.getLogger("scan_and_filter")


# ===========================================================================
# Stage 3: Docker sub-agent filtering (standalone version with own containers)
# ===========================================================================


def _copy_repo_into_container(env: Any, repo_path: Path, destination: Path) -> None:
    """Stream repo via tar into running container."""
    archive_cmd = [
        "tar", "-C", str(repo_path.parent), "-cf", "-", repo_path.name,
    ]
    extract_cmd = (
        f"mkdir -p {destination} && rm -rf {destination}/* && "
        f"tar -C {destination} --strip-components=1 -xf -"
    )
    with subprocess.Popen(archive_cmd, stdout=subprocess.PIPE) as tar_proc:
        exec_cmd = [
            env.config.executable, "exec", "-i", env.container_id,
            "bash", "-lc", extract_cmd,
        ]
        subprocess.run(exec_cmd, stdin=tar_proc.stdout, check=True, timeout=120)
        tar_proc.wait()
        if tar_proc.returncode != 0:
            raise RuntimeError("Failed to archive repo for container copy")


def _run_filter_agent_standalone(
    hyp: dict,
    repo_path: Path,
    target_file: str,
    model_name: str,
    model_config: dict,
    docker_image: str,
    agent_step_limit: int,
    agent_cost_limit: float,
    docker_timeout: int,
) -> dict:
    """Spin up a Docker container, run a DefaultAgent to verify one hypothesis, clean up.

    This is the standalone version that creates its own container per hypothesis.
    For the integrated version that reuses an existing container, see
    vulagent.orchestrator.scan_filter_stages.run_filter_agent.

    Returns dict with verdict, confidence, reason, reasoning, error.
    """
    from vulagent.agents.default import DefaultAgent
    from vulagent.environments.docker import DockerEnvironment
    from vulagent.models import get_model

    h = hyp.get("hypothesis", hyp)
    hotspots = h.get("hotspots", [])
    project_path = "/src"

    env = None
    try:
        env = DockerEnvironment(
            image=docker_image,
            cwd=project_path,
            run_args=["--rm"],
            timeout=docker_timeout,
        )
        _copy_repo_into_container(env, repo_path, Path(project_path))
        env.config.env.update({"PAGER": "cat", "LESS": "-R"})

        model = get_model(model_name, model_config)
        agent = DefaultAgent(
            model, env,
            system_template=FILTER_AGENT_SYSTEM,
            instance_template=FILTER_AGENT_INSTANCE,
            format_error_template=(
                "Your last response did not include a tool call. "
                "Every response MUST contain exactly one tool call: `bash` or `finish`."
            ),
            action_observation_template=(
                "<returncode>{{output.returncode}}</returncode>\n"
                "{% if output.output | length < 8000 %}"
                "<output>\n{{ output.output }}</output>"
                "{% else %}"
                "<output_head>\n{{ output.output[:4000] }}\n</output_head>\n"
                "<elided>{{ output.output | length - 8000 }} chars</elided>\n"
                "<output_tail>\n{{ output.output[-4000:] }}\n</output_tail>"
                "{% endif %}"
            ),
            step_limit=agent_step_limit,
            cost_limit=agent_cost_limit,
        )

        exit_status, result_text = agent.run(
            "Verify the vulnerability hypothesis",
            project_path=project_path,
            target_file=target_file,
            max_rounds=agent_step_limit,
            hypothesis_summary=h.get("summary", ""),
            hypothesis_description=h.get("description", ""),
            hypothesis_function=h.get("function", ""),
            hypothesis_trigger=h.get("trigger", ""),
            hypothesis_expected_crash=h.get("expected_crash", ""),
            hotspots=hotspots,
        )

        trajectory = agent.messages

        # Parse the finish payload
        try:
            import yaml
            parsed = yaml.safe_load(result_text)
            if isinstance(parsed, dict):
                payload = parsed.get("payload", parsed)
                return {
                    "verdict": str(payload.get("verdict", "VALID")).upper(),
                    "confidence": float(payload.get("confidence", 0.5)),
                    "reason": payload.get("reason", ""),
                    "reasoning": parsed.get("analysis", ""),
                    "exit_status": exit_status,
                    "model_cost": agent.model.cost,
                    "model_calls": agent.model.n_calls,
                    "trajectory": trajectory,
                    "error": None,
                }
        except Exception:
            pass

        # Fallback: try to extract JSON from result_text
        _, json_str = extract_json_block(result_text, array=False)
        try:
            data = json.loads(json_str)
            return {
                "verdict": str(data.get("verdict", "VALID")).upper(),
                "confidence": float(data.get("confidence", 0.5)),
                "reason": data.get("reason", ""),
                "reasoning": result_text,
                "exit_status": exit_status,
                "model_cost": getattr(agent.model, "cost", 0),
                "model_calls": getattr(agent.model, "n_calls", 0),
                "trajectory": trajectory,
                "error": None,
            }
        except json.JSONDecodeError:
            return {
                "verdict": "VALID",
                "confidence": 0.0,
                "reason": "Could not parse agent output",
                "reasoning": result_text,
                "exit_status": exit_status,
                "model_cost": getattr(agent.model, "cost", 0),
                "model_calls": getattr(agent.model, "n_calls", 0),
                "trajectory": trajectory,
                "error": f"parse error: {result_text[:200]}",
            }

    except Exception as e:
        return {
            "verdict": "VALID",  # conservative
            "confidence": 0.0,
            "reason": str(e),
            "reasoning": "",
            "exit_status": "Error",
            "model_cost": 0,
            "model_calls": 0,
            "trajectory": [],
            "error": str(e),
        }
    finally:
        if env is not None:
            env.cleanup()


# ===========================================================================
# Pipeline orchestration
# ===========================================================================


def run_pipeline(
    file_path: Path,
    repo_path: Path,
    model_name: str,
    model_kwargs: dict,
    filter_model: str | None = None,
    filter_model_kwargs: dict | None = None,
    workers: int = 4,
    max_functions: int = 50,
    filter_workers: int = 4,
    docker_image: str = "ubuntu:22.04",
    agent_step_limit: int = 5,
    agent_cost_limit: float = 2.0,
    docker_timeout: int = 120,
) -> dict:
    """Run the full scan-and-filter pipeline. Returns the result dict."""

    assert file_path.is_relative_to(repo_path), f"{file_path} is not under {repo_path}"

    source = file_path.read_text(errors="replace")
    started_at = datetime.now(timezone.utc)

    # -------------------------------------------------------------------
    # Stage 1: Hypothesis Generation
    # -------------------------------------------------------------------
    print("\n=== Stage 1: Hypothesis Generation ===", file=sys.stderr)

    print("  Summarizing file...", file=sys.stderr)
    summary, deep_summary, summary_msgs = phase_summarize(model_name, file_path, source, model_kwargs)
    print(f"  Summary: {len(summary)} chars, deep: {len(deep_summary)} chars", file=sys.stderr)

    print("  Parsing functions...", file=sys.stderr)
    functions = parse_functions(file_path, source)
    total_found = len(functions)
    if total_found > max_functions:
        functions = functions[:max_functions]
    print(f"  Found {total_found} functions (using {len(functions)})", file=sys.stderr)

    batches = make_batches(functions)
    total_tasks = 1 + len(FOCUSED_PASSES) + len(batches)
    effective_workers = min(workers, total_tasks)
    print(
        f"  Running {total_tasks} analysis tasks "
        f"(1 whole-file + {len(FOCUSED_PASSES)} focused + {len(batches)} batches) "
        f"with {effective_workers} workers...",
        file=sys.stderr,
    )

    wholefile_result: dict = {}
    focused_results: list[dict] = [{} for _ in FOCUSED_PASSES]
    function_analyses: list[dict] = [{}] * len(batches)
    completed = 0

    with ThreadPoolExecutor(max_workers=effective_workers) as executor:
        futures: dict = {}
        futures[executor.submit(
            phase_analyze_wholefile, model_name, file_path, summary_msgs, model_kwargs
        )] = ("wholefile", None)
        for idx, prompt in enumerate(FOCUSED_PASSES):
            futures[executor.submit(
                phase_analyze_focused, model_name, file_path, summary_msgs, prompt, model_kwargs
            )] = ("focused", idx)
        for idx, batch in enumerate(batches):
            futures[executor.submit(
                phase_analyze_functions, model_name, file_path, batch, summary_msgs, model_kwargs
            )] = ("batch", idx)

        for future in as_completed(futures):
            kind, idx = futures[future]
            completed += 1
            try:
                result = future.result()
                if kind == "wholefile":
                    wholefile_result = result
                elif kind == "focused":
                    focused_results[idx] = result
                else:
                    function_analyses[idx] = result
                print(f"  [{completed}/{total_tasks}] {kind} done", file=sys.stderr)
            except Exception as e:
                print(f"  [{completed}/{total_tasks}] ERROR ({kind}): {e}", file=sys.stderr)

    all_hypotheses = aggregate_hypotheses(wholefile_result, focused_results, function_analyses)
    print(f"\n  Generated {len(all_hypotheses)} raw hypotheses", file=sys.stderr)

    if not all_hypotheses:
        return _build_result(
            file_path, model_name, started_at,
            total_found, len(function_analyses),
            summary, deep_summary,
            all_hypotheses, [], [],
            wholefile_result, focused_results, function_analyses,
        )

    # -------------------------------------------------------------------
    # Stage 2: Classification & Dedup
    # -------------------------------------------------------------------
    print("\n=== Stage 2: Classification & Filtering ===", file=sys.stderr)

    source_lines = source.splitlines()
    dedup_kwargs = dict(model_kwargs)
    dedup_kwargs["temperature"] = 0.0

    print(f"  Classifying {len(all_hypotheses)} hypotheses...", file=sys.stderr)

    classifications: dict[int, dict] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(classify_hypothesis, h, model_name, dedup_kwargs, source_lines): i
            for i, h in enumerate(all_hypotheses)
        }
        done = 0
        for future in as_completed(futures):
            idx = futures[future]
            done += 1
            try:
                classifications[idx] = future.result()
                is_vuln = classifications[idx]["is_vulnerability"]
                is_asan = classifications[idx]["is_asan"]
                print(
                    f"  [{done}/{len(all_hypotheses)}] "
                    f"{('ASAN' if is_asan else 'VUL') if is_vuln else 'NOT'} — "
                    f"{classifications[idx]['reason'][:70]}",
                    file=sys.stderr,
                )
            except Exception as e:
                classifications[idx] = {
                    "is_vulnerability": False, "is_asan": False, "cwe_ids": [], "reason": f"error: {e}"
                }

    # Filter: keep only ASAN-triggerable vulnerabilities
    valid_indices = [
        i for i in range(len(all_hypotheses))
        if classifications[i]["is_vulnerability"] and classifications[i]["is_asan"]
    ]
    print(
        f"  Filtered: {len(all_hypotheses) - len(valid_indices)} non-asan-vulnerabilities, "
        f"{len(valid_indices)} remain",
        file=sys.stderr,
    )

    for i, h in enumerate(all_hypotheses):
        h["_cwe_ids"] = classifications[i]["cwe_ids"]
        h["_is_vulnerability"] = classifications[i]["is_vulnerability"]
        h["_is_asan"] = classifications[i]["is_asan"]
        if not classifications[i]["is_vulnerability"]:
            h["_removed"] = f"Not a vulnerability: {classifications[i]['reason']}"
        elif not classifications[i]["is_asan"]:
            h["_removed"] = f"Not ASAN-triggerable: {classifications[i]['reason']}"

    valid_hyps = [all_hypotheses[i] for i in valid_indices]
    cwe_map = {j: classifications[valid_indices[j]]["cwe_ids"] for j in range(len(valid_indices))}

    dedup_kwargs = dict(model_kwargs)
    dedup_kwargs["temperature"] = 0.0
    kept, removed = dedup_hypotheses(valid_hyps, cwe_map, model_name, dedup_kwargs, workers=workers)
    print(f"  Dedup: {len(valid_hyps)} -> {len(kept)} (removed {len(removed)} duplicates)", file=sys.stderr)

    # Mark dedup removals in all_hypotheses
    removed_summaries = {
        r.get("hypothesis", r).get("summary", ""): r.get("_removed", "")
        for r in removed
    }
    for h in all_hypotheses:
        if h.get("_is_vulnerability") and h.get("_is_asan") and not h.get("_removed"):
            summary_text = h.get("hypothesis", h).get("summary", "")
            if summary_text in removed_summaries:
                h["_removed"] = removed_summaries[summary_text]

    if not kept:
        return _build_result(
            file_path, model_name, started_at,
            total_found, len(function_analyses),
            summary, deep_summary,
            all_hypotheses, kept, [],
            wholefile_result, focused_results, function_analyses,
        )

    # -------------------------------------------------------------------
    # Stage 3: Docker Sub-agent Filtering
    # -------------------------------------------------------------------
    print(f"\n=== Stage 3: Docker Sub-agent Filtering ({len(kept)} hypotheses) ===", file=sys.stderr)

    fmodel = filter_model or model_name
    fmodel_config = filter_model_kwargs or {}

    target_file_rel = str(file_path.relative_to(repo_path)) if file_path.is_relative_to(repo_path) else str(file_path)

    print(f"  Filter model: {fmodel}", file=sys.stderr)
    print(f"  Docker image: {docker_image}", file=sys.stderr)
    print(f"  Filter workers: {filter_workers}", file=sys.stderr)
    print(f"  Agent step limit: {agent_step_limit}, cost limit: ${agent_cost_limit}", file=sys.stderr)

    filter_results: dict[int, dict] = {}
    with ThreadPoolExecutor(max_workers=filter_workers) as pool:
        futures = {
            pool.submit(
                _run_filter_agent_standalone,
                h, repo_path, target_file_rel,
                fmodel, fmodel_config, docker_image,
                agent_step_limit, agent_cost_limit, docker_timeout,
            ): i
            for i, h in enumerate(kept)
        }
        done = 0
        for future in as_completed(futures):
            idx = futures[future]
            done += 1
            try:
                filter_results[idx] = future.result()
                v = filter_results[idx]
                verdict = v["verdict"]
                conf = v["confidence"]
                reason = v["reason"][:60]
                cost = v.get("model_cost", 0)
                print(
                    f"  [{done}/{len(kept)}] {verdict} (conf={conf:.2f}, ${cost:.3f}) — {reason}",
                    file=sys.stderr,
                )
            except Exception as e:
                filter_results[idx] = {
                    "verdict": "VALID",
                    "confidence": 0.0,
                    "reason": str(e),
                    "reasoning": "",
                    "error": str(e),
                }

    # Apply filter results
    final_hypotheses = []
    for i, h in enumerate(kept):
        fr = filter_results.get(i, {})
        h["_filter_verdict"] = fr.get("verdict", "VALID")
        h["_filter_confidence"] = fr.get("confidence", 0.0)
        h["_filter_reason"] = fr.get("reason", "")
        h["_filter_reasoning"] = fr.get("reasoning", "")
        h["_filter_model_cost"] = fr.get("model_cost", 0)
        h["_filter_model_calls"] = fr.get("model_calls", 0)
        h["_filter_trajectory"] = fr.get("trajectory", [])

        if fr.get("verdict") == "INVALID" and fr.get("confidence", 0) >= 0.7:
            h["_removed"] = f"Filtered by sub-agent: {fr.get('reason', '')}"
            summary_text = h.get("hypothesis", h).get("summary", "")
            for ah in all_hypotheses:
                if ah.get("hypothesis", ah).get("summary", "") == summary_text and not ah.get("_removed"):
                    ah["_removed"] = h["_removed"]
        else:
            final_hypotheses.append(h)

    filtered_out = len(kept) - len(final_hypotheses)
    print(
        f"\n  Sub-agent filter: {len(kept)} -> {len(final_hypotheses)} "
        f"(removed {filtered_out} invalid)",
        file=sys.stderr,
    )

    return _build_result(
        file_path, model_name, started_at,
        total_found, len(function_analyses),
        summary, deep_summary,
        all_hypotheses, kept, final_hypotheses,
        wholefile_result, focused_results, function_analyses,
    )


def _build_result(
    file_path: Path,
    model_name: str,
    started_at: datetime,
    functions_found: int,
    functions_analyzed: int,
    summary: str,
    deep_summary: str,
    all_hypotheses: list[dict],
    deduped_hypotheses: list[dict],
    final_hypotheses: list[dict],
    wholefile_result: dict | None = None,
    focused_results: list[dict] | None = None,
    function_analyses: list[dict] | None = None,
) -> dict:
    """Build the in-memory result dict (used by run_pipeline)."""
    finished_at = datetime.now(timezone.utc)
    return {
        "info": {
            "file_path": str(file_path),
            "model": model_name,
            "started_at_utc": started_at.isoformat(),
            "finished_at_utc": finished_at.isoformat(),
            "duration_seconds": (finished_at - started_at).total_seconds(),
            "functions_found": functions_found,
            "functions_analyzed": functions_analyzed,
            "raw_hypothesis_count": len(all_hypotheses),
            "deduped_hypothesis_count": len(deduped_hypotheses),
            "final_hypothesis_count": len(final_hypotheses),
        },
        "summary": summary,
        "deep_summary": deep_summary,
        "all_hypotheses": all_hypotheses,
        "deduped_hypotheses": deduped_hypotheses,
        "final_hypotheses": final_hypotheses,
        "wholefile_analysis": (wholefile_result or {}).get("analysis", ""),
        "focused_analyses": [
            {k: v for k, v in fr.items() if k != "messages"}
            for fr in (focused_results or [])
        ],
        "function_analyses": [
            {k: v for k, v in fa.items() if not k.startswith("messages_")}
            for fa in (function_analyses or [])
        ],
    }


def _hypothesis_slug(hyp: dict, index: int) -> str:
    """Generate a short filesystem-safe folder name for a hypothesis."""
    h = hyp.get("hypothesis", hyp)
    summary = h.get("summary", "") or h.get("title", "") or f"hypothesis_{index}"
    slug = re.sub(r"[^a-z0-9]+", "_", summary.lower()).strip("_")[:80]
    return f"H{index:02d}_{slug}"


def _save_hypothesis_dir(
    base_dir: Path,
    hyp: dict,
    index: int,
) -> None:
    """Write a hypothesis to its own directory with separate trajectory file."""
    slug = _hypothesis_slug(hyp, index)
    hyp_dir = base_dir / slug
    hyp_dir.mkdir(parents=True, exist_ok=True)

    trajectory = hyp.pop("_filter_trajectory", [])
    (hyp_dir / "hypothesis.json").write_text(json.dumps(hyp, indent=2))
    if trajectory:
        (hyp_dir / "filter_trajectory.json").write_text(json.dumps(trajectory, indent=2))
    hyp["_filter_trajectory"] = trajectory


def _save_output(
    output_dir: Path,
    file_path: Path,
    model_name: str,
    started_at: datetime,
    functions_found: int,
    functions_analyzed: int,
    summary: str,
    deep_summary: str,
    all_hypotheses: list[dict],
    deduped_hypotheses: list[dict],
    final_hypotheses: list[dict],
    wholefile_result: dict | None = None,
    focused_results: list[dict] | None = None,
    function_analyses: list[dict] | None = None,
) -> None:
    """Save pipeline output as a directory tree."""
    output_dir.mkdir(parents=True, exist_ok=True)

    finished_at = datetime.now(timezone.utc)

    final_summaries = {
        h.get("hypothesis", h).get("summary", "") for h in final_hypotheses
    }

    valid_dir = output_dir / "valid_hypotheses"
    valid_dir.mkdir(exist_ok=True)
    for i, h in enumerate(final_hypotheses):
        _save_hypothesis_dir(valid_dir, h, i)

    invalid_dir = output_dir / "invalid_hypotheses"
    invalid_dir.mkdir(exist_ok=True)
    invalid_index = 0
    seen_summaries: set[str] = set()
    for h in all_hypotheses:
        hyp_summary = h.get("hypothesis", h).get("summary", "")
        if hyp_summary in seen_summaries:
            continue
        if h.get("_removed") or hyp_summary not in final_summaries:
            _save_hypothesis_dir(invalid_dir, h, invalid_index)
            invalid_index += 1
            seen_summaries.add(hyp_summary)

    summary_data = {
        "info": {
            "file_path": str(file_path),
            "model": model_name,
            "started_at_utc": started_at.isoformat(),
            "finished_at_utc": finished_at.isoformat(),
            "duration_seconds": (finished_at - started_at).total_seconds(),
            "functions_found": functions_found,
            "functions_analyzed": functions_analyzed,
            "raw_hypothesis_count": len(all_hypotheses),
            "deduped_hypothesis_count": len(deduped_hypotheses),
            "final_hypothesis_count": len(final_hypotheses),
        },
        "summary": summary,
        "deep_summary": deep_summary,
        "wholefile_analysis": (wholefile_result or {}).get("analysis", ""),
        "focused_analyses": [
            {k: v for k, v in fr.items() if k != "messages"}
            for fr in (focused_results or [])
        ],
        "function_analyses": [
            {k: v for k, v in fa.items() if not k.startswith("messages_")}
            for fa in (function_analyses or [])
        ],
        "valid_hypotheses": [
            h.get("hypothesis", h).get("summary", "") for h in final_hypotheses
        ],
        "invalid_hypothesis_count": invalid_index,
    }
    (output_dir / "summary.json").write_text(json.dumps(summary_data, indent=2))


# ===========================================================================
# CLI
# ===========================================================================


def main():
    parser = argparse.ArgumentParser(
        description="Scan-and-filter: hypothesize -> dedup -> Docker sub-agent filter"
    )
    parser.add_argument("-f", "--file", required=True, help="Source file to analyze")
    parser.add_argument("-r", "--repo", default=None,
                        help="Repository root (default: parent dir of --file)")
    parser.add_argument("-m", "--model", default=os.getenv("MSWEA_MODEL_NAME"),
                        help="Model for hypothesis generation & dedup")
    parser.add_argument("-b", "--base-url", default=None, help="LiteLLM proxy base URL")
    parser.add_argument("-k", "--api-key", default=os.getenv("MSWEA_MODEL_API_KEY"), help="API key")
    parser.add_argument("-o", "--output", default=None, help="Output JSON path")

    parser.add_argument("--filter-model", default=None,
                        help="Model for Docker sub-agent filtering (default: same as --model)")
    parser.add_argument("--filter-base-url", default=None,
                        help="Base URL for filter model (default: same as --base-url)")
    parser.add_argument("--filter-api-key", default=None,
                        help="API key for filter model (default: same as --api-key)")

    parser.add_argument("--docker-image", default="ubuntu:22.04",
                        help="Docker image for sub-agent containers (default: ubuntu:22.04)")
    parser.add_argument("--agent-step-limit", type=int, default=5,
                        help="Max steps per filter sub-agent (default: 5)")
    parser.add_argument("--agent-cost-limit", type=float, default=2.0,
                        help="Max cost per filter sub-agent (default: $2.00)")
    parser.add_argument("--docker-timeout", type=int, default=120,
                        help="Timeout in seconds for Docker commands (default: 120)")

    parser.add_argument("--workers", type=int, default=4,
                        help="Parallel workers for hypothesis generation (default: 4)")
    parser.add_argument("--filter-workers", type=int, default=4,
                        help="Parallel Docker sub-agent workers (default: 4)")
    parser.add_argument("--max-functions", type=int, default=50,
                        help="Max functions to analyze (default: 50)")
    args = parser.parse_args()

    file_path = Path(args.file).resolve()
    if not file_path.is_file():
        print(f"Error: file not found: {file_path}", file=sys.stderr)
        sys.exit(1)

    repo_path = Path(args.repo).resolve() if args.repo else file_path.parent
    if not repo_path.is_dir():
        print(f"Error: repo not found: {repo_path}", file=sys.stderr)
        sys.exit(1)

    model_name = args.model
    if not model_name:
        print("Error: no model specified. Use --model or set MSWEA_MODEL_NAME.", file=sys.stderr)
        sys.exit(1)

    if args.output:
        output_dir = Path(args.output)
    else:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        output_dir = Path("output/scan_and_filter") / f"saf_{file_path.stem}_{ts}"
    output_dir.mkdir(parents=True, exist_ok=True)

    model_kwargs: dict = {"temperature": 1.0, "drop_params": True}
    if args.base_url:
        model_kwargs["base_url"] = args.base_url
    if args.api_key:
        model_kwargs["api_key"] = args.api_key

    filter_model_kwargs: dict = {"model_kwargs": {"drop_params": True}}
    if args.filter_base_url or args.base_url:
        filter_model_kwargs["model_kwargs"]["base_url"] = args.filter_base_url or args.base_url
    if args.filter_api_key or args.api_key:
        filter_model_kwargs["model_kwargs"]["api_key"] = args.filter_api_key or args.api_key

    print(f"File:         {file_path}")
    print(f"Repo:         {repo_path}")
    print(f"Model:        {model_name}")
    print(f"Filter model: {args.filter_model or model_name}")
    print(f"Docker image: {args.docker_image}")
    print(f"Output:       {output_dir}")

    result = run_pipeline(
        file_path=file_path,
        repo_path=repo_path,
        model_name=model_name,
        model_kwargs=model_kwargs,
        filter_model=args.filter_model,
        filter_model_kwargs=filter_model_kwargs,
        workers=args.workers,
        max_functions=args.max_functions,
        filter_workers=args.filter_workers,
        docker_image=args.docker_image,
        agent_step_limit=args.agent_step_limit,
        agent_cost_limit=args.agent_cost_limit,
        docker_timeout=args.docker_timeout,
    )

    _save_output(
        output_dir=output_dir,
        file_path=file_path,
        model_name=model_name,
        started_at=datetime.fromisoformat(result["info"]["started_at_utc"]),
        functions_found=result["info"]["functions_found"],
        functions_analyzed=result["info"]["functions_analyzed"],
        summary=result["summary"],
        deep_summary=result["deep_summary"],
        all_hypotheses=result["all_hypotheses"],
        deduped_hypotheses=result["deduped_hypotheses"],
        final_hypotheses=result["final_hypotheses"],
    )
    print(f"\nSaved to: {output_dir}")
    info = result["info"]
    print(
        f"Pipeline: {info['raw_hypothesis_count']} raw -> "
        f"{info['deduped_hypothesis_count']} deduped -> "
        f"{info['final_hypothesis_count']} final "
        f"({info['duration_seconds']:.1f}s)"
    )
    valid_count = len(list((output_dir / "valid_hypotheses").iterdir()))
    invalid_count = len(list((output_dir / "invalid_hypotheses").iterdir()))
    print(f"  valid_hypotheses/   ({valid_count} entries)")
    print(f"  invalid_hypotheses/ ({invalid_count} entries)")


if __name__ == "__main__":
    main()

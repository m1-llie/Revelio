#!/usr/bin/env python3
"""
RevelioAgent Trace Viewer — lightweight server.

Usage:
    python server.py [--host HOST] [--port PORT] [--output-dir DIR ...]

Options:
    --host HOST     Host to bind (default: 127.0.0.1 for security)
    --port PORT     Port number (default: 8877)
    --output-dir    Output directories to scan

For remote access, use SSH tunnel:
    ssh -L 8877:127.0.0.1:8877 user@server

Serves the static frontend and a JSON API to browse run outputs.
No external dependencies — stdlib only.
"""

import argparse
import json
import os
import re
import mimetypes
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs

WEBSITE_DIR = Path(__file__).resolve().parent

SCRIPT_DIR = Path("/srv/share/revelio/")
SCRIPTS_DIR = SCRIPT_DIR  # backwards-compat alias used elsewhere
DEFAULT_OUTPUT_DIRS = [
    WEBSITE_DIR.parent / "output"
]


def _json_resp(handler, data, status=200):
    body = json.dumps(data, default=str).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.end_headers()
    handler.wfile.write(body)


def _text_resp(handler, text, status=200, content_type="text/plain"):
    body = text.encode() if isinstance(text, str) else text
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.end_headers()
    handler.wfile.write(body)


def _read_json(path):
    with open(path) as f:
        return json.load(f)


def _read_jsonl(path):
    events = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def _is_run_dir(path):
    """A run directory has manifest.json, trajectory.json, trajectory.jsonl,
    messages.jsonl (ClaudeCode/Codex), or a trajectories/*.yaml file (KISSSorcar)."""
    if not path.is_dir():
        return False
    if (path / "manifest.json").exists():
        return True
    if (path / "trajectory.json").exists():
        return True
    if (path / "trajectory.jsonl").exists():
        return True
    if (path / "messages.jsonl").exists():
        return True
    traj_dir = path / "trajectories"
    if traj_dir.is_dir():
        for ext in ("*.yaml", "*.yml"):
            if any(traj_dir.glob(ext)):
                return True
    return False


def _detect_traj_format(run_dir):
    """Return one of: 'manifest', 'revelio_traj', 'cc_traj_jsonl',
    'cc_messages', 'codex_messages', 'kiss_yaml', or None."""
    if (run_dir / "manifest.json").exists():
        return "manifest"
    if (run_dir / "trajectory.json").exists():
        return "revelio_traj"
    if (run_dir / "trajectory.jsonl").exists():
        return "cc_traj_jsonl"
    msg_path = run_dir / "messages.jsonl"
    if msg_path.exists():
        try:
            with open(msg_path) as f:
                first = f.readline().strip()
            if first:
                obj = json.loads(first)
                if obj.get("type") == "thread.started":
                    return "codex_messages"
        except Exception:
            pass
        return "cc_messages"
    traj_dir = run_dir / "trajectories"
    if traj_dir.is_dir():
        if any(traj_dir.glob("*.yaml")) or any(traj_dir.glob("*.yml")):
            return "kiss_yaml"
    return None


def _extract_arvo_id(name):
    m = re.match(r"(arvo-\d+)", name)
    return m.group(1) if m else None


def _ts_to_iso(ts):
    if ts is None:
        return None
    try:
        import datetime as dt
        return dt.datetime.fromtimestamp(int(ts), dt.timezone.utc).isoformat().replace("+00:00", "Z")
    except Exception:
        return None


def _run_dir_to_id(run_dir, output_dir):
    """Convert a run directory path to a URL-safe run ID using '--' as separator."""
    rel = run_dir.relative_to(output_dir)
    return str(rel).replace(os.sep, "--")


def _find_all_run_dirs(output_dirs):
    """Recursively find all run directories (any supported trajectory format)."""
    results = []  # list of (run_dir, output_dir)
    for d in output_dirs:
        if not d.exists():
            continue
        seen = set()
        # Files that mark a run dir as their direct parent.
        for pattern in ("trajectory.json", "manifest.json", "trajectory.jsonl", "messages.jsonl"):
            for match in d.rglob(pattern):
                run_dir = match.parent
                if run_dir in seen:
                    continue
                seen.add(run_dir)
                if _is_run_dir(run_dir):
                    results.append((run_dir, d))
        # KISSSorcar puts yaml under a `trajectories/` subdir.
        for traj_dir in d.rglob("trajectories"):
            if not traj_dir.is_dir():
                continue
            if not (any(traj_dir.glob("*.yaml")) or any(traj_dir.glob("*.yml"))):
                continue
            run_dir = traj_dir.parent
            if run_dir in seen:
                continue
            seen.add(run_dir)
            if _is_run_dir(run_dir):
                results.append((run_dir, d))
    return results


def _find_run_dir(run_id, output_dirs):
    # Convert '--' separated run_id back to a relative path
    rel_path = run_id.replace("--", os.sep)
    for d in output_dirs:
        candidate = d / rel_path
        if _is_run_dir(candidate):
            return candidate
    return None


def _load_score(run_dir):
    """Load score.json from a run directory, returning a compact dict or None."""
    score_path = run_dir / "score.json"
    if not score_path.exists():
        return None
    try:
        s = _read_json(score_path)
        return {
            "file_hit": s.get("file_hit_any", False),
            "file_hit_all": s.get("file_hit", False),
            "function_hit": s.get("function_hit", False),
            "line_hit": s.get("line_hit", False),
            "file_recall": s.get("file_recall", 0),
            "file_precision": s.get("file_precision", 0),
            "func_recall": s.get("func_recall", 0),
            "func_precision": s.get("func_precision", 0),
            "line_recall": s.get("line_recall", 0),
            "line_precision": s.get("line_precision", 0),
        }
    except Exception:
        return None


def _detect_pipeline(run_dir, traj_info=None):
    """Detect the pipeline type from a run directory."""
    # If report.json exists, it's a claude-code run (new format)
    if (run_dir / "report.json").exists():
        return "claude-code"
    # Check parent directory name as hint
    parent_name = run_dir.parent.name
    if "claude_code" in parent_name:
        return "claude-code"
    return "file-scan"


def _traj_to_run_summary(run_id, traj_info, source_dir_name, run_dir=None):
    """Synthesize a run list entry from trajectory.json info for trajectory-only runs."""
    config = traj_info.get("config", {})
    model_name = config.get("model", {}).get("model_name", "")
    cost = traj_info.get("model_stats", {}).get("instance_cost", 0)
    target_file = traj_info.get("target_file", "")
    folder_path = traj_info.get("folder_path", "")

    pipeline = _detect_pipeline(run_dir, traj_info) if run_dir else "file-scan"

    # Build a target ref
    project = Path(folder_path).name if folder_path else ""
    target_ref = f"{project}/{target_file}" if project and target_file else (target_file or folder_path or "")

    # For claude-code runs, use report.json for cost if available
    if pipeline == "claude-code" and run_dir and (run_dir / "report.json").exists():
        try:
            report = _read_json(run_dir / "report.json")
            report_cost = report.get("total_cost_usd")
            if report_cost:
                cost = report_cost
            if not model_name:
                model_usage = report.get("modelUsage", {})
                if model_usage:
                    model_name = max(model_usage, key=lambda k: model_usage[k].get("costUSD", 0))
        except Exception:
            pass

    return {
        "run_id": run_id,
        "target_ref": target_ref,
        "target_type": pipeline,
        "model_name": model_name,
        "pipeline": pipeline,
        "created_at": traj_info.get("started_at_utc"),
        "counters": {},
        "total_cost": round(cost, 4),
        "status": traj_info.get("exit_status", "unknown"),
        "hypotheses_confirmed": 0,
        "source_dir": source_dir_name,
        "duration_seconds": traj_info.get("duration_seconds"),
        "score": _load_score(run_dir) if run_dir else None,
    }


def _traj_to_detail(run_dir, run_id=None):
    """Build a full detail response from a trajectory-only run directory."""
    traj = _read_json(run_dir / "trajectory.json")
    info = traj.get("info", {})
    config = info.get("config", {})
    model_name = config.get("model", {}).get("model_name", "")
    target_file = info.get("target_file", "")
    folder_path = info.get("folder_path", "")
    project = Path(folder_path).name if folder_path else ""
    pipeline = _detect_pipeline(run_dir, info)

    # Load report.json if present (new claude-code format)
    result_text = ""
    report_data = None
    report_path = run_dir / "report.json"
    if report_path.exists():
        try:
            report_data = _read_json(report_path)
            result_text = report_data.get("result", "")
            if not model_name:
                model_usage = report_data.get("modelUsage", {})
                if model_usage:
                    model_name = max(model_usage, key=lambda k: model_usage[k].get("costUSD", 0))
        except Exception:
            pass

    # Synthesize a manifest-like object
    manifest = {
        "run_id": run_id or run_dir.name,
        "target_ref": f"{project}/{target_file}" if project and target_file else "",
        "target_type": pipeline,
        "model_name": model_name,
        "pipeline": pipeline,
        "created_at_utc": info.get("started_at_utc"),
        "finished_at_utc": info.get("finished_at_utc"),
        "exit_status": info.get("exit_status"),
        "docker_image": info.get("docker_image"),
        "folder_path": folder_path,
        "target_file": target_file,
        "duration_seconds": info.get("duration_seconds"),
    }
    if report_data:
        manifest["num_turns"] = report_data.get("num_turns")
        model_usage = report_data.get("modelUsage", {})
        if model_usage:
            manifest["model_usage"] = model_usage

    # Detect message format: new (content arrays with tool_use/tool_result) vs old (tool_calls + role:tool)
    raw_msgs = traj.get("messages", [])
    uses_content_arrays = False
    for msg in raw_msgs:
        content = msg.get("content")
        if isinstance(content, list) and content:
            first_type = content[0].get("type", "") if isinstance(content[0], dict) else ""
            if first_type in ("tool_use", "tool_result", "text"):
                uses_content_arrays = True
                break
        if msg.get("tool_calls"):
            break  # old format

    messages = []
    if uses_content_arrays:
        messages = _parse_content_array_messages(raw_msgs)
    else:
        messages = _parse_tool_calls_messages(raw_msgs)

    # Build a single trajectory summary
    cost = info.get("model_stats", {}).get("instance_cost")
    if report_data and report_data.get("total_cost_usd"):
        cost = report_data["total_cost_usd"]
    traj_summaries = [{
        "agent_name": pipeline,
        "exit_status": info.get("exit_status"),
        "cost": cost,
        "api_calls": info.get("model_stats", {}).get("api_calls"),
        "path": "trajectory.json",
        "message_count": len(raw_msgs),
    }]

    return {
        "manifest": manifest,
        "index": {"counters": {}},
        "events": [],
        "log": "",
        "artifacts": {cat: [] for cat in ["code_review", "hypotheses", "poc", "validation", "reports"]},
        "hypothesis_outputs": {},
        "trajectory_summaries": traj_summaries,
        "trajectory_only": True,
        "inline_messages": messages,
        "result_text": result_text,
    }


def _parse_tool_calls_messages(raw_msgs):
    """Parse old file-scan format: assistant.tool_calls + role:tool responses."""
    messages = []
    tool_resp_map = {}
    for msg in raw_msgs:
        if msg.get("role") == "tool" and msg.get("tool_call_id"):
            tool_resp_map[msg["tool_call_id"]] = msg

    for msg in raw_msgs:
        if msg.get("role") == "tool":
            continue
        if msg.get("role") == "assistant" and msg.get("tool_calls"):
            content = msg.get("content", "")
            if content and content.strip():
                messages.append({
                    "role": "assistant",
                    "content": content,
                    "timestamp": msg.get("timestamp"),
                })
            for tc in msg["tool_calls"]:
                tc_id = tc.get("id", "")
                cmd = tc.get("arguments", {}).get("command", "")
                tool_name = tc.get("name", "bash")
                resp = tool_resp_map.get(tc_id)
                output = ""
                returncode = None
                if resp:
                    try:
                        parsed = json.loads(resp.get("content", "{}"))
                        output = parsed.get("output", "")
                        if not output and "output_head" in parsed:
                            output = parsed["output_head"] + "\n... (truncated) ...\n" + parsed.get("output_tail", "")
                        returncode = parsed.get("returncode")
                    except (json.JSONDecodeError, AttributeError):
                        output = str(resp.get("content", ""))
                messages.append({
                    "role": "tool",
                    "content": "",
                    "command": cmd if tool_name == "bash" else f"[{tool_name}] {json.dumps(tc.get('arguments', {}))}",
                    "command_returncode": returncode,
                    "command_output": output,
                    "timestamp": resp.get("timestamp") if resp else msg.get("timestamp"),
                })
        else:
            messages.append({
                "role": msg.get("role", "unknown"),
                "content": msg.get("content", ""),
                "timestamp": msg.get("timestamp"),
            })
    return messages


def _parse_content_array_messages(raw_msgs):
    """Parse new claude-code format: content arrays with tool_use/tool_result parts."""
    messages = []
    for msg in raw_msgs:
        role = msg.get("role", "unknown")
        content = msg.get("content", [])
        timestamp = msg.get("timestamp")

        if not isinstance(content, list):
            # Plain string content
            if content and str(content).strip():
                messages.append({"role": role, "content": str(content), "timestamp": timestamp})
            continue

        if role == "assistant":
            text_parts = []
            for part in content:
                if not isinstance(part, dict):
                    continue
                if part.get("type") == "text":
                    text_parts.append(part.get("text", ""))
                elif part.get("type") == "tool_use":
                    # Flush accumulated text
                    if text_parts:
                        messages.append({"role": "assistant", "content": "\n".join(text_parts), "timestamp": timestamp})
                        text_parts = []
                    tool_name = part.get("name", "")
                    tool_input = part.get("input", {})
                    cmd = tool_input.get("command", "") if tool_name in ("Bash", "bash") else ""
                    if cmd:
                        messages.append({
                            "role": "tool", "content": "",
                            "command": cmd,
                            "command_returncode": None, "command_output": "",
                            "timestamp": timestamp,
                            "_tool_use_id": part.get("id", ""),
                        })
                    else:
                        messages.append({
                            "role": "tool", "content": "",
                            "command": f"[{tool_name}] {json.dumps(tool_input)[:500]}",
                            "command_returncode": None, "command_output": "",
                            "timestamp": timestamp,
                            "_tool_use_id": part.get("id", ""),
                        })
            if text_parts:
                messages.append({"role": "assistant", "content": "\n".join(text_parts), "timestamp": timestamp})

        elif role == "user":
            for part in content:
                if not isinstance(part, dict):
                    continue
                if part.get("type") == "tool_result":
                    tool_use_id = part.get("tool_use_id", "")
                    result_content = part.get("content", "")
                    is_error = part.get("is_error", False)
                    # Extract text from result
                    output = ""
                    if isinstance(result_content, str):
                        output = result_content
                    elif isinstance(result_content, list):
                        output = "\n".join(
                            p.get("text", "") for p in result_content
                            if isinstance(p, dict) and p.get("type") == "text"
                        )
                    # Attach to matching tool message
                    if output:
                        for m in reversed(messages):
                            if m.get("role") == "tool" and m.get("_tool_use_id") == tool_use_id:
                                m["command_output"] = output[:10000]
                                m["command_returncode"] = 1 if is_error else 0
                                break
                elif part.get("type") == "text":
                    text = part.get("text", "")
                    if text.strip():
                        messages.append({"role": "user", "content": text, "timestamp": timestamp})
        else:
            # system or other roles
            text = ""
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text":
                    text += part.get("text", "")
            if text.strip():
                messages.append({"role": role, "content": text, "timestamp": timestamp})

    # Clean up internal _tool_use_id keys
    for m in messages:
        m.pop("_tool_use_id", None)
    return messages


def _cc_traj_to_run_summary(run_id, run_dir, source_dir_name):
    """Synthesize a run list entry from a Claude Code trajectory.jsonl."""
    traj_path = run_dir / "trajectory.jsonl"
    lines = _read_jsonl(traj_path)
    if not lines:
        return None
    # Extract info from init line
    init = lines[0] if lines[0].get("type") == "system" else {}
    model_name = init.get("model", "")
    cve_id = run_dir.name

    # Use the result line (last line with type=result) for accurate stats
    result_line = None
    for line in reversed(lines):
        if line.get("type") == "result":
            result_line = line
            break

    total_cost = 0.0
    duration_seconds = None
    num_turns = None
    status = "completed"

    if result_line:
        total_cost = result_line.get("total_cost_usd", 0.0)
        duration_ms = result_line.get("duration_ms")
        if duration_ms:
            duration_seconds = round(duration_ms / 1000, 1)
        num_turns = result_line.get("num_turns")
        if result_line.get("is_error"):
            status = "error"
        elif result_line.get("subtype") == "success":
            status = "completed"

    return {
        "run_id": run_id,
        "target_ref": cve_id,
        "target_type": "claude-code",
        "model_name": model_name,
        "pipeline": "claude-code",
        "created_at": None,
        "counters": {},
        "total_cost": round(total_cost, 2),
        "status": status,
        "hypotheses_confirmed": 0,
        "source_dir": source_dir_name,
        "duration_seconds": duration_seconds,
        "num_turns": num_turns,
        "score": _load_score(run_dir),
    }


def _cc_traj_to_detail(run_dir, run_id=None):
    """Build a detail response from a Claude Code trajectory.jsonl."""
    traj_path = run_dir / "trajectory.jsonl"
    lines = _read_jsonl(traj_path)
    if not lines:
        return {"error": "empty trajectory"}

    init = lines[0] if lines[0].get("type") == "system" else {}
    model_name = init.get("model", "")
    cve_id = run_dir.name

    # Find the result line for stats
    result_line = None
    for line in reversed(lines):
        if line.get("type") == "result":
            result_line = line
            break

    total_cost = 0.0
    duration_seconds = None
    num_turns = None
    exit_status = "completed"
    result_text = ""

    if result_line:
        total_cost = result_line.get("total_cost_usd", 0.0)
        duration_ms = result_line.get("duration_ms")
        if duration_ms:
            duration_seconds = round(duration_ms / 1000, 1)
        num_turns = result_line.get("num_turns")
        if result_line.get("is_error"):
            exit_status = "error"
        result_text = result_line.get("result", "")

    # Collect messages for display
    messages = []
    for line in lines:
        line_type = line.get("type")
        msg = line.get("message", {})

        if line_type == "assistant":
            content_parts = msg.get("content", [])
            text_parts = []
            for part in (content_parts if isinstance(content_parts, list) else []):
                if isinstance(part, dict) and part.get("type") == "text":
                    text_parts.append(part["text"])
                elif isinstance(part, dict) and part.get("type") == "tool_use":
                    tool_name = part.get("name", "")
                    tool_input = part.get("input", {})
                    if text_parts:
                        messages.append({
                            "role": "assistant",
                            "content": "\n".join(text_parts),
                        })
                        text_parts = []
                    cmd = tool_input.get("command", "") if tool_name in ("Bash", "bash") else ""
                    if cmd:
                        messages.append({
                            "role": "tool",
                            "content": "",
                            "command": cmd,
                            "command_returncode": None,
                            "command_output": "",
                        })
                    else:
                        messages.append({
                            "role": "tool",
                            "content": "",
                            "command": f"[{tool_name}] {json.dumps(tool_input)[:500]}",
                            "command_returncode": None,
                            "command_output": "",
                        })
            if text_parts:
                messages.append({
                    "role": "assistant",
                    "content": "\n".join(text_parts),
                })

        elif line_type == "user":
            content_parts = msg.get("content", [])
            if isinstance(content_parts, list):
                for part in content_parts:
                    if isinstance(part, dict) and part.get("type") == "tool_result":
                        result_content = part.get("content", "")
                        if isinstance(result_content, str) and result_content:
                            for m in reversed(messages):
                                if m.get("role") == "tool" and not m.get("command_output"):
                                    m["command_output"] = result_content[:5000]
                                    m["command_returncode"] = 0 if not part.get("is_error") else 1
                                    break
                        elif isinstance(result_content, list):
                            text = "\n".join(
                                p.get("text", "") for p in result_content
                                if isinstance(p, dict) and p.get("type") == "text"
                            )
                            if text:
                                for m in reversed(messages):
                                    if m.get("role") == "tool" and not m.get("command_output"):
                                        m["command_output"] = text[:5000]
                                        m["command_returncode"] = 0 if not part.get("is_error") else 1
                                        break
            # Also check tool_use_result on the line itself
            tur = line.get("tool_use_result")
            if isinstance(tur, dict):
                stdout = tur.get("stdout", "")
                stderr = tur.get("stderr", "")
                output = stdout
                if stderr:
                    output = output + "\n[stderr] " + stderr if output else stderr
                if output:
                    for m in reversed(messages):
                        if m.get("role") == "tool" and not m.get("command_output"):
                            m["command_output"] = output[:5000]
                            break

        elif line_type == "result":
            pass  # result_text stored separately for the Report tab

    # Build model usage info from result line
    model_usage = {}
    if result_line:
        model_usage = result_line.get("modelUsage", {})

    manifest = {
        "run_id": run_id or cve_id,
        "target_ref": cve_id,
        "target_type": "claude-code",
        "model_name": model_name,
        "pipeline": "claude-code",
        "exit_status": exit_status,
        "duration_seconds": duration_seconds,
        "num_turns": num_turns,
        "model_usage": model_usage,
    }

    api_calls = sum(1 for l in lines if l.get("type") == "assistant")
    traj_summaries = [{
        "agent_name": "claude-code",
        "exit_status": exit_status,
        "cost": round(total_cost, 2),
        "api_calls": api_calls,
        "path": "trajectory.jsonl",
        "message_count": len(lines),
    }]

    return {
        "manifest": manifest,
        "index": {"counters": {}},
        "events": [],
        "log": "",
        "artifacts": {cat: [] for cat in ["code_review", "hypotheses", "poc", "validation", "reports"]},
        "hypothesis_outputs": {},
        "trajectory_summaries": traj_summaries,
        "trajectory_only": True,
        "inline_messages": messages,
        "result_text": result_text,
    }


def _classify_verdict_label(c):
    """Human-readable classify verdict for stage2 UI."""
    if not c.get("is_vulnerability"):
        return "NOT"
    sanitizers = c.get("sanitizers") or []
    if c.get("is_asan") or "asan" in sanitizers:
        parts = [s.upper() for s in sanitizers[:3]] if sanitizers else ["ASAN"]
        return "+".join(parts) if len(parts) > 1 else "ASAN"
    if sanitizers:
        return "+".join(s.upper() for s in sanitizers[:3])
    return "VUL(no-san)"


def _load_revelio_stage2(traces_dir):
    """Load stage2 classify + dedup trace files."""
    classify_files = []
    dedup_files = []
    if not traces_dir.is_dir():
        return classify_files, dedup_files
    for f in sorted(traces_dir.glob("stage2_classify_*.json")):
        try:
            data = _read_json(f)
            classifications = []
            for c in data.get("classifications") or []:
                if not isinstance(c, dict):
                    continue
                classifications.append({
                    "index": c.get("index"),
                    "summary": (c.get("summary") or "")[:500],
                    "is_vulnerability": c.get("is_vulnerability"),
                    "sanitizers": c.get("sanitizers") or [],
                    "is_asan": c.get("is_asan"),
                    "severity": c.get("severity"),
                    "reason": (c.get("reason") or "")[:500],
                    "verdict_label": _classify_verdict_label(c),
                })
            classify_files.append({
                "file": data.get("file", f.stem),
                "input_count": data.get("input_count", len(classifications)),
                "classifications": classifications,
                "cost": data.get("cost"),
                "calls": data.get("calls"),
            })
        except Exception:
            continue
    for f in sorted(traces_dir.glob("stage2_dedup_*.json")):
        try:
            data = _read_json(f)
            dedup_files.append({
                "file": data.get("file", f.stem),
                "candidate_pairs": data.get("candidate_pairs"),
                "kept_count": data.get("kept_count"),
                "removed": data.get("removed") or [],
                "comparisons": data.get("comparisons") or [],
            })
        except Exception:
            continue
    return classify_files, dedup_files


def _norm_summary(s):
    return (s or "").strip().lower()


def _hotspot_loc_key(hotspot):
    if not isinstance(hotspot, dict):
        return None
    fn = hotspot.get("function")
    line = hotspot.get("line_start")
    if not fn or line is None:
        return None
    try:
        return (fn, int(line))
    except (TypeError, ValueError):
        return None


def _load_stage1_hypothesis_locations(traces_dir):
    """Map each file's raw classify index -> (function, line_start) hotspot
    location, read from stage1's aggregated_hypotheses (index-aligned with
    stage2_classify's classification index). Hypotheses that are otherwise
    textually identical (e.g. the same generic "missing NULL check" summary
    generated for several call sites in one file) can only be told apart by
    their actual code location, which classify-stage data alone doesn't carry.
    """
    locations = {}
    if not traces_dir or not traces_dir.is_dir():
        return locations
    for f in sorted(traces_dir.glob("stage1_*.json")):
        try:
            data = _read_json(f)
        except Exception:
            continue
        fname = data.get("file", f.stem)
        by_idx = {}
        for i, item in enumerate(data.get("aggregated_hypotheses") or []):
            hyp = item.get("hypothesis") if isinstance(item, dict) and "hypothesis" in item else item
            if not isinstance(hyp, dict):
                continue
            hotspots = hyp.get("hotspots") or []
            key = _hotspot_loc_key(hotspots[0]) if hotspots else None
            if key:
                by_idx[i] = key
        if by_idx:
            locations[fname] = by_idx
    return locations


def _stage1_hypothesis_summaries(hyp_list):
    out = []
    for item in hyp_list or []:
        if not isinstance(item, dict):
            continue
        hyp = item.get("hypothesis")
        if isinstance(hyp, dict):
            s = hyp.get("summary") or hyp.get("title") or hyp.get("description") or ""
        elif isinstance(hyp, str):
            s = hyp
        else:
            s = item.get("summary") or item.get("title") or item.get("description") or ""
        s = (s or "").strip()
        if s:
            out.append(s[:500])
    return out


def _classify_kept(c):
    return bool(c.get("is_vulnerability")) and bool(c.get("sanitizers") or c.get("is_asan"))


def _reasons_align(a, b, n=160):
    a = (a or "").strip()
    b = (b or "").strip()
    if not a or not b:
        return True
    if a == b:
        return True
    chunk = a[:n]
    return chunk in b or b[:n] in a


def _stage3_entry_from_stage(stage):
    if not stage:
        return None
    info = stage.get("info") or {}
    return {
        "verdict": info.get("verdict"),
        "confidence": info.get("confidence"),
        "reason": info.get("reason") or "",
    }


def _resolve_stage3_stage(file_, norm, filt, hypothesis_stages, stage1_locations=None, classify_index=None):
    """Match a pipeline row to its stage3 filter trace.

    Filter traces are keyed by position in the post-dedup batch, not by the
    classify index or global hypothesis id — positional maps collide. Match on
    (file, summary) and disambiguate with verdict/reason when needed.
    """
    if not file_ or not norm:
        return None
    stages = [
        s for s in hypothesis_stages
        if s.get("stage") == "stage3.filter"
        and (s.get("info") or {}).get("file") == file_
        and _norm_summary((s.get("info") or {}).get("summary")) == norm
    ]
    if not stages:
        return None
    if len(stages) == 1:
        return stages[0]
    verdict = (filt or {}).get("verdict")
    reason = (filt or {}).get("reason") or ""
    if verdict:
        by_verdict = [
            s for s in stages
            if (s.get("info") or {}).get("verdict") == verdict
            and _reasons_align(reason, (s.get("info") or {}).get("reason"))
        ]
        if len(by_verdict) == 1:
            return by_verdict[0]
        if by_verdict:
            stages = by_verdict
    if len(stages) == 1:
        return stages[0]
    return None


def _build_revelio_hypothesis_pipeline(
    *,
    stage2_classify,
    stage2_dedup,
    hypothesis_stages,
    hypotheses,
    poc_stages,
    val_by_hid,
    rep_by_hid,
    stage1_locations=None,
    duplicate_of=None,
):
    """One row per raw hypothesis with KEPT/DROPPED status at each pipeline gate."""
    duplicate_of = duplicate_of or {}
    stage1_locations = stage1_locations or {}
    dedup_by_file = {df.get("file"): df for df in stage2_dedup}

    # Group final hypotheses by (file, summary) rather than collapsing into a
    # single dict entry: several distinct hypotheses can share identical
    # generic wording (e.g. the same "missing NULL check" summary generated
    # for multiple call sites in one file). When a (file, summary) group has
    # more than one candidate, disambiguate by (function, line) location;
    # otherwise every row with that text would be wrongly attributed to
    # whichever candidate happened to be inserted last.
    final_candidates = {}
    all_ghids = set()
    for h in hypotheses:
        if not isinstance(h, dict):
            continue
        fp = h.get("file_path") or ""
        norm = _norm_summary(h.get("summary") or h.get("title") or h.get("description"))
        ghid = h.get("hypothesis_id") or h.get("id")
        if not (fp and norm and ghid):
            continue
        all_ghids.add(ghid)
        refs = h.get("references") or []
        loc = _hotspot_loc_key(refs[0]) if refs else None
        final_candidates.setdefault((fp, norm), []).append((ghid, loc))

    def _resolve_global_hid(file_, norm_, idx_):
        candidates = final_candidates.get((file_, norm_))
        if not candidates:
            return None
        if len(candidates) == 1:
            return candidates[0][0]
        loc = stage1_locations.get(file_, {}).get(idx_)
        if loc:
            for ghid, cand_loc in candidates:
                if cand_loc == loc:
                    return ghid
        return None

    poc_hids = {
        ps.get("hid")
        for ps in poc_stages
        if ps.get("hid") and "PoCBuilder" in (ps.get("agent") or "")
    }
    confirmed_hids = set()
    for ghid in all_ghids | poc_hids:
        if not ghid:
            continue
        # val_by_hid/rep_by_hid store the raw handoff wrapper
        # ({"stage", ..., "data": {...}}) — the real fields live under "data".
        v = (val_by_hid.get(ghid) or {}).get("data") or {}
        r = (rep_by_hid.get(ghid) or {}).get("data") or {}
        if v.get("crash_detected") or r.get("crash_detected"):
            confirmed_hids.add(ghid)

    pipeline = []
    for cf in stage2_classify:
        df = dedup_by_file.get(cf.get("file")) or {}
        removed_map = {
            _norm_summary(r.get("summary")): (r.get("reason") or "")
            for r in (df.get("removed") or [])
            if isinstance(r, dict)
        }
        for c in cf.get("classifications") or []:
            idx = c.get("index")
            if idx is None:
                continue
            summary = c.get("summary") or ""
            norm = _norm_summary(summary)
            hid = f"SF{int(idx) + 1:02d}"
            stage3_trace_key = None

            if _classify_kept(c):
                classify = {"status": "kept", "verdict_label": c.get("verdict_label"), "reason": ""}
            else:
                classify = {"status": "dropped", "verdict_label": c.get("verdict_label"), "reason": c.get("reason") or ""}

            if classify["status"] == "dropped":
                dedup = {"status": "skipped", "reason": ""}
                filt = {"status": "skipped", "verdict": None, "reason": ""}
                dropped_at = "classify"
            elif norm in removed_map:
                dedup = {"status": "dropped", "reason": removed_map[norm]}
                filt = {"status": "skipped", "verdict": None, "reason": ""}
                dropped_at = "dedup"
            else:
                dedup = {"status": "kept", "reason": ""}
                file_ = cf.get("file")
                s3_stage = _resolve_stage3_stage(
                    file_, norm, None, hypothesis_stages, stage1_locations, idx,
                )
                s3 = _stage3_entry_from_stage(s3_stage)
                stage3_trace_key = s3_stage.get("stage_key") if s3_stage else None
                if s3:
                    verdict = s3.get("verdict")
                    conf = s3.get("confidence") or 0
                    reason = s3.get("reason") or ""
                    if conf <= 0:
                        # A confidence of exactly 0 means the filter agent
                        # couldn't actually evaluate the hypothesis (e.g. "unable
                        # to access container") rather than a genuine judgment —
                        # treat it as unresolved, not as having passed review.
                        filt = {"status": "skipped", "verdict": verdict, "reason": reason}
                        dropped_at = None
                    elif verdict == "INVALID" and conf >= 0.7:
                        filt = {"status": "dropped", "verdict": verdict, "reason": reason}
                        dropped_at = "filter"
                    else:
                        filt = {"status": "kept", "verdict": verdict, "reason": reason}
                        dropped_at = None
                else:
                    filt = {"status": "skipped", "verdict": None, "reason": ""}
                    dropped_at = None
                    stage3_trace_key = None

            global_hid = _resolve_global_hid(cf.get("file"), norm, idx)
            survived = global_hid is not None and not dropped_at
            confirmed = bool(global_hid and global_hid in confirmed_hids)
            crash_confidence = (
                ((val_by_hid.get(global_hid) or {}).get("data") or {}).get("crash_confidence")
                if global_hid else None
            )

            poc_status = "skipped"
            if global_hid and global_hid in poc_hids:
                poc_status = "confirmed" if confirmed else "attempted"

            pipeline.append({
                "index": idx,
                "hid": hid,
                "global_hid": global_hid,
                "file": cf.get("file"),
                "summary": summary,
                "classify": classify,
                "dedup": dedup,
                "filter": filt,
                "poc": {"status": poc_status},
                "final": {
                    "survived": survived,
                    "confirmed": confirmed,
                    "duplicate_of": duplicate_of.get(global_hid) if global_hid else None,
                    "crash_confidence": crash_confidence,
                },
                "dropped_at": dropped_at,
                "stage3_trace_key": stage3_trace_key,
            })

    pipeline.sort(key=lambda r: (r.get("file") or "", r.get("index") or 0))
    return pipeline


def _compute_revelio_funnel(*, pipeline, confirmed, ranked_count=None):
    """Derive funnel counts directly from the per-hypothesis pipeline rows
    (the same data behind the Hypothesis pipeline table) instead of separate
    event/trace heuristics, so every stage count is guaranteed consistent
    and monotonically non-increasing."""
    raw_count = len(pipeline)
    after_classify = sum(1 for r in pipeline if r["classify"]["status"] == "kept")
    after_dedup = sum(1 for r in pipeline if r["dedup"]["status"] == "kept")
    # Survived the static-filter gate (not dropped at filter), including
    # unresolved reviews (filter status "skipped", e.g. container access errors).
    after_static_filter = sum(
        1 for r in pipeline
        if r["dedup"]["status"] == "kept" and r.get("dropped_at") != "filter"
    )
    if ranked_count is not None:
        after_rank = ranked_count
    else:
        after_rank = len({
            r["global_hid"] for r in pipeline
            if r["final"]["survived"] and r.get("global_hid")
        })
    poc_attempted = len({
        r["global_hid"] for r in pipeline
        if r["poc"]["status"] in ("attempted", "confirmed") and r.get("global_hid")
    })

    return {
        "raw": raw_count,
        "after_classify": after_classify,
        "after_dedup": after_dedup,
        "after_static_filter": after_static_filter,
        "after_rank": after_rank,
        "poc_attempted": poc_attempted,
        "confirmed": confirmed,
    }


def _compute_revelio_cost(*, stage2_classify, hypothesis_stages, poc_stages, events):
    scan_cost = 0.0
    for ev in events:
        payload = ev.get("payload") or {}
        if ev.get("event") == "scan_filter_end" and payload.get("total_cost"):
            scan_cost = float(payload["total_cost"])
            break
    if scan_cost == 0.0:
        for cf in stage2_classify:
            if cf.get("cost"):
                scan_cost += float(cf["cost"])
        for s in hypothesis_stages:
            info = s.get("info") or {}
            if info.get("model_cost"):
                scan_cost += float(info["model_cost"])
    poc_cost = 0.0
    for ps in poc_stages:
        info = ps.get("info") or {}
        stats = info.get("model_stats") or {}
        if stats.get("instance_cost"):
            poc_cost += float(stats["instance_cost"])
    return round(scan_cost + poc_cost, 4)


def _revelio_to_detail(run_dir, run_id=None, *, include_messages=True):
    """Detail builder for Revelio's `scan_filter_detect` pipeline.

    Bundles each hypothesis (from hypotheses.json) with its handoff artifacts
    (poc_recipe_*.json, validation_*.json, report_*.json) and parses the
    per-hypothesis PoCBuilderAgent trajectory into inline messages.
    """
    manifest = _read_json(run_dir / "manifest.json") if (run_dir / "manifest.json").exists() else {}
    events = _read_jsonl(run_dir / "events.jsonl") if (run_dir / "events.jsonl").exists() else []
    log_text = (run_dir / "log.txt").read_text(errors="replace") if (run_dir / "log.txt").exists() else ""

    # Hypotheses (top-level) → list of dicts
    hyps_path = run_dir / "hypotheses.json"
    hypotheses = []
    if hyps_path.exists():
        try:
            hyps = _read_json(hyps_path)
            if isinstance(hyps, dict):
                hypotheses = hyps.get("hypotheses", []) or []
            elif isinstance(hyps, list):
                hypotheses = hyps
        except Exception:
            pass

    # Per-hypothesis handoffs
    handoff_dir = run_dir / "artifacts" / "handoffs"
    def _maybe_json(p):
        try:
            return _read_json(p) if p.exists() else None
        except Exception:
            return None

    poc_by_hid = {}
    val_by_hid = {}
    rep_by_hid = {}
    duplicate_of = {}
    if handoff_dir.is_dir():
        for f in handoff_dir.glob("poc_recipe_*.json"):
            hid = f.stem.replace("poc_recipe_", "")
            poc_by_hid[hid] = _maybe_json(f)
        for f in handoff_dir.glob("validation_*.json"):
            hid = f.stem.replace("validation_", "")
            val_by_hid[hid] = _maybe_json(f)
        for f in handoff_dir.glob("report_*.json"):
            hid = f.stem.replace("report_", "")
            rep_by_hid[hid] = _maybe_json(f)
        dedup_wrapper = _maybe_json(handoff_dir / "dedup_findings.json")
        duplicate_of = ((dedup_wrapper or {}).get("data") or {}).get("duplicate_of") or {}

    # PoC-stage trajectories live in trajectory.json under `agents`
    # (PoCBuilderAgent_SFNN, ReporterAgent_SFNN_attempt*, …)
    poc_stages = []
    traj_path = run_dir / "trajectory.json"
    poc_idx = 0
    if traj_path.exists():
        try:
            traj_raw = _read_json(traj_path)
            agents = traj_raw.get("agents", {}) if isinstance(traj_raw, dict) else {}
            for agent_name, agent_data in agents.items():
                if not isinstance(agent_data, dict):
                    continue
                msgs = agent_data.get("messages", []) or []
                parsed = _parse_tool_calls_messages(msgs) if include_messages else []
                hm = re.search(r"_(SF\d+)(?:_|$)", agent_name)
                hid = hm.group(1) if hm else None
                poc_stages.append({
                    "stage_key": f"poc-{poc_idx}",
                    "label": agent_name,
                    "hid": hid,
                    "agent": agent_name,
                    "info": agent_data.get("info", {}),
                    "messages": parsed,
                    "raw_count": len(msgs),
                    "message_count": len(msgs),
                })
                poc_idx += 1
        except Exception:
            pass

    # Hypothesis-stage trajectories live under traces/{stage1,stage2,stage3_filter}.
    hypothesis_stages = []
    stage2_classify = []
    stage2_dedup = []
    stage3_error_count = 0
    stage3_total_files = 0
    traces_dir = run_dir / "traces"
    if traces_dir.is_dir():
        stage2_classify, stage2_dedup = _load_revelio_stage2(traces_dir)
        stage1_idx = 0
        for f in sorted(traces_dir.glob("stage1_*.json")):
            try:
                data = _read_json(f)
            except Exception:
                continue
            fname = data.get("file", f.stem)

            wf = data.get("wholefile") or {}
            wf_msgs = wf.get("messages") or []
            if wf_msgs:
                parsed = _parse_tool_calls_messages(wf_msgs) if include_messages else []
                hypothesis_stages.append({
                    "stage_key": f"hyp-s1-wf-{stage1_idx}",
                    "label": f"stage1 · whole-file ({fname})",
                    "stage": "stage1.wholefile",
                    "info": {
                        "hypothesis_count": len((wf.get("hypotheses") or [])),
                        "generated": _stage1_hypothesis_summaries(wf.get("hypotheses") or []),
                    },
                    "messages": parsed,
                    "raw_count": len(wf_msgs),
                    "message_count": len(wf_msgs),
                })
                stage1_idx += 1

            for idx, foc in enumerate(data.get("focused") or []):
                if not isinstance(foc, dict):
                    continue
                fmsgs = foc.get("messages") or []
                if not fmsgs:
                    continue
                parsed = _parse_tool_calls_messages(fmsgs) if include_messages else []
                hypothesis_stages.append({
                    "stage_key": f"hyp-s1-foc-{stage1_idx}",
                    "label": f"stage1 · focused #{idx} ({fname})",
                    "stage": "stage1.focused",
                    "info": {
                        "focus_index": idx,
                        "focus_prompt": (foc.get("focus_prompt") or "")[:200],
                        "hypothesis_count": len((foc.get("hypotheses") or [])),
                        "generated": _stage1_hypothesis_summaries(foc.get("hypotheses") or []),
                    },
                    "messages": parsed,
                    "raw_count": len(fmsgs),
                    "message_count": len(fmsgs),
                })
                stage1_idx += 1

            for fn in data.get("functions") or []:
                if not isinstance(fn, dict):
                    continue
                fmsgs = fn.get("messages") or []
                if not fmsgs:
                    continue
                fn_name = fn.get("function") or "?"
                parsed = _parse_tool_calls_messages(fmsgs) if include_messages else []
                hypothesis_stages.append({
                    "stage_key": f"hyp-s1-fn-{stage1_idx}",
                    "label": f"stage1 · function `{fn_name}` ({fname})",
                    "stage": "stage1.function",
                    "info": {
                        "function": fn_name,
                        "hypothesis_count": len((fn.get("hypotheses") or [])),
                        "generated": _stage1_hypothesis_summaries(fn.get("hypotheses") or []),
                    },
                    "messages": parsed,
                    "raw_count": len(fmsgs),
                    "message_count": len(fmsgs),
                })
                stage1_idx += 1

        stage3_idx = 0
        stage3_dir = traces_dir / "stage3_filter"
        if stage3_dir.is_dir():
            stage3_files = sorted(stage3_dir.glob("*.json"))

            def _hyp_idx_key(p):
                m = re.search(r"hyp_(\d+)_", p.name)
                return int(m.group(1)) if m else 1_000_000

            stage3_files.sort(key=_hyp_idx_key)
            for f in stage3_files:
                try:
                    data = _read_json(f)
                except Exception:
                    continue
                stage3_total_files += 1
                traj = data.get("trajectory") or []
                if not traj:
                    # An empty trajectory with an error field means the filter
                    # call itself failed (e.g. an upstream API auth error) —
                    # the verdict/confidence fields are meaningless defaults,
                    # not a real "reviewed and rejected" outcome. Track this
                    # so the funnel can tell a genuine 0 apart from a stage
                    # that never actually ran.
                    if data.get("error"):
                        stage3_error_count += 1
                    continue
                hi = data.get("hypothesis_index")
                verdict = data.get("verdict") or "?"
                hid = f"SF{int(hi) + 1:02d}" if hi is not None else None
                parsed = _parse_tool_calls_messages(traj) if include_messages else []
                hypothesis_stages.append({
                    "stage_key": f"hyp-s3-{stage3_idx}",
                    "label": f"stage3 filter · hyp #{hi} — {verdict}",
                    "stage": "stage3.filter",
                    "hid": hid,
                    "info": {
                        "file": data.get("file"),
                        "hypothesis_index": hi,
                        "verdict": verdict,
                        "confidence": data.get("confidence"),
                        "summary": data.get("summary", ""),
                        "reason": (data.get("reason") or "")[:1000],
                        "model_cost": data.get("model_cost"),
                        "model_calls": data.get("model_calls"),
                    },
                    "messages": parsed,
                    "raw_count": len(traj),
                    "message_count": len(traj),
                })
                stage3_idx += 1

    # Hypothesis metadata for each PoC stage (so the frontend can show what
    # hypothesis the PoC builder was working on).
    hyp_by_hid = {}
    for h in hypotheses:
        if isinstance(h, dict):
            hid = h.get("hypothesis_id") or h.get("id")
            if hid:
                hyp_by_hid[hid] = h

    # Attach artifact summaries to each PoC stage for inline context.
    for ps in poc_stages:
        hid = ps.get("hid")
        ps["hypothesis"] = hyp_by_hid.get(hid) if hid else None
        ps["poc"] = poc_by_hid.get(hid) if hid else None
        ps["validation"] = val_by_hid.get(hid) if hid else None
        ps["report"] = rep_by_hid.get(hid) if hid else None

    # Confirmed count derived from validation/report artifacts.
    confirmed = 0
    for hid in hyp_by_hid:
        # val_by_hid/rep_by_hid store the raw handoff wrapper — unwrap "data".
        v = (val_by_hid.get(hid) or {}).get("data") or {}
        r = (rep_by_hid.get(hid) or {}).get("data") or {}
        if v.get("crash_detected") or r.get("crash_detected"):
            confirmed += 1

    hypothesis_pipeline = _build_revelio_hypothesis_pipeline(
        stage2_classify=stage2_classify,
        stage2_dedup=stage2_dedup,
        hypothesis_stages=hypothesis_stages,
        hypotheses=hypotheses,
        poc_stages=poc_stages,
        val_by_hid=val_by_hid,
        rep_by_hid=rep_by_hid,
        stage1_locations=_load_stage1_hypothesis_locations(traces_dir),
        duplicate_of=duplicate_of,
    )

    funnel = _compute_revelio_funnel(
        pipeline=hypothesis_pipeline,
        confirmed=confirmed,
        ranked_count=len(hyp_by_hid),
    )
    # A "Filtered: 0" that comes from every filter call erroring out (e.g. an
    # upstream API auth failure) looks identical to a legitimate "everything
    # was reviewed and rejected" outcome unless we flag it explicitly.
    funnel["filter_stage_failed"] = stage3_total_files > 0 and stage3_error_count == stage3_total_files
    cost_total = _compute_revelio_cost(
        stage2_classify=stage2_classify,
        hypothesis_stages=hypothesis_stages,
        poc_stages=poc_stages,
        events=events,
    )

    duration_seconds = None
    if events:
        try:
            import datetime as dt
            ts0 = events[0].get("timestamp")
            ts1 = events[-1].get("timestamp")
            if ts0 and ts1:
                t0 = dt.datetime.fromisoformat(ts0.replace("Z", "+00:00"))
                t1 = dt.datetime.fromisoformat(ts1.replace("Z", "+00:00"))
                duration_seconds = round((t1 - t0).total_seconds(), 1)
        except Exception:
            pass

    hyp_msg_total = sum(s.get("raw_count", 0) for s in hypothesis_stages)
    poc_msg_total = sum(s.get("raw_count", 0) for s in poc_stages)

    poc_status = "not_run"
    if poc_stages:
        poc_status = "ran"
    elif funnel.get("after_rank", 0) == 0:
        poc_status = "skipped_no_hypotheses"
    elif not traj_path.exists():
        poc_status = "skipped_or_incomplete"

    return {
        "manifest": manifest,
        "events": events,
        "log": log_text,
        "revelio": True,
        "revelio_hypothesis_stages": hypothesis_stages,
        "revelio_poc_stages": poc_stages,
        "revelio_stage2_classify": stage2_classify,
        "revelio_stage2_dedup": stage2_dedup,
        "revelio_hypothesis_pipeline": hypothesis_pipeline,
        "revelio_summary": {
            "hypothesis_count": len(hyp_by_hid),
            "confirmed": confirmed,
            "hypothesis_steps": len(hypothesis_stages),
            "poc_steps": len(poc_stages),
            "hypothesis_msgs": hyp_msg_total,
            "poc_msgs": poc_msg_total,
            "cost_total": cost_total,
            "duration_seconds": duration_seconds,
            "funnel": funnel,
            "poc_status": poc_status,
            "has_trajectory": traj_path.exists(),
        },
        # Legacy fields kept empty so the existing frontend doesn't choke
        "index": {"counters": {}},
        "artifacts": {cat: [] for cat in ["code_review", "hypotheses", "poc", "validation", "reports"]},
        "hypothesis_outputs": {},
        "trajectory_summaries": [],
    }


def _revelio_get_stage(run_dir, stage_key, offset=0, limit=None):
    """Load messages for a single Revelio stage (lazy-load API)."""
    detail = _revelio_to_detail(run_dir, include_messages=True)
    for collection in (detail.get("revelio_hypothesis_stages") or [], detail.get("revelio_poc_stages") or []):
        for stage in collection:
            if stage.get("stage_key") == stage_key:
                messages = stage.get("messages") or []
                total = len(messages)
                if limit is not None:
                    messages = messages[offset:offset + limit]
                else:
                    messages = messages[offset:]
                return {
                    "stage_key": stage_key,
                    "label": stage.get("label"),
                    "stage": stage.get("stage"),
                    "hid": stage.get("hid"),
                    "info": stage.get("info"),
                    "messages": messages,
                    "total": total,
                    "offset": offset,
                    "limit": limit,
                }
    return None


# ── New experiment_traj formats (ClaudeCode / Codex / KISSSorcar) ─────────
#
# All three live as one run dir per (agent, arvo-case) with their own native
# trajectory file. We translate each into the existing "inline_messages"
# contract the frontend already understands.

def _read_metrics(run_dir):
    p = run_dir / "metrics.json"
    if not p.exists():
        return {}
    try:
        return _read_json(p)
    except Exception:
        return {}


def _read_report_md(run_dir):
    p = run_dir / "report.md"
    if not p.exists():
        return ""
    try:
        return p.read_text(errors="replace")
    except Exception:
        return ""


def _parse_cc_messages(lines):
    """Parse the ClaudeCode messages.jsonl stream (`{content: [...], ...}` per line)."""
    messages = []
    tool_use_to_idx = {}
    for line in lines:
        # Skip init/system lines (top-level "subtype": "init" or wrapped under "data")
        if line.get("subtype") == "init":
            continue
        if isinstance(line.get("data"), dict) and line["data"].get("type") == "system":
            continue

        content = line.get("content")
        if not isinstance(content, list):
            continue

        for part in content:
            if not isinstance(part, dict):
                continue

            # Thinking block
            if "thinking" in part and "id" not in part and "tool_use_id" not in part:
                txt = part.get("thinking", "")
                if txt and txt.strip():
                    messages.append({"role": "assistant", "content": txt})
                continue

            ptype = part.get("type")

            # Plain assistant text
            if ptype == "text" or ("text" in part and "id" not in part and "tool_use_id" not in part):
                txt = part.get("text", "")
                if txt and txt.strip():
                    messages.append({"role": "assistant", "content": txt})
                continue

            # Assistant tool_use (has id + name + input)
            if "id" in part and "name" in part and "input" in part:
                tool_name = part.get("name", "")
                tool_input = part.get("input", {}) or {}
                cmd = tool_input.get("command", "") if tool_name in ("Bash", "bash") else ""
                disp = cmd if cmd else f"[{tool_name}] {json.dumps(tool_input)[:500]}"
                idx = len(messages)
                messages.append({
                    "role": "tool", "content": "",
                    "command": disp,
                    "command_returncode": None,
                    "command_output": "",
                })
                tool_use_to_idx[part["id"]] = idx
                continue

            # User tool_result (has tool_use_id)
            if "tool_use_id" in part:
                tu_id = part["tool_use_id"]
                idx = tool_use_to_idx.get(tu_id)
                if idx is None:
                    continue
                output = part.get("content", "")
                if isinstance(output, list):
                    output = "\n".join(
                        p.get("text", "") for p in output if isinstance(p, dict)
                    )
                is_error = part.get("is_error", False)
                # Prefer tool_use_result if present on the line (has stdout/stderr)
                tur = line.get("tool_use_result")
                if isinstance(tur, dict):
                    stdout = tur.get("stdout", "") or ""
                    stderr = tur.get("stderr", "") or ""
                    if stdout or stderr:
                        out = stdout
                        if stderr:
                            out = (out + "\n[stderr] " + stderr) if out else stderr
                        output = out
                messages[idx]["command_output"] = str(output)[:10000]
                messages[idx]["command_returncode"] = 1 if is_error else 0
                continue
    return messages


def _cc_msg_to_run_summary(run_id, run_dir, source_dir_name):
    metrics = _read_metrics(run_dir)
    # Try to read init line for model
    model_name = ""
    try:
        with open(run_dir / "messages.jsonl") as f:
            first = f.readline().strip()
        if first:
            obj = json.loads(first)
            data = obj.get("data", obj)
            model_name = data.get("model", "") or ""
    except Exception:
        pass
    if not model_name:
        usage = metrics.get("model_usage", {}) or {}
        if usage:
            model_name = max(usage, key=lambda k: usage[k].get("costUSD", 0))

    duration = None
    if metrics.get("duration_ms"):
        duration = round(metrics["duration_ms"] / 1000, 1)

    status = "error" if metrics.get("is_error") else "completed"
    arvo_id = _extract_arvo_id(run_dir.name) or run_dir.name

    return {
        "run_id": run_id,
        "target_ref": arvo_id,
        "target_type": "claude-code",
        "model_name": model_name,
        "pipeline": "claude-code",
        "created_at": None,
        "counters": {},
        "total_cost": round(metrics.get("total_cost_usd", 0) or 0, 4),
        "status": status,
        "hypotheses_confirmed": 0,
        "source_dir": source_dir_name,
        "duration_seconds": duration,
        "num_turns": metrics.get("num_turns"),
        "score": _load_score(run_dir),
    }


def _cc_msg_to_detail(run_dir, run_id=None):
    lines = _read_jsonl(run_dir / "messages.jsonl")
    metrics = _read_metrics(run_dir)
    model_name = ""
    if lines:
        first = lines[0]
        data = first.get("data", first)
        model_name = data.get("model", "") or ""
    if not model_name:
        usage = metrics.get("model_usage", {}) or {}
        if usage:
            model_name = max(usage, key=lambda k: usage[k].get("costUSD", 0))

    duration = None
    if metrics.get("duration_ms"):
        duration = round(metrics["duration_ms"] / 1000, 1)

    arvo_id = _extract_arvo_id(run_dir.name) or run_dir.name
    manifest = {
        "run_id": run_id or run_dir.name,
        "target_ref": arvo_id,
        "target_type": "claude-code",
        "model_name": model_name,
        "pipeline": "claude-code",
        "exit_status": "error" if metrics.get("is_error") else "completed",
        "duration_seconds": duration,
        "num_turns": metrics.get("num_turns"),
        "model_usage": metrics.get("model_usage", {}),
    }

    messages = _parse_cc_messages(lines)
    traj_summaries = [{
        "agent_name": "claude-code",
        "exit_status": manifest["exit_status"],
        "cost": round(metrics.get("total_cost_usd", 0) or 0, 4),
        "api_calls": metrics.get("llm_call_number"),
        "path": "messages.jsonl",
        "message_count": len(lines),
    }]

    return {
        "manifest": manifest,
        "index": {"counters": {}},
        "events": [],
        "log": "",
        "artifacts": {cat: [] for cat in ["code_review", "hypotheses", "poc", "validation", "reports"]},
        "hypothesis_outputs": {},
        "trajectory_summaries": traj_summaries,
        "trajectory_only": True,
        "inline_messages": messages,
        "result_text": _read_report_md(run_dir),
    }


def _parse_codex_messages(lines):
    """Parse Codex messages.jsonl (item.started/item.completed events)."""
    messages = []
    pending = {}  # item id -> messages-index
    for line in lines:
        t = line.get("type")
        item = line.get("item") or {}
        it_type = item.get("type")

        if t == "item.completed" and it_type == "agent_message":
            txt = item.get("text", "")
            if txt and txt.strip():
                messages.append({"role": "assistant", "content": txt})

        elif t == "item.started" and it_type == "command_execution":
            cmd = item.get("command", "")
            idx = len(messages)
            messages.append({
                "role": "tool", "content": "",
                "command": cmd,
                "command_returncode": None,
                "command_output": "",
            })
            pending[item.get("id")] = idx

        elif t == "item.completed" and it_type == "command_execution":
            iid = item.get("id")
            idx = pending.pop(iid, None)
            if idx is None:
                idx = len(messages)
                messages.append({
                    "role": "tool", "content": "",
                    "command": item.get("command", ""),
                    "command_returncode": None,
                    "command_output": "",
                })
            output = (item.get("aggregated_output") or "")[:10000]
            messages[idx]["command_output"] = output
            ec = item.get("exit_code")
            if isinstance(ec, int):
                messages[idx]["command_returncode"] = ec
            elif item.get("status") == "failed":
                messages[idx]["command_returncode"] = 1
            else:
                messages[idx]["command_returncode"] = 0

        elif t == "item.completed" and it_type == "file_change":
            payload = {k: v for k, v in item.items() if k not in ("type",)}
            messages.append({
                "role": "tool", "content": "",
                "command": f"[file_change] {json.dumps(payload)[:500]}",
                "command_returncode": 0,
                "command_output": "",
            })
    return messages


def _codex_msg_to_run_summary(run_id, run_dir, source_dir_name):
    metrics = _read_metrics(run_dir)
    arvo_id = _extract_arvo_id(run_dir.name) or run_dir.name
    status = "error" if metrics.get("is_error") else (metrics.get("stop_reason", "completed") or "completed")
    return {
        "run_id": run_id,
        "target_ref": arvo_id,
        "target_type": "codex",
        "model_name": metrics.get("model", ""),
        "pipeline": "codex",
        "created_at": None,
        "counters": {},
        "total_cost": round(metrics.get("estimated_cost_usd", 0) or 0, 4),
        "status": status,
        "hypotheses_confirmed": 0,
        "source_dir": source_dir_name,
        "duration_seconds": None,
        "num_turns": metrics.get("items_completed"),
        "score": _load_score(run_dir),
    }


def _codex_msg_to_detail(run_dir, run_id=None):
    lines = _read_jsonl(run_dir / "messages.jsonl")
    metrics = _read_metrics(run_dir)
    arvo_id = _extract_arvo_id(run_dir.name) or run_dir.name
    status = "error" if metrics.get("is_error") else (metrics.get("stop_reason", "completed") or "completed")

    manifest = {
        "run_id": run_id or run_dir.name,
        "target_ref": arvo_id,
        "target_type": "codex",
        "model_name": metrics.get("model", ""),
        "pipeline": "codex",
        "exit_status": status,
        "num_turns": metrics.get("items_completed"),
    }

    messages = _parse_codex_messages(lines)
    traj_summaries = [{
        "agent_name": "codex",
        "exit_status": status,
        "cost": round(metrics.get("estimated_cost_usd", 0) or 0, 4),
        "api_calls": metrics.get("llm_call_number"),
        "path": "messages.jsonl",
        "message_count": len(lines),
    }]
    return {
        "manifest": manifest,
        "index": {"counters": {}},
        "events": [],
        "log": "",
        "artifacts": {cat: [] for cat in ["code_review", "hypotheses", "poc", "validation", "reports"]},
        "hypothesis_outputs": {},
        "trajectory_summaries": traj_summaries,
        "trajectory_only": True,
        "inline_messages": messages,
        "result_text": _read_report_md(run_dir),
    }


def _kiss_yaml_files(run_dir):
    """Return KISSSorcar trajectory yaml files sorted (the last is usually the final session)."""
    traj_dir = run_dir / "trajectories"
    if not traj_dir.is_dir():
        return []
    files = list(traj_dir.glob("*.yaml")) + list(traj_dir.glob("*.yml"))
    return sorted(files)


def _kiss_load_traj(run_dir):
    files = _kiss_yaml_files(run_dir)
    if not files:
        return None
    try:
        import yaml
    except ImportError:
        return None
    try:
        with open(files[-1]) as f:
            return yaml.safe_load(f)
    except Exception:
        return None


def _parse_kiss_messages(traj_data):
    messages = []
    if not isinstance(traj_data, dict):
        return messages
    for m in traj_data.get("messages", []) or []:
        if not isinstance(m, dict):
            continue
        role = (m.get("role") or "").strip()
        if role == "model":
            role = "assistant"
        content = m.get("content", "")
        if isinstance(content, str) and content.strip():
            messages.append({
                "role": role or "user",
                "content": content,
                "timestamp": _ts_to_iso(m.get("timestamp")),
            })
    return messages


def _kiss_to_run_summary(run_id, run_dir, source_dir_name):
    metrics = _read_metrics(run_dir)
    traj = _kiss_load_traj(run_dir) or {}
    model_name = traj.get("model", "") or metrics.get("model", "")
    arvo_id = _extract_arvo_id(run_dir.name) or run_dir.name
    cost = metrics.get("estimated_cost_usd")
    if cost is None:
        cost = traj.get("global_budget_used") or traj.get("budget_used") or 0
    status = "completed" if metrics.get("is_success") else "unknown"

    duration = None
    start = traj.get("run_start_timestamp")
    end = traj.get("run_end_timestamp")
    if start and end:
        try:
            duration = float(end) - float(start)
        except Exception:
            pass

    created = _ts_to_iso(start)
    return {
        "run_id": run_id,
        "target_ref": arvo_id,
        "target_type": "kiss-sorcar",
        "model_name": model_name,
        "pipeline": "kiss-sorcar",
        "created_at": created,
        "counters": {},
        "total_cost": round(float(cost or 0), 4),
        "status": status,
        "hypotheses_confirmed": 0,
        "source_dir": source_dir_name,
        "duration_seconds": duration,
        "num_turns": traj.get("step_count") or metrics.get("llm_call_number"),
        "score": _load_score(run_dir),
    }


def _kiss_to_detail(run_dir, run_id=None):
    traj = _kiss_load_traj(run_dir) or {}
    metrics = _read_metrics(run_dir)
    arvo_id = _extract_arvo_id(run_dir.name) or run_dir.name
    model_name = traj.get("model", "") or metrics.get("model", "")

    start = traj.get("run_start_timestamp")
    end = traj.get("run_end_timestamp")
    duration = None
    if start and end:
        try:
            duration = float(end) - float(start)
        except Exception:
            pass

    status = "completed" if metrics.get("is_success") else "unknown"
    manifest = {
        "run_id": run_id or run_dir.name,
        "target_ref": arvo_id,
        "target_type": "kiss-sorcar",
        "model_name": model_name,
        "pipeline": "kiss-sorcar",
        "exit_status": status,
        "duration_seconds": duration,
        "num_turns": traj.get("step_count"),
        "created_at_utc": _ts_to_iso(start),
        "finished_at_utc": _ts_to_iso(end),
    }

    messages = _parse_kiss_messages(traj)
    cost = metrics.get("estimated_cost_usd")
    if cost is None:
        cost = traj.get("global_budget_used") or traj.get("budget_used") or 0
    traj_summaries = [{
        "agent_name": traj.get("name", "kiss-sorcar"),
        "exit_status": status,
        "cost": round(float(cost or 0), 4),
        "api_calls": metrics.get("llm_call_number"),
        "path": str((_kiss_yaml_files(run_dir) or [run_dir])[-1].name) if _kiss_yaml_files(run_dir) else "",
        "message_count": len(traj.get("messages", []) or []),
    }]

    if not messages and not traj:
        # PyYAML unavailable — leave a hint instead of crashing
        result_text = "PyYAML is not installed on the server; install it to view KISSSorcar trajectories."
    else:
        result_text = _read_report_md(run_dir)

    return {
        "manifest": manifest,
        "index": {"counters": {}},
        "events": [],
        "log": "",
        "artifacts": {cat: [] for cat in ["code_review", "hypotheses", "poc", "validation", "reports"]},
        "hypothesis_outputs": {},
        "trajectory_summaries": traj_summaries,
        "trajectory_only": True,
        "inline_messages": messages,
        "result_text": result_text,
    }


def _load_cve_dataset():
    """Load CVE dataset from scripts/cve_dataset.jsonl into a dict keyed by CVE ID."""
    dataset_path = SCRIPTS_DIR / "cve_dataset.jsonl"
    if not dataset_path.exists():
        return {}
    result = {}
    for line in open(dataset_path):
        line = line.strip()
        if line:
            entry = json.loads(line)
            cve_id = entry.get("cve_id", "")
            if cve_id:
                result[cve_id] = entry
    return result


def _extract_cve_id(run_dir):
    """Extract a CVE ID from the run directory name."""
    name = run_dir.name
    m = re.match(r"(CVE-\d{4}-\d+)", name)
    return m.group(1) if m else None


def _parse_file_scan_locations(run_dir):
    """Extract reported hotspot locations from a file-scan trajectory.json submission."""
    traj_path = run_dir / "trajectory.json"
    if not traj_path.exists():
        return []
    try:
        traj = _read_json(traj_path)
        submission = traj.get("info", {}).get("submission", "")
        if not submission:
            return []
        try:
            import yaml
            parsed = yaml.safe_load(submission)
        except ImportError:
            # Fallback: parse the YAML manually for the payload field
            # The submission has key: value pairs; payload is a JSON string
            parsed = {}
            for line in submission.split("\n"):
                stripped = line.strip()
                if stripped.startswith("payload:"):
                    rest = stripped[len("payload:"):].strip()
                    if rest.startswith('"'):
                        # YAML-quoted string - use json to decode the escape sequences
                        try:
                            parsed["payload"] = json.loads(rest)
                        except json.JSONDecodeError:
                            pass
                    else:
                        parsed["payload"] = rest
                    break
            if "payload" not in parsed:
                return []
        payload_str = parsed.get("payload", "")
        if not payload_str:
            return []
        payload = json.loads(payload_str)
        locations = []
        items = payload if isinstance(payload, list) else [payload]
        for item in items:
            hyp = item.get("hypothesis", {})
            for hs in hyp.get("hotspots", []):
                locations.append({
                    "file_path": hs.get("file_path", ""),
                    "line_start": hs.get("line_start"),
                    "line_end": hs.get("line_end"),
                    "function": hs.get("function", ""),
                    "context": hs.get("context", ""),
                    "source": "file_scan",
                })
        return locations
    except Exception:
        return []


def _parse_claude_code_locations(run_dir):
    """Extract reported vulnerability locations from a Claude Code trajectory.jsonl."""
    traj_path = run_dir / "trajectory.jsonl"
    if not traj_path.exists():
        return []
    locations = []
    seen = set()
    try:
        lines = _read_jsonl(traj_path)
        # Collect all assistant text content
        all_text = []
        for line in lines:
            if line.get("type") != "assistant":
                continue
            msg = line.get("message", {})
            content = msg.get("content", [])
            if isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        all_text.append(part["text"])
            elif isinstance(content, str):
                all_text.append(content)

        full_text = "\n".join(all_text)

        # Pattern 1: **Location:** `file:line` or **Location:** `file:line-line`
        for m in re.finditer(r'\*\*Location:\*\*\s*`([^`]+?):(\d+)(?:-(\d+))?`', full_text):
            fp, ls, le = m.group(1), int(m.group(2)), m.group(3)
            le = int(le) if le else ls
            key = (fp, ls, le)
            if key not in seen:
                seen.add(key)
                locations.append({
                    "file_path": fp,
                    "line_start": ls,
                    "line_end": le,
                    "function": "",
                    "context": "",
                    "source": "claude_code",
                })

        # Pattern 2: file.ext:NNN references (common in code analysis)
        for m in re.finditer(r'(?:^|\s|`)([a-zA-Z0-9_/\-]+\.\w+):(\d+)(?:-(\d+))?', full_text):
            fp, ls, le = m.group(1), int(m.group(2)), m.group(3)
            le = int(le) if le else ls
            # Filter out obvious non-file patterns
            if fp.startswith("http") or fp.startswith("0x"):
                continue
            key = (fp, ls, le)
            if key not in seen:
                seen.add(key)
                locations.append({
                    "file_path": fp,
                    "line_start": ls,
                    "line_end": le,
                    "function": "",
                    "context": "",
                    "source": "claude_code",
                })
    except Exception:
        pass
    return locations


def _parse_report_json_locations(run_dir):
    """Extract hotspot locations from report.json result field (structured JSON in markdown)."""
    report_path = run_dir / "report.json"
    if not report_path.exists():
        return []
    try:
        report = _read_json(report_path)
        result = report.get("result", "")
        if not result:
            return []
        # Extract JSON from ```json ... ``` code blocks
        blocks = re.findall(r'```json\s*\n(.*?)```', result, re.DOTALL)
        locations = []
        for block in blocks:
            try:
                parsed = json.loads(block)
                items = parsed if isinstance(parsed, list) else [parsed]
                for item in items:
                    hyp = item.get("hypothesis", {})
                    for hs in hyp.get("hotspots", []):
                        locations.append({
                            "file_path": hs.get("file_path", ""),
                            "line_start": hs.get("line_start"),
                            "line_end": hs.get("line_end"),
                            "function": hs.get("function", ""),
                            "context": hs.get("context", ""),
                            "source": "claude_code",
                        })
            except (json.JSONDecodeError, AttributeError):
                continue
        return locations
    except Exception:
        return []


def _build_vuln_context(run_dir, cve_dataset):
    """Build the full vulnerability context for a run."""
    cve_id = _extract_cve_id(run_dir)
    if not cve_id:
        return None

    cve_info = cve_dataset.get(cve_id, {})

    # Determine source type and parse locations
    has_traj_json = (run_dir / "trajectory.json").exists()
    has_traj_jsonl = (run_dir / "trajectory.jsonl").exists()
    has_report_json = (run_dir / "report.json").exists()

    locations = []
    if has_traj_json:
        # trajectory.json submission has structured hotspots
        locations = _parse_file_scan_locations(run_dir)
    if not locations and has_report_json:
        # report.json result may have structured JSON with hotspots
        locations = _parse_report_json_locations(run_dir)
    if not locations and has_traj_jsonl:
        # Fall back to regex extraction from trajectory.jsonl
        locations = _parse_claude_code_locations(run_dir)

    # Collect file paths to load: from CVE dataset + from reported locations
    file_paths = set(cve_info.get("files", []))
    for loc in locations:
        if loc.get("file_path"):
            file_paths.add(loc["file_path"])

    # Read source files from scripts/repos/{CVE_ID}/
    repo_dir = SCRIPTS_DIR / "repos" / cve_id
    resolved_repo = repo_dir.resolve()
    source_files = {}

    # Build a reference directory from the CVE dataset files (these have exact paths)
    known_dirs = set()
    for known_fp in cve_info.get("files", []):
        parent = str(Path(known_fp).parent)
        if parent and parent != ".":
            known_dirs.add(parent)

    for fp in sorted(file_paths):
        # Try the file path directly first
        candidate = repo_dir / fp
        if candidate.exists() and candidate.is_file():
            pass  # use it directly
        else:
            # Search recursively for the filename
            fname = Path(fp).name
            matches = list(repo_dir.rglob(fname))
            candidate = None
            if matches:
                # Prefer matches in known directories from the CVE dataset
                for m in matches:
                    rel = str(m.relative_to(resolved_repo))
                    if any(rel.startswith(d + "/") or str(Path(rel).parent) == d for d in known_dirs):
                        candidate = m
                        break
                if not candidate:
                    candidate = matches[0]
        if candidate:
            candidate = candidate.resolve()
            # Safety: must be under repo_dir
            if not str(candidate).startswith(str(resolved_repo)):
                continue
            if candidate.exists() and candidate.is_file():
                try:
                    content = candidate.read_text(errors="replace")
                    rel = str(candidate.relative_to(resolved_repo))
                    source_files[rel] = content
                except Exception:
                    pass

    # Read patch
    patch_content = ""
    patch_path = SCRIPTS_DIR / "patches" / f"{cve_id}.patch"
    if patch_path.exists():
        try:
            patch_content = patch_path.read_text(errors="replace")
        except Exception:
            pass

    return {
        "cve_id": cve_id,
        "cve_info": {
            "description": cve_info.get("description", ""),
            "cwe_ids": cve_info.get("cwe_ids", []),
            "files": cve_info.get("files", []),
            "files_changed": cve_info.get("files_changed"),
            "functions_changed": cve_info.get("functions_changed"),
        },
        "reported_locations": locations,
        "source_files": source_files,
        "patch": patch_content,
    }


def make_handler(output_dirs):
    cve_dataset = _load_cve_dataset()

    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(WEBSITE_DIR), **kwargs)

        def end_headers(self):
            # Disable browser caching so users always see the latest UI without hard-refresh.
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            super().end_headers()

        def log_message(self, fmt, *args):
            pass  # quiet

        def do_GET(self):
            parsed = urlparse(self.path)
            path = parsed.path
            qs = parse_qs(parsed.query)

            if path == "/api/runs":
                self._handle_runs_list()
            elif path.startswith("/api/runs/"):
                parts = path[len("/api/runs/"):].split("/", 1)
                run_id = parts[0]
                rest = parts[1] if len(parts) > 1 else ""
                run_dir = _find_run_dir(run_id, output_dirs)
                if not run_dir:
                    _json_resp(self, {"error": "run not found"}, 404)
                    return
                if rest == "":
                    self._handle_run_detail(run_dir, run_id=run_id)
                elif rest.startswith("stage/"):
                    stage_key = rest[len("stage/"):]
                    qs = parse_qs(parsed.query)
                    offset = int(qs.get("offset", ["0"])[0])
                    limit_raw = qs.get("limit", [None])[0]
                    limit = int(limit_raw) if limit_raw else None
                    stage = _revelio_get_stage(run_dir, stage_key, offset=offset, limit=limit)
                    if stage is None:
                        _json_resp(self, {"error": "stage not found"}, 404)
                    else:
                        _json_resp(self, stage)
                elif rest == "events":
                    self._handle_events(run_dir)
                elif rest == "log":
                    self._handle_log(run_dir)
                elif rest.startswith("artifact/"):
                    rel = rest[len("artifact/"):]
                    self._handle_artifact(run_dir, rel)
                elif rest == "vuln_context":
                    self._handle_vuln_context(run_dir)
                elif rest.startswith("file/"):
                    rel = rest[len("file/"):]
                    self._handle_file(run_dir, rel)
                else:
                    _json_resp(self, {"error": "unknown endpoint"}, 404)
            else:
                # Static files
                if path == "/":
                    self.path = "/index.html"
                super().do_GET()

        def _handle_runs_list(self):
            runs = []
            for run_dir, out_dir in _find_all_run_dirs(output_dirs):
                run_id = _run_dir_to_id(run_dir, out_dir)
                fmt = _detect_traj_format(run_dir)
                manifest_path = run_dir / "manifest.json"

                if fmt == "cc_messages":
                    try:
                        s = _cc_msg_to_run_summary(run_id, run_dir, str(out_dir.name))
                        if s: runs.append(s)
                    except Exception:
                        pass
                    continue

                if fmt == "codex_messages":
                    try:
                        s = _codex_msg_to_run_summary(run_id, run_dir, str(out_dir.name))
                        if s: runs.append(s)
                    except Exception:
                        pass
                    continue

                if fmt == "kiss_yaml":
                    try:
                        s = _kiss_to_run_summary(run_id, run_dir, str(out_dir.name))
                        if s: runs.append(s)
                    except Exception:
                        pass
                    continue

                if fmt == "cc_traj_jsonl":
                    try:
                        s = _cc_traj_to_run_summary(run_id, run_dir, str(out_dir.name))
                        if s: runs.append(s)
                    except Exception:
                        pass
                    continue

                if fmt == "revelio_traj":
                    try:
                        traj = _read_json(run_dir / "trajectory.json")
                        runs.append(_traj_to_run_summary(run_id, traj.get("info", {}), str(out_dir.name), run_dir=run_dir))
                    except Exception:
                        pass
                    continue

                # Revelio scan_filter_detect: manifest + hypotheses.json (trajectory.json optional)
                if fmt == "manifest" and (run_dir / "hypotheses.json").exists():
                    fmt = "revelio_detect"
                    # fall through to the manifest branch below — it computes summary fine

                if manifest_path.exists():
                    manifest = _read_json(manifest_path)
                    index_path = run_dir / "index.json"
                    counters = {}
                    if index_path.exists():
                        idx = _read_json(index_path)
                        counters = idx.get("counters", {})
                    # parse log for cost info
                    total_cost = 0.0
                    log_path = run_dir / "log.txt"
                    if log_path.exists():
                        with open(log_path) as f:
                            for line in f:
                                if "cost=$" in line:
                                    try:
                                        c = line.split("cost=$")[1].split(")")[0]
                                        total_cost += float(c)
                                    except (ValueError, IndexError):
                                        pass
                    # check success from events
                    events_path = run_dir / "events.jsonl"
                    status = "unknown"
                    hypotheses_confirmed = 0
                    if events_path.exists():
                        events = _read_jsonl(events_path)
                        for ev in events:
                            if ev.get("event") == "run_success_all":
                                status = "success"
                                hypotheses_confirmed = ev.get("payload", {}).get("count", 0)
                        if status == "unknown":
                            for ev in events:
                                if ev.get("event") == "run_success":
                                    status = "partial"
                                    hypotheses_confirmed += 1
                    runs.append({
                        "run_id": run_id,
                        "target_ref": manifest.get("target_ref"),
                        "target_type": manifest.get("target_type"),
                        "model_name": manifest.get("model_name"),
                        "filter_model": manifest.get("filter_model"),
                        "poc_model": manifest.get("poc_model"),
                        "pipeline": manifest.get("pipeline"),
                        "created_at": manifest.get("created_at_utc"),
                        "counters": counters,
                        "total_cost": round(total_cost, 4),
                        "status": status,
                        "hypotheses_confirmed": hypotheses_confirmed,
                        "source_dir": str(out_dir.name),
                        "score": _load_score(run_dir),
                    })
            # Group runs that share an arvo/CVE case across agents.
            def _case_key(r):
                tref = r.get("target_ref") or ""
                rid = r.get("run_id") or ""
                m = re.search(r"arvo[-:](\d+)", tref) or re.search(r"arvo[-:](\d+)", rid)
                if m:
                    return f"arvo-{int(m.group(1)):08d}"
                m = re.search(r"(CVE-\d{4}-\d+)", tref) or re.search(r"(CVE-\d{4}-\d+)", rid)
                if m:
                    return m.group(1)
                return tref
            runs.sort(key=lambda r: r.get("created_at") or "", reverse=True)
            runs.sort(key=lambda r: (_case_key(r), r.get("source_dir") or ""))
            _json_resp(self, runs)

        def _handle_run_detail(self, run_dir, run_id=None):
            fmt = _detect_traj_format(run_dir)
            # Revelio scan_filter_detect runs: manifest + hypotheses.json (trajectory.json optional)
            if fmt == "manifest" and (run_dir / "hypotheses.json").exists():
                _json_resp(self, _revelio_to_detail(run_dir, run_id=run_id, include_messages=False))
                return
            if fmt == "cc_messages":
                _json_resp(self, _cc_msg_to_detail(run_dir, run_id=run_id))
                return
            if fmt == "codex_messages":
                _json_resp(self, _codex_msg_to_detail(run_dir, run_id=run_id))
                return
            if fmt == "kiss_yaml":
                _json_resp(self, _kiss_to_detail(run_dir, run_id=run_id))
                return
            if fmt == "cc_traj_jsonl":
                _json_resp(self, _cc_traj_to_detail(run_dir, run_id=run_id))
                return
            if fmt == "revelio_traj":
                _json_resp(self, _traj_to_detail(run_dir, run_id=run_id))
                return

            manifest = _read_json(run_dir / "manifest.json")
            index = {}
            if (run_dir / "index.json").exists():
                index = _read_json(run_dir / "index.json")
            events = []
            if (run_dir / "events.jsonl").exists():
                events = _read_jsonl(run_dir / "events.jsonl")
            log_text = ""
            if (run_dir / "log.txt").exists():
                log_text = (run_dir / "log.txt").read_text()

            # Load all key artifacts inline
            artifacts = {}
            for category in ["code_review", "hypotheses", "poc", "validation", "reports"]:
                artifacts[category] = []
                for entry in index.get("artifacts", {}).get(category, []):
                    art_path = run_dir / entry.get("path", "")
                    if art_path.exists() and art_path.suffix == ".json":
                        try:
                            artifacts[category].append(_read_json(art_path))
                        except Exception:
                            artifacts[category].append({"error": "failed to read", "path": str(entry.get("path"))})
                    else:
                        artifacts[category].append({"meta": entry.get("meta", {}), "path": entry.get("path")})

            # hypothesis output dirs
            hyp_outputs = {}
            for d in sorted(run_dir.iterdir()):
                if d.is_dir() and d.name.startswith("hypothesis_"):
                    hid = d.name.replace("hypothesis_", "")
                    files = {}
                    for f in sorted(d.iterdir()):
                        if f.suffix == ".md":
                            files["report_md"] = f.read_text()
                        elif f.suffix == ".py":
                            files["script_py"] = f.read_text()
                        elif f.name.startswith("poc_"):
                            # Binary — show hex
                            raw = f.read_bytes()
                            files["poc_hex"] = raw.hex()
                            files["poc_size"] = len(raw)
                            # Try to show printable portion
                            try:
                                files["poc_ascii"] = raw.decode("ascii", errors="replace")
                            except Exception:
                                pass
                    hyp_outputs[hid] = files

            # Trajectory summaries (not full messages — too large)
            traj_summaries = []
            seen_agents = set()
            for entry in index.get("artifacts", {}).get("trajectories", []):
                agent_name = entry.get("meta", {}).get("agent_name", "unknown")
                if agent_name in seen_agents:
                    continue
                seen_agents.add(agent_name)
                art_path = run_dir / entry.get("path", "")
                if art_path.exists():
                    try:
                        traj = _read_json(art_path)
                        info = traj.get("data", {}).get("info", {})
                        traj_summaries.append({
                            "agent_name": agent_name,
                            "exit_status": info.get("exit_status"),
                            "cost": info.get("model_stats", {}).get("instance_cost"),
                            "api_calls": info.get("model_stats", {}).get("api_calls"),
                            "path": entry.get("path"),
                            "message_count": len(traj.get("data", {}).get("messages", [])),
                        })
                    except Exception:
                        traj_summaries.append({"agent_name": agent_name, "path": entry.get("path"), "error": "parse failed"})

            _json_resp(self, {
                "manifest": manifest,
                "index": index,
                "events": events,
                "log": log_text,
                "artifacts": artifacts,
                "hypothesis_outputs": hyp_outputs,
                "trajectory_summaries": traj_summaries,
            })

        def _handle_events(self, run_dir):
            path = run_dir / "events.jsonl"
            if path.exists():
                _json_resp(self, _read_jsonl(path))
            else:
                _json_resp(self, [])

        def _handle_log(self, run_dir):
            path = run_dir / "log.txt"
            if path.exists():
                _text_resp(self, path.read_text())
            else:
                _text_resp(self, "", 404)

        def _handle_artifact(self, run_dir, rel_path):
            # Prevent path traversal
            safe = (run_dir / rel_path).resolve()
            if not str(safe).startswith(str(run_dir)):
                _json_resp(self, {"error": "forbidden"}, 403)
                return
            if safe.exists() and safe.suffix == ".json":
                _json_resp(self, _read_json(safe))
            elif safe.exists():
                _text_resp(self, safe.read_text(errors="replace"))
            else:
                _json_resp(self, {"error": "not found"}, 404)

        def _handle_file(self, run_dir, rel_path):
            safe = (run_dir / rel_path).resolve()
            if not str(safe).startswith(str(run_dir)):
                _json_resp(self, {"error": "forbidden"}, 403)
                return
            if safe.exists():
                ct = mimetypes.guess_type(str(safe))[0] or "text/plain"
                _text_resp(self, safe.read_bytes(), content_type=ct)
            else:
                _text_resp(self, "not found", 404)

        def _handle_vuln_context(self, run_dir):
            ctx = _build_vuln_context(run_dir, cve_dataset)
            if ctx is None:
                _json_resp(self, {"error": "no CVE context available"}, 404)
            else:
                _json_resp(self, ctx)

    return Handler


def main():
    parser = argparse.ArgumentParser(description="Revelio Trace Viewer")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1 for security)")
    parser.add_argument("--port", type=int, default=8877, help="Port number (default: 8877)")
    parser.add_argument("--output-dir", nargs="*", help="Output directories to scan")
    args = parser.parse_args()

    if args.output_dir:
        output_dirs = [Path(d).resolve() for d in args.output_dir]
    else:
        output_dirs = [d for d in DEFAULT_OUTPUT_DIRS if d.exists()]

    host = args.host
    print(f"Revelio Trace Viewer")
    print(f"  Scanning: {[str(d) for d in output_dirs]}")
    print(f"  Serving:  http://{host}:{args.port}")
    if host == "127.0.0.1":
        print(f"  Use SSH tunnel: ssh -L {args.port}:127.0.0.1:{args.port} <server>")
    print()

    server = HTTPServer((host, args.port), make_handler(output_dirs))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()


if __name__ == "__main__":
    main()

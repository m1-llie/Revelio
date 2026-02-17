#!/usr/bin/env python3
"""
VulAgent Trace Viewer — lightweight server.

Usage:
    python server.py [--port PORT] [--output-dir DIR ...]

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
SCRIPTS_DIR = WEBSITE_DIR.parent / "scripts"
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
    """A run directory has manifest.json, trajectory.json, or trajectory.jsonl."""
    return path.is_dir() and (
        (path / "manifest.json").exists()
        or (path / "trajectory.json").exists()
        or (path / "trajectory.jsonl").exists()
    )


def _run_dir_to_id(run_dir, output_dir):
    """Convert a run directory path to a URL-safe run ID using '--' as separator."""
    rel = run_dir.relative_to(output_dir)
    return str(rel).replace(os.sep, "--")


def _find_all_run_dirs(output_dirs):
    """Recursively find all directories containing trajectory.json, trajectory.jsonl, or manifest.json."""
    results = []  # list of (run_dir, output_dir)
    for d in output_dirs:
        if not d.exists():
            continue
        seen = set()
        for pattern in ("trajectory.json", "manifest.json", "trajectory.jsonl"):
            for match in d.rglob(pattern):
                run_dir = match.parent
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
                manifest_path = run_dir / "manifest.json"
                traj_path = run_dir / "trajectory.json"
                cc_traj_path = run_dir / "trajectory.jsonl"

                # Claude Code trajectory.jsonl run
                if not manifest_path.exists() and not traj_path.exists() and cc_traj_path.exists():
                    try:
                        summary = _cc_traj_to_run_summary(run_id, run_dir, str(out_dir.name))
                        if summary:
                            runs.append(summary)
                    except Exception:
                        pass
                    continue

                # Trajectory-only run (no manifest)
                if not manifest_path.exists() and traj_path.exists():
                    try:
                        traj = _read_json(traj_path)
                        traj_info = traj.get("info", {})
                        runs.append(_traj_to_run_summary(run_id, traj_info, str(out_dir.name), run_dir=run_dir))
                    except Exception:
                        pass
                    continue

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
                        "pipeline": manifest.get("pipeline"),
                        "created_at": manifest.get("created_at_utc"),
                        "counters": counters,
                        "total_cost": round(total_cost, 4),
                        "status": status,
                        "hypotheses_confirmed": hypotheses_confirmed,
                        "source_dir": str(out_dir.name),
                        "score": _load_score(run_dir),
                    })
            runs.sort(key=lambda r: r.get("created_at") or "", reverse=True)
            _json_resp(self, runs)

        def _handle_run_detail(self, run_dir, run_id=None):
            # Claude Code trajectory.jsonl run
            if not (run_dir / "manifest.json").exists() and not (run_dir / "trajectory.json").exists() and (run_dir / "trajectory.jsonl").exists():
                _json_resp(self, _cc_traj_to_detail(run_dir, run_id=run_id))
                return
            # Trajectory-only run (no manifest)
            if not (run_dir / "manifest.json").exists() and (run_dir / "trajectory.json").exists():
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
    parser = argparse.ArgumentParser(description="VulAgent Trace Viewer")
    parser.add_argument("--port", type=int, default=8877)
    parser.add_argument("--output-dir", nargs="*", help="Output directories to scan")
    args = parser.parse_args()

    if args.output_dir:
        output_dirs = [Path(d).resolve() for d in args.output_dir]
    else:
        output_dirs = [d for d in DEFAULT_OUTPUT_DIRS if d.exists()]

    print(f"VulAgent Trace Viewer")
    print(f"  Scanning: {[str(d) for d in output_dirs]}")
    print(f"  Serving:  http://0.0.0.0:{args.port}")
    print()

    server = HTTPServer(("0.0.0.0", args.port), make_handler(output_dirs))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()


if __name__ == "__main__":
    main()

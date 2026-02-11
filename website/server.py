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
import mimetypes
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs

WEBSITE_DIR = Path(__file__).resolve().parent
DEFAULT_OUTPUT_DIRS = [
    WEBSITE_DIR.parent / "output",
    WEBSITE_DIR.parent / "output_old",
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


def _find_run_dir(run_id, output_dirs):
    for d in output_dirs:
        candidate = d / run_id
        if candidate.is_dir() and (candidate / "manifest.json").exists():
            return candidate
    return None


def make_handler(output_dirs):

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
                    self._handle_run_detail(run_dir)
                elif rest == "events":
                    self._handle_events(run_dir)
                elif rest == "log":
                    self._handle_log(run_dir)
                elif rest.startswith("artifact/"):
                    rel = rest[len("artifact/"):]
                    self._handle_artifact(run_dir, rel)
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
            for d in output_dirs:
                if not d.exists():
                    continue
                for entry in sorted(d.iterdir()):
                    manifest_path = entry / "manifest.json"
                    if entry.is_dir() and manifest_path.exists():
                        manifest = _read_json(manifest_path)
                        index_path = entry / "index.json"
                        counters = {}
                        if index_path.exists():
                            idx = _read_json(index_path)
                            counters = idx.get("counters", {})
                        # parse log for cost info
                        total_cost = 0.0
                        log_path = entry / "log.txt"
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
                        events_path = entry / "events.jsonl"
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
                            "run_id": manifest.get("run_id", entry.name),
                            "target_ref": manifest.get("target_ref"),
                            "target_type": manifest.get("target_type"),
                            "model_name": manifest.get("model_name"),
                            "pipeline": manifest.get("pipeline"),
                            "created_at": manifest.get("created_at_utc"),
                            "counters": counters,
                            "total_cost": round(total_cost, 4),
                            "status": status,
                            "hypotheses_confirmed": hypotheses_confirmed,
                            "source_dir": str(d.name),
                        })
            runs.sort(key=lambda r: r.get("created_at", ""), reverse=True)
            _json_resp(self, runs)

        def _handle_run_detail(self, run_dir):
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

#!/usr/bin/env python3
"""
VulAgent Scan & Filter Viewer — lightweight server.

Usage:
    python server.py [--host HOST] [--port PORT] [--output-dir DIR]

Options:
    --host HOST     Host to bind (default: 127.0.0.1)
    --port PORT     Port number (default: 8877)
    --output-dir    Root output directory (default: ../output)

Serves the static frontend and a JSON API for scan_and_filter results.
No external dependencies — stdlib only.
"""

import argparse
import json
import os
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse

WEBSITE_DIR = Path(__file__).resolve().parent
DEFAULT_OUTPUT_DIR = WEBSITE_DIR.parent / "output"


def _json_resp(handler, data, status=200):
    body = json.dumps(data, default=str).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.end_headers()
    handler.wfile.write(body)


def _read_json(path):
    with open(path) as f:
        return json.load(f)


def _find_runs(output_dir):
    """Find all scan_and_filter run directories."""
    saf_dir = output_dir / "scan_and_filter"
    if not saf_dir.exists():
        return []
    runs = []
    for d in sorted(saf_dir.iterdir(), reverse=True):
        if d.is_dir() and (d / "summary.json").exists():
            runs.append(d)
    return runs


def _list_hypotheses(run_dir, category):
    """List hypotheses in valid_hypotheses or invalid_hypotheses."""
    hyp_dir = run_dir / category
    if not hyp_dir.exists():
        return []
    results = []
    for d in sorted(hyp_dir.iterdir()):
        if not d.is_dir():
            continue
        h_path = d / "hypothesis.json"
        if not h_path.exists():
            continue
        try:
            data = _read_json(h_path)
            data["_dir_name"] = d.name
            data["_has_trajectory"] = (d / "filter_trajectory.json").exists()
            results.append(data)
        except Exception:
            continue
    return results


class Handler(SimpleHTTPRequestHandler):
    output_dir = DEFAULT_OUTPUT_DIR

    def log_message(self, fmt, *args):
        pass  # quiet

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        # API routes
        if path == "/api/runs":
            return self._api_runs()
        if path.startswith("/api/run/"):
            return self._api_run(path[len("/api/run/"):])

        # Serve index.html for root
        if path in ("", "/"):
            return self._serve_file(WEBSITE_DIR / "index.html", "text/html")

        # Static files
        local = WEBSITE_DIR / path.lstrip("/")
        if local.exists() and local.is_file():
            import mimetypes
            ct = mimetypes.guess_type(str(local))[0] or "application/octet-stream"
            return self._serve_file(local, ct)

        self.send_error(404)

    def _serve_file(self, fpath, content_type):
        data = fpath.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _api_runs(self):
        runs = _find_runs(self.output_dir)
        result = []
        for r in runs:
            try:
                summary = _read_json(r / "summary.json")
                info = summary.get("info", {})
                result.append({
                    "id": r.name,
                    "file_path": info.get("file_path", ""),
                    "model": info.get("model", ""),
                    "started_at": info.get("started_at_utc", ""),
                    "duration_seconds": info.get("duration_seconds", 0),
                    "functions_found": info.get("functions_found", 0),
                    "functions_analyzed": info.get("functions_analyzed", 0),
                    "raw_hypotheses": info.get("raw_hypothesis_count", 0),
                    "deduped_hypotheses": info.get("deduped_hypothesis_count", 0),
                    "final_hypotheses": info.get("final_hypothesis_count", 0),
                    "valid_count": len(summary.get("valid_hypotheses", [])),
                    "invalid_count": summary.get("invalid_hypothesis_count", 0),
                })
            except Exception:
                continue
        _json_resp(self, result)

    def _api_run(self, rest):
        """Route: /api/run/<run_id>[/...]"""
        parts = rest.split("/")
        run_id = parts[0]
        run_dir = self.output_dir / "scan_and_filter" / run_id

        if not run_dir.exists() or not (run_dir / "summary.json").exists():
            return _json_resp(self, {"error": "Run not found"}, 404)

        # /api/run/<id> — full summary
        if len(parts) == 1:
            summary = _read_json(run_dir / "summary.json")
            return _json_resp(self, summary)

        # /api/run/<id>/valid
        if len(parts) == 2 and parts[1] == "valid":
            return _json_resp(self, _list_hypotheses(run_dir, "valid_hypotheses"))

        # /api/run/<id>/invalid
        if len(parts) == 2 and parts[1] == "invalid":
            return _json_resp(self, _list_hypotheses(run_dir, "invalid_hypotheses"))

        # /api/run/<id>/hypothesis/<category>/<dir_name>
        if len(parts) >= 4 and parts[1] == "hypothesis":
            category = parts[2]  # "valid" or "invalid"
            dir_name = "/".join(parts[3:])
            folder = "valid_hypotheses" if category == "valid" else "invalid_hypotheses"
            hyp_dir = run_dir / folder / dir_name

            if not hyp_dir.exists():
                return _json_resp(self, {"error": "Hypothesis not found"}, 404)

            h_path = hyp_dir / "hypothesis.json"
            if not h_path.exists():
                return _json_resp(self, {"error": "hypothesis.json not found"}, 404)

            data = _read_json(h_path)
            data["_dir_name"] = dir_name
            data["_has_trajectory"] = (hyp_dir / "filter_trajectory.json").exists()
            return _json_resp(self, data)

        # /api/run/<id>/trajectory/<category>/<dir_name>
        if len(parts) >= 4 and parts[1] == "trajectory":
            category = parts[2]
            dir_name = "/".join(parts[3:])
            folder = "valid_hypotheses" if category == "valid" else "invalid_hypotheses"
            traj_path = run_dir / folder / dir_name / "filter_trajectory.json"

            if not traj_path.exists():
                return _json_resp(self, {"error": "Trajectory not found"}, 404)

            return _json_resp(self, _read_json(traj_path))

        _json_resp(self, {"error": "Unknown route"}, 404)


def main():
    parser = argparse.ArgumentParser(description="VulAgent Scan & Filter Viewer")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8877)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()

    Handler.output_dir = args.output_dir.resolve()

    server = HTTPServer((args.host, args.port), Handler)
    print(f"Serving on http://{args.host}:{args.port}")
    print(f"Output dir: {Handler.output_dir}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()


if __name__ == "__main__":
    main()

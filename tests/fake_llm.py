"""A tiny fake Ollama server for tests: no model needed.

It "finds" an issue on any added line containing the word `danger(` and
otherwise returns no findings - enough to exercise the full pipeline.
"""

from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence
        pass

    def _send(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/api/tags":
            self._send({"models": [{"name": "fake-model:latest"}]})
        else:
            self._send({"error": "not found"}, 404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        req = json.loads(self.rfile.read(length) or b"{}")
        self.server.requests.append(req)
        if req.get("model") == "missing-model":  # mimic Ollama when a model isn't pulled
            self._send({"error": "model 'missing-model' not found"}, 404)
            return
        user = req["messages"][-1]["content"]
        findings = []
        for m in re.finditer(r"^\s*(\d+) \+ .*danger\(", user, re.M):
            findings.append({
                "line": int(m.group(1)), "severity": "high", "category": "injection",
                "message": "danger() called with user input", "suggestion": "validate input",
            })
        if "hallucinate" in user:
            findings.append({"line": 9999, "severity": "critical", "category": "secret",
                             "message": "made up", "suggestion": ""})
        self._send({"message": {"role": "assistant", "content": json.dumps({"findings": findings})},
                    "prompt_eval_count": 120, "eval_count": 8, "load_duration": 0,
                    "prompt_eval_duration": 200_000_000, "eval_duration": 100_000_000})


class FakeOllama:
    def __init__(self):
        self.server = HTTPServer(("127.0.0.1", 0), _Handler)
        self.server.requests = []
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"

    @property
    def requests(self):
        return self.server.requests

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()

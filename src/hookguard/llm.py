"""Minimal, dependency-free clients for local LLM servers.

Supported:
  * Ollama      - native /api/chat endpoint (default http://127.0.0.1:11434)
  * llama.cpp   - llama-server's OpenAI-compatible /v1/chat/completions (default http://127.0.0.1:8080)

Both are asked for JSON constrained by a schema, so even small models return
parseable output most of the time. Requests never go through HTTP proxies:
the model runs on this machine and code must not leave it.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

FINDINGS_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "line": {"type": "integer"},
                    "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                    "category": {"type": "string"},
                    "message": {"type": "string"},
                    "suggestion": {"type": "string"},
                },
                "required": ["line", "severity", "category", "message"],
            },
        }
    },
    "required": ["findings"],
}

# Direct connections only, ignoring HTTP(S)_PROXY env vars.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class LLMError(RuntimeError):
    pass


def _request(url: str, payload: Optional[dict], timeout: float) -> dict:
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        url, data=data, method="POST" if data else "GET",
        headers={"Content-Type": "application/json"},
    )
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")[:300]
        raise LLMError(f"HTTP {exc.code} from {url}: {body}") from exc
    except (urllib.error.URLError, ConnectionError, TimeoutError, OSError) as exc:
        raise LLMError(f"cannot reach {url}: {getattr(exc, 'reason', exc)}") from exc
    except json.JSONDecodeError as exc:
        raise LLMError(f"invalid JSON from {url}") from exc


class Backend:
    name = "base"
    default_host = ""

    def __init__(self, model: str, host: str = "", timeout: float = 60,
                 temperature: float = 0.0, num_ctx: int = 8192, think: Optional[bool] = None):
        self.model = model
        self.host = (host or self.default_host).rstrip("/")
        self.timeout = timeout
        self.temperature = temperature
        self.num_ctx = num_ctx
        # Reasoning models (e.g. qwen3) "think" before answering unless told not to.
        # None = don't send the option (models without a thinking mode).
        self.think = think

    def chat(self, system: str, user: str) -> str:  # pragma: no cover - interface
        raise NotImplementedError

    def health(self) -> Tuple[bool, str]:  # pragma: no cover - interface
        raise NotImplementedError


class OllamaBackend(Backend):
    name = "ollama"
    default_host = "http://127.0.0.1:11434"

    def chat(self, system: str, user: str) -> str:
        payload = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "stream": False,
            "format": FINDINGS_SCHEMA,
            "keep_alive": "10m",  # keep the model warm between commits
            "options": {"temperature": self.temperature, "num_ctx": self.num_ctx, "seed": 7},
        }
        if self.think is not None:
            payload["think"] = bool(self.think)
        resp = _request(f"{self.host}/api/chat", payload, self.timeout)
        try:
            return resp["message"]["content"]
        except (KeyError, TypeError) as exc:
            raise LLMError(f"unexpected Ollama response: {str(resp)[:200]}") from exc

    def list_models(self) -> List[str]:
        resp = _request(f"{self.host}/api/tags", None, 5)
        return [m.get("name", "") for m in resp.get("models", [])]

    def health(self) -> Tuple[bool, str]:
        try:
            models = self.list_models()
        except LLMError as exc:
            return False, f"Ollama not reachable at {self.host} ({exc}). Start it with `ollama serve`."
        wanted = self.model if ":" in self.model else self.model + ":latest"
        if wanted not in models and self.model not in models:
            return False, (f"Ollama is running but model '{self.model}' is not pulled. "
                           f"Run: ollama pull {self.model}")
        return True, f"Ollama OK at {self.host}, model '{self.model}' available"


class LlamaCppBackend(Backend):
    name = "llamacpp"
    default_host = "http://127.0.0.1:8080"

    def chat(self, system: str, user: str) -> str:
        payload = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "temperature": self.temperature,
            "seed": 7,
            "response_format": {"type": "json_schema", "json_schema": {"name": "findings", "schema": FINDINGS_SCHEMA}},
        }
        resp = _request(f"{self.host}/v1/chat/completions", payload, self.timeout)
        try:
            return resp["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"unexpected llama-server response: {str(resp)[:200]}") from exc

    def health(self) -> Tuple[bool, str]:
        try:
            resp = _request(f"{self.host}/health", None, 5)
        except LLMError as exc:
            return False, (f"llama-server not reachable at {self.host} ({exc}). "
                           "Start it with: llama-server -m <model.gguf> --port 8080")
        status = resp.get("status", "ok") if isinstance(resp, dict) else "ok"
        if status != "ok":
            return False, f"llama-server at {self.host} reports status '{status}'"
        return True, f"llama-server OK at {self.host}"


BACKENDS = {"ollama": OllamaBackend, "llamacpp": LlamaCppBackend, "llama.cpp": LlamaCppBackend}


def make_backend(llm_cfg: Dict[str, Any]) -> Backend:
    name = str(llm_cfg.get("backend", "ollama")).lower()
    if name not in BACKENDS:
        raise LLMError(f"unknown LLM backend '{name}' (use 'ollama' or 'llamacpp')")
    return BACKENDS[name](
        model=llm_cfg.get("model", ""),
        host=llm_cfg.get("host", ""),
        timeout=float(llm_cfg.get("timeout", 60)),
        temperature=float(llm_cfg.get("temperature", 0.0)),
        num_ctx=int(llm_cfg.get("num_ctx", 8192)),
        think=_parse_think(llm_cfg.get("think")),
    )


def _parse_think(value: Any) -> Optional[bool]:
    """Config value -> True/False/None. "" or "auto" means: don't send the option."""
    if value is None or (isinstance(value, str) and value.strip().lower() in ("", "auto")):
        return None
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


def timed_chat(backend: Backend, system: str, user: str) -> Tuple[str, float]:
    start = time.monotonic()
    out = backend.chat(system, user)
    return out, time.monotonic() - start

"""LLM review stage: chunk the diff, ask the local model, validate what comes back."""

from __future__ import annotations

import hashlib
import json
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from hookguard.llm import Backend, LLMError
from hookguard.models import FileChange, Finding, Severity
from hookguard.prompts import PROMPT_VERSION, SYSTEM_PROMPT, build_user_prompt
from hookguard.secrets import redact_line

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_KNOWN_CATEGORIES = {
    "secret", "injection", "unsafe-deserialization", "auth", "crypto",
    "path-traversal", "ssrf", "dangerous-bug",
}
LINE_SNAP_DISTANCE = 2  # tolerate small off-by-N line numbers from the model


@dataclass
class ReviewStats:
    chunks: int = 0
    cached: int = 0
    llm_calls: int = 0
    seconds: float = 0.0
    dropped_invalid: int = 0   # findings pointing at lines that were not added (hallucinations)
    skipped_budget: int = 0    # chunks skipped because the total time budget ran out


@dataclass
class ReviewResult:
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    stats: ReviewStats = field(default_factory=ReviewStats)


def render_patch(change: FileChange) -> List[str]:
    """Turn a unified diff into numbered lines the model can cite, with secrets masked."""
    rendered: List[str] = []
    new_no = 0
    in_hunk = False
    for raw in change.patch.splitlines():
        m = _HUNK_RE.match(raw)
        if m:
            in_hunk = True
            new_no = int(m.group(1))
            if rendered:
                rendered.append("     ...")
            continue
        if not in_hunk or not raw:
            continue
        tag, text = raw[0], redact_line(raw[1:])
        if tag == "+":
            rendered.append(f"{new_no:>5} + {text}")
            new_no += 1
        elif tag == " ":
            rendered.append(f"{new_no:>5}   {text}")
            new_no += 1
        elif tag == "-":
            rendered.append(f"{'':>5} - {text}")
    return rendered


def chunk_lines(lines: List[str], max_chars: int) -> List[str]:
    chunks: List[str] = []
    buf: List[str] = []
    size = 0
    for line in lines:
        if buf and size + len(line) + 1 > max_chars:
            chunks.append("\n".join(buf))
            buf, size = [], 0
        buf.append(line[:max_chars])
        size += len(line) + 1
    if buf:
        chunks.append("\n".join(buf))
    # Only chunks that contain added code are worth a model call.
    return [c for c in chunks if re.search(r"^\s*\d+ \+ ", c, re.M)]


def parse_model_json(text: str) -> List[Dict[str, Any]]:
    """Parse the model's reply defensively; small models sometimes wrap JSON in prose."""
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?|```$", "", text).strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}|\[.*\]", text, re.S)
        if not m:
            raise LLMError(f"model did not return JSON: {text[:120]!r}")
        try:
            data = json.loads(m.group(0))
        except json.JSONDecodeError as exc:
            raise LLMError(f"model returned malformed JSON: {text[:120]!r}") from exc
    if isinstance(data, dict):
        data = data.get("findings", [])
    if not isinstance(data, list):
        return []
    return [d for d in data if isinstance(d, dict)]


class _Cache:
    def __init__(self, path: Optional[Path], max_entries: int = 1000):
        self.path = path
        self.max_entries = max_entries
        self.data: Dict[str, Any] = {}
        if path and path.is_file():
            try:
                self.data = json.loads(path.read_text("utf-8"))
            except (OSError, json.JSONDecodeError):
                self.data = {}

    def get(self, key: str):
        return self.data.get(key)

    def put(self, key: str, value) -> None:
        self.data[key] = value
        if len(self.data) > self.max_entries:
            for k in list(self.data)[: len(self.data) - self.max_entries]:
                del self.data[k]

    def save(self) -> None:
        if not self.path:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self.data), "utf-8")
        except OSError:
            pass


class LLMReviewer:
    def __init__(self, backend: Backend, llm_cfg: Dict[str, Any], cache_path: Optional[Path] = None,
                 progress: bool = True):
        self.backend = backend
        self.cfg = llm_cfg
        self.min_severity = Severity.parse(llm_cfg.get("min_severity", "medium"), Severity.MEDIUM)
        self.max_chars = int(llm_cfg.get("max_chunk_chars", 6000))
        self.total_timeout = float(llm_cfg.get("total_timeout", 120))
        self.cache = _Cache(cache_path if llm_cfg.get("cache", True) else None)
        self.progress = progress

    def _log(self, msg: str) -> None:
        if self.progress:
            print(msg, file=sys.stderr, flush=True)

    def _key(self, prompt: str) -> str:
        h = hashlib.sha256()
        for part in (PROMPT_VERSION, self.backend.name, self.backend.model, prompt):
            h.update(part.encode("utf-8"))
            h.update(b"\0")
        return h.hexdigest()

    def _validate(self, raw: Dict[str, Any], change: FileChange, stats: ReviewStats) -> Optional[Finding]:
        added = change.added_linenos()
        try:
            line = int(raw.get("line"))
        except (TypeError, ValueError):
            stats.dropped_invalid += 1
            return None
        if line not in added:
            near = [n for n in added if abs(n - line) <= LINE_SNAP_DISTANCE]
            if not near:
                stats.dropped_invalid += 1
                return None
            line = min(near, key=lambda n: abs(n - line))
        sev = Severity.parse(raw.get("severity", "medium"), Severity.MEDIUM)
        if sev < self.min_severity:
            return None
        category = str(raw.get("category", "other")).strip().lower().replace(" ", "-") or "other"
        if category not in _KNOWN_CATEGORIES:
            category = "other"
        message = str(raw.get("message", "")).strip()
        if not message:
            stats.dropped_invalid += 1
            return None
        code = next((a.text for a in change.added if a.lineno == line), "")
        return Finding(
            file=change.path, line=line, severity=sev, category=category, rule="llm",
            message=message[:300], source="llm",
            suggestion=str(raw.get("suggestion", "")).strip()[:300],
            snippet=redact_line(code.strip())[:160],
        )

    def review(self, changes: List[FileChange]) -> ReviewResult:
        result = ReviewResult()
        stats = result.stats
        start = time.monotonic()
        for change in changes:
            for body in chunk_lines(render_patch(change), self.max_chars):
                stats.chunks += 1
                prompt = build_user_prompt(change.path, body)
                key = self._key(prompt)
                raw_items = self.cache.get(key)
                if raw_items is not None:
                    stats.cached += 1
                else:
                    if time.monotonic() - start > self.total_timeout:
                        stats.skipped_budget += 1
                        continue
                    self._log(f"  reviewing {change.path} with {self.backend.model} ...")
                    try:
                        t0 = time.monotonic()
                        text = self.backend.chat(SYSTEM_PROMPT, prompt)
                        stats.llm_calls += 1
                        raw_items = parse_model_json(text)
                        self._log(f"    done in {time.monotonic() - t0:.1f}s, {len(raw_items)} raw finding(s)")
                    except LLMError as exc:
                        result.errors.append(f"{change.path}: {exc}")
                        if "cannot reach" in str(exc):
                            stats.seconds = time.monotonic() - start
                            return result  # server is down; don't retry every chunk
                        continue
                    self.cache.put(key, raw_items)
                for raw in raw_items:
                    f = self._validate(raw, change, stats)
                    if f:
                        result.findings.append(f)
        if stats.skipped_budget:
            result.errors.append(
                f"time budget of {self.total_timeout:.0f}s reached; {stats.skipped_budget} chunk(s) not reviewed"
            )
        self.cache.save()
        stats.seconds = time.monotonic() - start
        return result

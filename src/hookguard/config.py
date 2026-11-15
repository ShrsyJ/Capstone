"""Configuration: built-in defaults, overridden by .hookguard.toml, then env vars."""

from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any, Dict, Optional

try:  # Python 3.11+
    import tomllib as _toml
except ModuleNotFoundError:  # pragma: no cover - depends on interpreter
    try:
        import tomli as _toml  # type: ignore
    except ModuleNotFoundError:
        _toml = None

CONFIG_FILENAME = ".hookguard.toml"

DEFAULTS: Dict[str, Any] = {
    # Findings at or above this severity block the commit.
    "block_on": "high",
    # Glob patterns (matched against the repo-relative path) that are never scanned.
    "exclude": [
        "*.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
        "*.min.js", "*.min.css", "*.map", "*.svg", "*.png", "*.jpg", "*.jpeg", "*.gif",
        "*.pdf", "*.ico", "*.woff", "*.woff2", "dist/*", "build/*", "vendor/*",
        "node_modules/*",
    ],
    "max_file_bytes": 300_000,
    "secrets": {
        "enabled": True,
        # Shannon entropy (bits/char) a generic "password = '...'" value needs to count.
        "entropy_threshold": 3.0,
        # Regexes; a matched secret value that matches any of these is ignored.
        "allowlist": [],
    },
    "rules": {
        "enabled": True,
        "disabled": [],  # rule ids to turn off, e.g. ["py-bare-except"]
    },
    "llm": {
        "enabled": True,
        "backend": "ollama",            # "ollama" or "llamacpp"
        "model": "qwen2.5-coder:3b",
        "host": "",                     # empty = backend default
        "timeout": 60,                  # seconds per request
        "total_timeout": 120,           # seconds for the whole LLM stage
        "max_chunk_chars": 6000,        # diff text per request
        "temperature": 0.0,
        "num_ctx": 8192,
        "min_severity": "medium",       # drop LLM findings below this
        "can_block": True,              # may LLM findings block, or only warn?
        "on_error": "warn",             # "warn" (fail open) or "block" (fail closed)
        "skip_if_blocked": True,        # don't wait for the model if a secret already blocks
        "cache": True,
    },
}


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def _env_overrides(cfg: Dict[str, Any]) -> Dict[str, Any]:
    env = os.environ
    if env.get("HOOKGUARD_MODEL"):
        cfg["llm"]["model"] = env["HOOKGUARD_MODEL"]
    if env.get("HOOKGUARD_HOST"):
        cfg["llm"]["host"] = env["HOOKGUARD_HOST"]
    if env.get("HOOKGUARD_BACKEND"):
        cfg["llm"]["backend"] = env["HOOKGUARD_BACKEND"]
    if env.get("HOOKGUARD_NO_LLM", "").lower() in ("1", "true", "yes"):
        cfg["llm"]["enabled"] = False
    return cfg


def load_config(repo_root: Optional[Path] = None, path: Optional[Path] = None) -> Dict[str, Any]:
    """Load the effective config for a repository."""
    cfg = copy.deepcopy(DEFAULTS)
    cfg_path = path or ((repo_root or Path.cwd()) / CONFIG_FILENAME)
    if cfg_path.is_file():
        if _toml is None:
            import sys

            print(
                f"hookguard: warning: ignoring {cfg_path.name} because no TOML parser is available "
                "(pip install tomli, or use Python 3.11+); using defaults",
                file=sys.stderr,
            )
            return _env_overrides(cfg)
        with open(cfg_path, "rb") as fh:
            user = _toml.load(fh)
        cfg = _deep_merge(cfg, user)
        # User excludes extend the built-in list rather than replacing it.
        if "exclude" in user:
            cfg["exclude"] = list(dict.fromkeys(DEFAULTS["exclude"] + list(user["exclude"])))
    return _env_overrides(cfg)


DEFAULT_CONFIG_TOML = """\
# hookguard configuration. Every key is optional; these are the defaults.

# Findings at or above this severity block the commit: low | medium | high | critical
block_on = "high"

# Extra paths to skip (glob, repo-relative). These are added to the built-in list.
# exclude = ["tests/fixtures/*"]

[secrets]
enabled = true
entropy_threshold = 3.0
# Regexes for values that look like secrets but are not (test fixtures, etc.)
allowlist = []

[rules]
enabled = true
# Turn off individual static rules by id, e.g. ["py-bare-except"]
disabled = []

[llm]
enabled = true
backend = "ollama"            # "ollama" or "llamacpp" (llama-server)
model = "qwen2.5-coder:3b"
# host = "http://127.0.0.1:11434"   # llama-server default: http://127.0.0.1:8080
timeout = 60
total_timeout = 120
max_chunk_chars = 6000
temperature = 0.0
num_ctx = 8192
min_severity = "medium"
can_block = true
on_error = "warn"             # "warn" = commit anyway if the model is down; "block" = refuse
skip_if_blocked = true        # skip the model when a secret/static rule already blocks the commit
cache = true
"""

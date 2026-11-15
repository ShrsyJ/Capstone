"""The review pipeline: filter files -> secrets -> static rules -> local LLM -> verdict."""

from __future__ import annotations

import fnmatch
import time
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional

from hookguard.llm import LLMError, make_backend
from hookguard.models import FileChange, Finding, Severity
from hookguard.reviewer import LLMReviewer, ReviewStats
from hookguard.rules import RuleEngine
from hookguard.secrets import SecretScanner


@dataclass
class Report:
    findings: List[Finding] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    blocked: bool = False
    block_reason: str = ""
    files_reviewed: List[str] = field(default_factory=list)
    files_skipped: List[str] = field(default_factory=list)
    timings: Dict[str, float] = field(default_factory=dict)
    llm_stats: Optional[ReviewStats] = None
    llm_ran: bool = False
    llm_raw: List[str] = field(default_factory=list)  # raw model replies (not printed)

    def to_dict(self) -> dict:
        return {
            "blocked": self.blocked,
            "block_reason": self.block_reason,
            "findings": [f.to_dict() for f in self.findings],
            "warnings": self.warnings,
            "files_reviewed": self.files_reviewed,
            "files_skipped": self.files_skipped,
            "timings": {k: round(v, 3) for k, v in self.timings.items()},
            "llm": vars(self.llm_stats) if self.llm_stats else None,
        }


def is_excluded(path: str, patterns: List[str]) -> bool:
    p = PurePosixPath(path)
    return any(fnmatch.fnmatch(path, pat) or fnmatch.fnmatch(p.name, pat) for pat in patterns)


def _dedupe(findings: List[Finding]) -> List[Finding]:
    """Keep one finding per (file, line, category); deterministic layers win over the LLM."""
    order = {"secrets": 0, "rules": 1, "llm": 2}
    best: Dict[tuple, Finding] = {}
    for f in sorted(findings, key=lambda f: (order.get(f.source, 9), -int(f.severity))):
        key = (f.file, f.line, "secret" if f.category == "secret" else f.category)
        if key not in best:
            best[key] = f
    # An LLM "secret" finding on a line the secret scanner already flagged is redundant.
    secret_lines = {(f.file, f.line) for f in best.values() if f.source == "secrets"}
    out = [f for f in best.values() if not (f.source == "llm" and (f.file, f.line) in secret_lines)]
    return sorted(out, key=lambda f: (f.file, f.line or 0, -int(f.severity)))


def run_pipeline(
    changes: List[FileChange],
    cfg: Dict[str, Any],
    use_llm: Optional[bool] = None,
    cache_path: Optional[Path] = None,
    progress: bool = True,
) -> Report:
    report = Report()
    block_on = Severity.parse(cfg.get("block_on", "high"), Severity.HIGH)
    llm_cfg = cfg.get("llm", {})

    reviewable: List[FileChange] = []
    for ch in changes:
        if is_excluded(ch.path, cfg.get("exclude", [])) or not ch.added:
            report.files_skipped.append(ch.path)
            continue
        size = sum(len(a.text) + 1 for a in ch.added)
        if size > int(cfg.get("max_file_bytes", 300_000)):
            report.files_skipped.append(ch.path)
            report.warnings.append(f"{ch.path}: change too large ({size} bytes), skipped")
            continue
        reviewable.append(ch)
    report.files_reviewed = [c.path for c in reviewable]

    # 1. Secrets (always on unless explicitly disabled; never needs a model)
    t = time.monotonic()
    if cfg.get("secrets", {}).get("enabled", True):
        scanner = SecretScanner(
            entropy_threshold=float(cfg["secrets"].get("entropy_threshold", 3.0)),
            allowlist=cfg["secrets"].get("allowlist", []),
        )
        for ch in reviewable:
            report.findings.extend(scanner.scan(ch))
    report.timings["secrets"] = time.monotonic() - t

    # 2. Static anti-pattern rules
    t = time.monotonic()
    if cfg.get("rules", {}).get("enabled", True):
        engine = RuleEngine(disabled=cfg["rules"].get("disabled", []))
        for ch in reviewable:
            report.findings.extend(engine.scan(ch))
    report.timings["rules"] = time.monotonic() - t

    already_blocked = any(f.severity >= block_on for f in report.findings)

    # 3. Local LLM review
    llm_enabled = llm_cfg.get("enabled", True) if use_llm is None else use_llm
    llm_failed = False
    if llm_enabled and reviewable and already_blocked and llm_cfg.get("skip_if_blocked", True):
        report.warnings.append("LLM review skipped: commit is already blocked by deterministic checks")
    elif llm_enabled and reviewable:
        t = time.monotonic()
        try:
            backend = make_backend(llm_cfg)
            reviewer = LLMReviewer(backend, llm_cfg, cache_path=cache_path, progress=progress)
            result = reviewer.review(reviewable)
            report.llm_ran = result.stats.llm_calls > 0 or result.stats.cached > 0
            report.llm_stats = result.stats
            report.findings.extend(result.findings)
            report.llm_raw = result.raw_responses
            for err in result.errors:
                report.warnings.append(f"LLM: {err}")
            llm_failed = bool(result.errors) and not report.llm_ran
        except LLMError as exc:
            report.warnings.append(f"LLM: {exc}")
            llm_failed = True
        report.timings["llm"] = time.monotonic() - t

    report.findings = _dedupe(report.findings)

    # Verdict
    can_block_llm = bool(llm_cfg.get("can_block", True))
    blocking = [
        f for f in report.findings
        if f.severity >= block_on and (f.source != "llm" or can_block_llm)
    ]
    if blocking:
        report.blocked = True
        report.block_reason = f"{len(blocking)} finding(s) at or above '{block_on.label()}'"
    elif llm_failed and str(llm_cfg.get("on_error", "warn")).lower() == "block":
        report.blocked = True
        report.block_reason = "LLM review failed and llm.on_error = 'block'"
    return report

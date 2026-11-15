"""Human-readable terminal output."""

from __future__ import annotations

import os
import sys
from itertools import groupby
from typing import TextIO

from hookguard.engine import Report
from hookguard.models import Severity


class _C:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def __call__(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text


_SEV_COLOR = {Severity.CRITICAL: "1;41;97", Severity.HIGH: "1;31", Severity.MEDIUM: "33", Severity.LOW: "36"}
_SOURCE_LABEL = {"secrets": "secret-scan", "rules": "static", "llm": "llm"}


def print_report(report: Report, out: TextIO = sys.stdout, color: bool = None) -> None:
    if color is None:
        color = out.isatty() and os.environ.get("NO_COLOR") is None
    c = _C(color)

    print(c("1", "hookguard") + c("2", f"  reviewed {len(report.files_reviewed)} file(s)"), file=out)

    for path, items in groupby(report.findings, key=lambda f: f.file):
        print("", file=out)
        print(c("1;4", path), file=out)
        for f in items:
            sev = c(_SEV_COLOR[f.severity], f" {f.severity.label().upper():<8}")
            loc = f"L{f.line}" if f.line else "  "
            src = c("2", f"[{_SOURCE_LABEL.get(f.source, f.source)}:{f.rule if f.source != 'llm' else f.category}]")
            print(f"  {sev} {loc:>6}  {f.message} {src}", file=out)
            if f.snippet:
                print(c("2", f"{'':>18}> {f.snippet}"), file=out)
            if f.suggestion:
                print(c("32", f"{'':>18}fix: {f.suggestion}"), file=out)

    for w in report.warnings:
        print(c("33", f"\n  ! {w}"), file=out)

    t = report.timings
    timing = ", ".join(f"{k} {v * 1000:.0f}ms" if v < 1 else f"{k} {v:.1f}s" for k, v in t.items())
    print("", file=out)
    if report.blocked:
        print(c("1;31", f"✖ Commit blocked: {report.block_reason}"), file=out)
        print(c("2", "  Fix the issues above, or bypass once with: git commit --no-verify"), file=out)
        print(c("2", "  Mark a known false positive with a trailing comment: hookguard: ignore"), file=out)
    elif report.findings:
        print(c("1;33", f"⚠ {len(report.findings)} warning(s), commit allowed"), file=out)
    else:
        print(c("1;32", "✔ No issues found"), file=out)
    if timing:
        print(c("2", f"  ({timing})"), file=out)

"""Fast static anti-pattern rules (single-line regexes, language-aware).

These catch the obvious, high-confidence cases in milliseconds. The LLM layer is
for things a regex cannot judge (context, intent, multi-line logic).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Iterable, List, Optional, Pattern, Tuple

from hookguard.models import FileChange, Finding, Severity
from hookguard.secrets import SUPPRESS_MARKERS, redact_line

PY = (".py", ".pyw")
JS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte")
GO = (".go",)
JAVA = (".java", ".kt", ".scala")
SH = (".sh", ".bash", ".zsh")
ANY: Tuple[str, ...] = ()


@dataclass(frozen=True)
class StaticRule:
    id: str
    extensions: Tuple[str, ...]   # empty tuple = all text files
    pattern: Pattern[str]
    severity: Severity
    category: str
    message: str
    suggestion: str
    unless: Optional[Pattern[str]] = None  # if this also matches the line, skip it


def _r(p: str) -> Pattern[str]:
    return re.compile(p)


STATIC_RULES: List[StaticRule] = [
    # ---- Python ----
    StaticRule("py-eval-exec", PY, _r(r"(?<![\w.])(eval|exec)\s*\("), Severity.HIGH, "code-injection",
               "Use of eval()/exec() can execute arbitrary code.",
               "Use ast.literal_eval() for literals, or explicit parsing/dispatch."),
    StaticRule("py-subprocess-shell", PY, _r(r"subprocess\.\w+\(.*shell\s*=\s*True"), Severity.HIGH,
               "command-injection", "subprocess with shell=True is vulnerable to shell injection.",
               "Pass an argument list and keep shell=False."),
    StaticRule("py-os-system", PY, _r(r"\bos\.(system|popen)\s*\("), Severity.MEDIUM, "command-injection",
               "os.system()/os.popen() run commands through the shell.",
               "Use subprocess.run([...]) with an argument list."),
    StaticRule("py-pickle-load", PY, _r(r"\b(c?[Pp]ickle|dill|joblib)\.loads?\s*\("), Severity.MEDIUM,
               "unsafe-deserialization", "Unpickling untrusted data can execute arbitrary code.",
               "Use JSON or another safe format for untrusted input."),
    StaticRule("py-yaml-load", PY, _r(r"\byaml\.(load|load_all)\s*\("), Severity.HIGH, "unsafe-deserialization",
               "yaml.load() without SafeLoader can construct arbitrary objects.",
               "Use yaml.safe_load().", unless=_r(r"SafeLoader|CSafeLoader")),
    StaticRule("py-sql-format", PY,
               _r(r"\.execute(many)?\(\s*(f[\"']|[\"'][^\"']*[\"']\s*(%|\.format\(|\+))"),
               Severity.HIGH, "sql-injection", "SQL query built with string formatting.",
               "Use parameterised queries: cursor.execute(sql, params)."),
    StaticRule("py-requests-verify-false", PY, _r(r"\bverify\s*=\s*False\b"), Severity.MEDIUM, "insecure-tls",
               "TLS certificate verification disabled.", "Remove verify=False or pin a CA bundle."),
    StaticRule("py-flask-debug", PY, _r(r"\.run\(.*debug\s*=\s*True"), Severity.MEDIUM, "insecure-config",
               "Flask debug mode exposes an interactive debugger.", "Never enable debug in deployable code."),
    StaticRule("py-bare-except", PY, _r(r"^\s*except\s*:\s*(pass)?\s*$"), Severity.LOW, "error-handling",
               "Bare except swallows every error, including KeyboardInterrupt.",
               "Catch specific exceptions and log them."),
    # ---- JavaScript / TypeScript ----
    StaticRule("js-eval", JS, _r(r"(?<![\w.])eval\s*\(|\bnew\s+Function\s*\("), Severity.HIGH, "code-injection",
               "eval()/new Function() executes arbitrary strings as code.", "Parse data with JSON.parse or refactor."),
    StaticRule("js-inner-html", JS, _r(r"\.(innerHTML|outerHTML)\s*\+?=|dangerouslySetInnerHTML|document\.write\("),
               Severity.MEDIUM, "xss", "Writing raw HTML can lead to cross-site scripting.",
               "Use textContent, or sanitise with a library like DOMPurify."),
    StaticRule("js-exec-template", JS, _r(r"\bexec(Sync)?\s*\(\s*`[^`]*\$\{"), Severity.HIGH, "command-injection",
               "Shell command built from a template string with interpolation.",
               "Use execFile/spawn with an argument array."),
    StaticRule("js-tls-disabled", JS, _r(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0"),
               Severity.MEDIUM, "insecure-tls", "TLS certificate verification disabled.",
               "Keep certificate verification on."),
    # ---- Other languages ----
    StaticRule("go-insecure-skip-verify", GO, _r(r"InsecureSkipVerify\s*:\s*true"), Severity.MEDIUM, "insecure-tls",
               "TLS certificate verification disabled.", "Remove InsecureSkipVerify."),
    StaticRule("java-runtime-exec", JAVA, _r(r"Runtime\.getRuntime\(\)\.exec\(.*\+"), Severity.HIGH,
               "command-injection", "Command built by string concatenation.",
               "Use ProcessBuilder with an argument list."),
    StaticRule("sh-curl-pipe-shell", SH, _r(r"(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z)?sh\b"), Severity.MEDIUM,
               "supply-chain", "Piping a download straight into a shell.", "Download, verify checksum, then run."),
    # ---- Any language ----
    StaticRule("sql-string-concat", ANY,
               _r(r"(?i)[\"'`]\s*(select\s.+\sfrom|insert\s+into|update\s+\w+\s+set|delete\s+from)\b[^\"'`]*[\"'`]\s*\+\s*\w"),
               Severity.HIGH, "sql-injection", "SQL query built by string concatenation.",
               "Use parameterised queries / prepared statements."),
    StaticRule("chmod-777", ANY, _r(r"chmod\s*\(?\s*['\"]?(0o?)?777\b"), Severity.MEDIUM, "insecure-permissions",
               "World-writable permissions (777).", "Use the narrowest permissions needed (e.g. 644/755)."),
]

_COMMENT_RE = re.compile(r"^\s*(#|//|/\*|\*|--)")


class RuleEngine:
    def __init__(self, disabled: Iterable[str] = ()):
        disabled = set(disabled)
        self.rules = [r for r in STATIC_RULES if r.id not in disabled]

    def _applies(self, rule: StaticRule, path: str) -> bool:
        if not rule.extensions:
            return True
        return PurePosixPath(path).suffix.lower() in rule.extensions

    def scan(self, change: FileChange) -> List[Finding]:
        rules = [r for r in self.rules if self._applies(r, change.path)]
        if not rules:
            return []
        out: List[Finding] = []
        for added in change.added:
            line = added.text
            if _COMMENT_RE.match(line) or any(m in line.lower() for m in SUPPRESS_MARKERS):
                continue
            for rule in rules:
                if rule.pattern.search(line) and not (rule.unless and rule.unless.search(line)):
                    out.append(
                        Finding(
                            file=change.path,
                            line=added.lineno,
                            severity=rule.severity,
                            category=rule.category,
                            rule=rule.id,
                            message=rule.message,
                            source="rules",
                            suggestion=rule.suggestion,
                            snippet=redact_line(line.strip())[:160],
                        )
                    )
        return out

"""Deterministic secret detection: provider-specific regexes + entropy-checked assignments.

This layer never depends on the LLM, so a commit containing a known key format is
blocked even when no model is running. It is fast (pure regex) and explainable.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Iterable, List, Optional, Pattern

from hookguard.models import FileChange, Finding, Severity

SUPPRESS_MARKERS = ("hookguard: ignore", "hookguard:ignore", "pragma: allowlist secret")


@dataclass(frozen=True)
class SecretRule:
    id: str
    description: str
    pattern: Pattern[str]
    severity: Severity = Severity.CRITICAL
    group: int = 0           # regex group holding the secret value
    check_entropy: bool = False


def _r(p: str, flags: int = 0) -> Pattern[str]:
    return re.compile(p, flags)


SECRET_RULES: List[SecretRule] = [
    SecretRule("private-key", "Private key block",
               _r(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----")),
    SecretRule("aws-access-key-id", "AWS access key ID",
               _r(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"), group=1),
    SecretRule("aws-secret-access-key", "AWS secret access key",
               _r(r"(?i)aws.{0,20}?(?:secret|private).{0,20}?['\"\s:=]+([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"),
               group=1),
    SecretRule("github-token", "GitHub token",
               _r(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255})\b"), group=1),
    SecretRule("github-fine-grained-pat", "GitHub fine-grained PAT",
               _r(r"\b(github_pat_[A-Za-z0-9_]{60,255})\b"), group=1),
    SecretRule("gitlab-token", "GitLab personal access token",
               _r(r"\b(glpat-[A-Za-z0-9_\-]{20,})\b"), group=1),
    SecretRule("slack-token", "Slack token",
               _r(r"\b(xox[abposr]-[A-Za-z0-9-]{10,})\b"), group=1),
    SecretRule("slack-webhook", "Slack incoming webhook URL",
               _r(r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+)"), group=1),
    SecretRule("stripe-secret-key", "Stripe secret/restricted key",
               _r(r"\b((?:sk|rk)_live_[A-Za-z0-9]{20,})\b"), group=1),
    SecretRule("google-api-key", "Google API key",
               _r(r"\b(AIza[0-9A-Za-z_\-]{35})(?![0-9A-Za-z_\-])"), group=1),
    SecretRule("anthropic-api-key", "Anthropic API key",
               _r(r"\b(sk-ant-[A-Za-z0-9_\-]{20,})"), group=1),
    SecretRule("openai-api-key", "OpenAI API key",
               _r(r"\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}|sk-proj-[A-Za-z0-9_\-]{40,})"),
               group=1),
    SecretRule("huggingface-token", "Hugging Face token",
               _r(r"\b(hf_[A-Za-z0-9]{34,})\b"), group=1),
    SecretRule("twilio-api-key", "Twilio API key",
               _r(r"\b(SK[0-9a-fA-F]{32})\b"), severity=Severity.HIGH, group=1),
    SecretRule("sendgrid-api-key", "SendGrid API key",
               _r(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b"), group=1),
    SecretRule("npm-token", "npm access token",
               _r(r"\b(npm_[A-Za-z0-9]{36})\b"), group=1),
    SecretRule("jwt", "JSON Web Token",
               _r(r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})"),
               severity=Severity.HIGH, group=1),
    SecretRule("url-credentials", "Credentials embedded in a URL",
               _r(r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@'\"]+:([^\s@/'\"]{6,})@[^\s'\"]+"),
               severity=Severity.HIGH, group=1, check_entropy=True),
    # Generic: secret-looking variable name assigned a quoted literal.
    SecretRule("generic-secret-assignment", "Hardcoded secret in assignment",
               _r(r"(?i)(?:api[_\-]?key|apikey|secret(?:[_\-]?key)?|client[_\-]?secret|access[_\-]?token|"
                  r"auth[_\-]?token|bearer|passw(?:or)?d|pwd|private[_\-]?key|credentials?)"
                  r"[\w\-]*['\"]?\s*(?::=|=>|==|=|:)\s*[fbru]?['\"`]([^'\"`\s]{8,})['\"`]"),
               severity=Severity.HIGH, group=1, check_entropy=True),
]

# Values that look like secrets but are obviously placeholders.
_PLACEHOLDER_RE = re.compile(
    r"(?i)^(?:x+|\*+|\.+|-+|0+|1234.*|test.*|dummy.*|fake.*|sample.*|example.*|changeme|"
    r"your[_\-].*|<.*>|\{\{.*\}\}|\$\{.*\}|\$[A-Z_]+|%\(.*\)s|__[A-Z0-9_]+__|placeholder.*|redacted|"
    r"none|null|undefined|password|secret|todo.*)$"
)
_CODE_REF_RE = re.compile(r"(?i)(os\.environ|getenv|process\.env|env\(|config\[|settings\.)")


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def redact(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * min(len(value) - 4, 12)


def _is_suppressed(line: str) -> bool:
    low = line.lower()
    return any(m in low for m in SUPPRESS_MARKERS)


def redact_line(line: str) -> str:
    """Mask every secret value found on a line (used for output and before LLM prompts)."""
    out = line
    for rule in SECRET_RULES:
        for m in rule.pattern.finditer(line):
            value = m.group(rule.group) if rule.group else m.group(0)
            if value and len(value) > 4:
                out = out.replace(value, redact(value))
    return out


class SecretScanner:
    def __init__(self, entropy_threshold: float = 3.0, allowlist: Optional[Iterable[str]] = None):
        self.entropy_threshold = entropy_threshold
        self.allowlist = [re.compile(a) for a in (allowlist or [])]

    def _accept(self, rule: SecretRule, value: str, line: str) -> bool:
        if any(a.search(value) for a in self.allowlist):
            return False
        if rule.check_entropy:
            if _PLACEHOLDER_RE.match(value) or _CODE_REF_RE.search(value):
                return False
            if shannon_entropy(value) < self.entropy_threshold:
                return False
        return True

    def scan_text(self, path: str, lineno: int, line: str) -> List[Finding]:
        if _is_suppressed(line):
            return []
        findings: List[Finding] = []
        seen_spans = []
        for rule in SECRET_RULES:
            for m in rule.pattern.finditer(line):
                value = m.group(rule.group) if rule.group else m.group(0)
                span = m.span(rule.group) if rule.group else m.span()
                # A specific rule already matched this exact value: skip generic duplicates.
                if any(s[0] <= span[0] and span[1] <= s[1] for s in seen_spans):
                    continue
                if not self._accept(rule, value, line):
                    continue
                seen_spans.append(span)
                findings.append(
                    Finding(
                        file=path,
                        line=lineno,
                        severity=rule.severity,
                        category="secret",
                        rule=rule.id,
                        message=f"{rule.description} detected",
                        source="secrets",
                        suggestion="Remove it from the code, rotate the credential, and load it from "
                                   "an environment variable or secrets manager instead.",
                        snippet=redact_line(line.strip())[:160],
                    )
                )
        return findings

    def scan(self, change: FileChange) -> List[Finding]:
        out: List[Finding] = []
        for added in change.added:
            out.extend(self.scan_text(change.path, added.lineno, added.text))
        return out

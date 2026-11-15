"""Core data types shared by every layer of the pipeline."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import List, Optional


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str, default: "Severity" = None) -> "Severity":
        try:
            return cls[str(value).strip().upper()]
        except KeyError:
            if default is not None:
                return default
            raise ValueError(f"unknown severity: {value!r}")

    def label(self) -> str:
        return self.name.lower()


@dataclass
class AddedLine:
    """A line added by the change, with its line number in the new file."""

    lineno: int
    text: str


@dataclass
class FileChange:
    """Everything we know about one changed file."""

    path: str
    added: List[AddedLine] = field(default_factory=list)
    # Unified diff with a few lines of context, used as the LLM's input.
    patch: str = ""
    is_new_file: bool = False

    def added_linenos(self) -> set:
        return {a.lineno for a in self.added}


@dataclass
class Finding:
    file: str
    line: Optional[int]
    severity: Severity
    category: str       # e.g. "secret", "injection", "unsafe-deserialization"
    rule: str           # rule id, e.g. "aws-access-key" or "llm"
    message: str
    source: str         # "secrets" | "rules" | "llm"
    suggestion: str = ""
    snippet: str = ""   # already redacted

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.label()
        return d

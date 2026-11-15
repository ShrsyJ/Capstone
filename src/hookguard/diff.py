"""Read staged changes from git and parse unified diffs into FileChange objects."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import List, Optional

from hookguard.models import AddedLine, FileChange

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


class GitError(RuntimeError):
    pass


def _git(args: List[str], cwd: Optional[Path] = None) -> str:
    try:
        proc = subprocess.run(
            ["git", "-c", "core.quotepath=off", *args],
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError as exc:  # git not installed
        raise GitError("git executable not found") from exc
    if proc.returncode != 0:
        raise GitError(proc.stderr.strip() or f"git {' '.join(args)} failed")
    return proc.stdout


def repo_root(cwd: Optional[Path] = None) -> Path:
    return Path(_git(["rev-parse", "--show-toplevel"], cwd).strip())


def hooks_dir(cwd: Optional[Path] = None) -> Path:
    """Hooks directory, honouring core.hooksPath and worktrees."""
    out = _git(["rev-parse", "--git-path", "hooks"], cwd).strip()
    p = Path(out)
    if not p.is_absolute():
        p = (cwd or Path.cwd()) / p
    return p.resolve()


def git_dir(cwd: Optional[Path] = None) -> Path:
    p = Path(_git(["rev-parse", "--git-dir"], cwd).strip())
    if not p.is_absolute():
        p = (cwd or Path.cwd()) / p
    return p.resolve()


def staged_diff(cwd: Optional[Path] = None, context: int = 3) -> str:
    return _git(
        [
            "diff", "--cached", "--no-color", "--no-ext-diff",
            f"--unified={context}", "--diff-filter=ACMR",
        ],
        cwd,
    )


def _clean_path(raw: str) -> str:
    raw = raw.rstrip("\n").split("\t")[0]
    if raw.startswith('"') and raw.endswith('"'):
        raw = raw[1:-1].encode("latin-1", "backslashreplace").decode("unicode_escape")
    if raw.startswith(("a/", "b/")):
        raw = raw[2:]
    return raw


def parse_unified_diff(text: str) -> List[FileChange]:
    """Parse `git diff` output. Only additions are tracked (we review new code)."""
    files: List[FileChange] = []
    current: Optional[FileChange] = None
    patch_lines: List[str] = []
    new_lineno = 0
    in_hunk = False

    def flush() -> None:
        if current is not None:
            current.patch = "".join(patch_lines)
            files.append(current)

    for line in text.splitlines(keepends=True):
        if line.startswith("diff --git "):
            flush()
            current, patch_lines, in_hunk = None, [line], False
            current = FileChange(path="")
            continue
        if current is None:
            continue
        patch_lines.append(line)

        if not in_hunk:
            if line.startswith("new file mode"):
                current.is_new_file = True
            elif line.startswith("+++ "):
                target = line[4:]
                if target.strip() != "/dev/null":
                    current.path = _clean_path(target)
            elif line.startswith("Binary files "):
                current.added = []
        m = _HUNK_RE.match(line)
        if m:
            in_hunk = True
            new_lineno = int(m.group(1))
            continue
        if not in_hunk:
            continue
        if line.startswith("+"):
            current.added.append(AddedLine(new_lineno, line[1:].rstrip("\r\n")))
            new_lineno += 1
        elif line.startswith(" "):
            new_lineno += 1
        elif line.startswith("-") or line.startswith("\\"):
            pass  # removed line / "No newline at end of file"
    flush()
    return [f for f in files if f.path]


def file_as_change(path: str, content: str) -> FileChange:
    """Treat a whole file as newly added (used by `hookguard scan` and the eval harness)."""
    lines = content.splitlines()
    added = [AddedLine(i + 1, t) for i, t in enumerate(lines)]
    patch = f"--- /dev/null\n+++ b/{path}\n@@ -0,0 +1,{len(lines)} @@\n" + "".join(
        f"+{t}\n" for t in lines
    )
    return FileChange(path=path, added=added, patch=patch, is_new_file=True)

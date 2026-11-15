"""Install / uninstall the git pre-commit hook."""

from __future__ import annotations

import os
import stat
import sys
import time
from pathlib import Path
from typing import Optional

from hookguard.diff import hooks_dir

MARKER = "# hookguard-managed-hook"


def hook_script(python: Optional[str] = None) -> str:
    python = python or sys.executable
    return f"""#!/bin/sh
{MARKER}
# Runs a local, offline review of staged changes before each commit.
# Skip once:  git commit --no-verify     Skip via env:  HOOKGUARD_SKIP=1 git commit ...
[ "$HOOKGUARD_SKIP" = "1" ] && exit 0
if [ -x "{python}" ]; then
  exec "{python}" -m hookguard run
elif command -v hookguard >/dev/null 2>&1; then
  exec hookguard run
else
  echo "hookguard: not found (was the virtualenv removed?); skipping review" >&2
  exit 0
fi
"""


def install(cwd: Optional[Path] = None, force: bool = False) -> str:
    hdir = hooks_dir(cwd)
    hdir.mkdir(parents=True, exist_ok=True)
    target = hdir / "pre-commit"
    if target.exists():
        existing = target.read_text("utf-8", errors="replace")
        if MARKER not in existing:
            if not force:
                raise FileExistsError(
                    f"{target} already exists and was not created by hookguard. "
                    "Re-run with --force to back it up and replace it, or call "
                    "`hookguard run` from your existing hook."
                )
            backup = target.with_name(f"pre-commit.backup-{int(time.time())}")
            target.rename(backup)
    target.write_text(hook_script(), "utf-8")
    mode = target.stat().st_mode
    target.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return str(target)


def uninstall(cwd: Optional[Path] = None) -> Optional[str]:
    target = hooks_dir(cwd) / "pre-commit"
    if target.exists() and MARKER in target.read_text("utf-8", errors="replace"):
        os.remove(target)
        return str(target)
    return None

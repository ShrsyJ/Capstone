"""Command-line interface.

  hookguard init         write a default .hookguard.toml
  hookguard install      install the git pre-commit hook in this repo
  hookguard uninstall    remove it
  hookguard run          review staged changes (what the hook calls)
  hookguard scan FILE..  review whole files (demo / CI / evaluation)
  hookguard doctor       check git, the LLM backend, and the model
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from hookguard import __version__
from hookguard.config import CONFIG_FILENAME, DEFAULT_CONFIG_TOML, load_config
from hookguard.diff import GitError, file_as_change, git_dir, parse_unified_diff, repo_root, staged_diff
from hookguard.engine import run_pipeline
from hookguard.hook import install, uninstall
from hookguard.llm import LLMError, make_backend
from hookguard.report import print_report


def _apply_overrides(cfg: dict, args: argparse.Namespace) -> dict:
    if getattr(args, "model", None):
        cfg["llm"]["model"] = args.model
    if getattr(args, "backend", None):
        cfg["llm"]["backend"] = args.backend
    if getattr(args, "host", None):
        cfg["llm"]["host"] = args.host
    if getattr(args, "block_on", None):
        cfg["block_on"] = args.block_on
    return cfg


def _emit(report, as_json: bool) -> int:
    if as_json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print_report(report)
    return 1 if report.blocked else 0


def cmd_run(args: argparse.Namespace) -> int:
    try:
        root = repo_root()
        diff_text = staged_diff(root)
        cache = git_dir(root) / "hookguard" / "cache.json"
    except GitError as exc:
        print(f"hookguard: {exc}", file=sys.stderr)
        return 2
    cfg = _apply_overrides(load_config(root), args)
    changes = parse_unified_diff(diff_text)
    if not changes:
        if not args.json:
            print("hookguard: nothing staged to review")
        return 0
    report = run_pipeline(changes, cfg, use_llm=False if args.no_llm else None,
                          cache_path=cache, progress=not args.json)
    return _emit(report, args.json)


def cmd_scan(args: argparse.Namespace) -> int:
    cfg = _apply_overrides(load_config(Path.cwd()), args)
    changes = []
    for name in args.files:
        p = Path(name)
        files = [f for f in p.rglob("*") if f.is_file()] if p.is_dir() else [p]
        for f in files:
            try:
                changes.append(file_as_change(f.as_posix(), f.read_text("utf-8")))
            except (UnicodeDecodeError, OSError):
                continue
    report = run_pipeline(changes, cfg, use_llm=False if args.no_llm else None, progress=not args.json)
    return _emit(report, args.json)


def cmd_install(args: argparse.Namespace) -> int:
    try:
        path = install(force=args.force)
    except (GitError, FileExistsError) as exc:
        print(f"hookguard: {exc}", file=sys.stderr)
        return 1
    print(f"Installed pre-commit hook at {path}")
    print("Run `hookguard doctor` to check that your local model is ready.")
    return 0


def cmd_uninstall(args: argparse.Namespace) -> int:
    try:
        path = uninstall()
    except GitError as exc:
        print(f"hookguard: {exc}", file=sys.stderr)
        return 1
    print(f"Removed {path}" if path else "No hookguard-managed hook found.")
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    target = Path.cwd() / CONFIG_FILENAME
    if target.exists() and not args.force:
        print(f"{target} already exists (use --force to overwrite)", file=sys.stderr)
        return 1
    target.write_text(DEFAULT_CONFIG_TOML, "utf-8")
    print(f"Wrote {target}")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    ok = True
    try:
        root = repo_root()
        print(f"✔ git repository: {root}")
    except GitError as exc:
        root = Path.cwd()
        print(f"✖ not inside a git repository ({exc})")
        ok = False
    cfg = _apply_overrides(load_config(root), args)
    llm_cfg = cfg["llm"]
    if not llm_cfg.get("enabled", True):
        print("• LLM review disabled in config; only secret/static checks will run")
        return 0 if ok else 1
    try:
        healthy, msg = make_backend(llm_cfg).health()
    except LLMError as exc:
        healthy, msg = False, str(exc)
    print(("✔ " if healthy else "✖ ") + msg)
    if healthy and args.smoke:
        from hookguard.models import AddedLine, FileChange
        from hookguard.reviewer import LLMReviewer

        demo = FileChange(
            path="demo.py",
            added=[AddedLine(1, "import os"), AddedLine(2, "def run(cmd):"),
                   AddedLine(3, "    os.system('ping ' + cmd)")],
            patch="@@ -0,0 +1,3 @@\n+import os\n+def run(cmd):\n+    os.system('ping ' + cmd)\n",
        )
        llm_cfg = dict(llm_cfg, cache=False)
        res = LLMReviewer(make_backend(llm_cfg), llm_cfg, progress=True).review([demo])
        print(f"  smoke test: {len(res.findings)} finding(s) in {res.stats.seconds:.1f}s; errors: {res.errors or 'none'}")
        for f in res.findings:
            print(f"    L{f.line} {f.severity.label()} {f.category}: {f.message}")
    return 0 if (ok and healthy) else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hookguard", description="Local-first, offline pre-commit code review.")
    p.add_argument("--version", action="version", version=f"hookguard {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def llm_opts(sp):
        sp.add_argument("--model", help="model name (e.g. qwen2.5-coder:3b)")
        sp.add_argument("--backend", choices=["ollama", "llamacpp"])
        sp.add_argument("--host", help="LLM server URL")

    sp = sub.add_parser("run", help="review staged changes (used by the hook)")
    llm_opts(sp)
    sp.add_argument("--no-llm", action="store_true", help="only run secret + static checks")
    sp.add_argument("--json", action="store_true", help="machine-readable output")
    sp.add_argument("--block-on", choices=["low", "medium", "high", "critical"])
    sp.set_defaults(func=cmd_run)

    sp = sub.add_parser("scan", help="review whole files or folders")
    sp.add_argument("files", nargs="+")
    llm_opts(sp)
    sp.add_argument("--no-llm", action="store_true")
    sp.add_argument("--json", action="store_true")
    sp.add_argument("--block-on", choices=["low", "medium", "high", "critical"])
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("install", help="install the pre-commit hook")
    sp.add_argument("--force", action="store_true", help="replace (and back up) an existing hook")
    sp.set_defaults(func=cmd_install)

    sp = sub.add_parser("uninstall", help="remove the pre-commit hook")
    sp.set_defaults(func=cmd_uninstall)

    sp = sub.add_parser("init", help="write a default .hookguard.toml")
    sp.add_argument("--force", action="store_true")
    sp.set_defaults(func=cmd_init)

    sp = sub.add_parser("doctor", help="check the setup")
    llm_opts(sp)
    sp.add_argument("--smoke", action="store_true", help="also send a tiny test review to the model")
    sp.set_defaults(func=cmd_doctor)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nhookguard: interrupted", file=sys.stderr)
        return 130
    except RuntimeError as exc:
        print(f"hookguard: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

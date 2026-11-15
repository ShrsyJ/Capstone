"""Evaluation harness: how well does each layer / model decide "block or allow"?

Modes
  static   secret scanner + regex rules only (the baseline, no model)
  llm      the local model alone (secret/static layers disabled) - ablation
  hybrid   the real tool: static layers first, then the model

Splits
  Every label has a "split" (train | dev | test; default dev). Tune prompts on dev
  only; run --split test once, for the final numbers.

Usage
  python eval/run_eval.py                                   # static baseline only
  python eval/run_eval.py --models qwen2.5-coder:1.5b qwen2.5-coder:3b
  python eval/run_eval.py --models qwen2.5-coder:3b --backend llamacpp --host http://127.0.0.1:8080

Writes eval/results/<timestamp>.md (summary table) and .json (per-case detail).
"""

from __future__ import annotations

import argparse
import copy
import json
import platform
import statistics
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from hookguard.config import DEFAULTS  # noqa: E402
from hookguard.diff import file_as_change  # noqa: E402
from hookguard.engine import run_pipeline  # noqa: E402
from hookguard import __version__  # noqa: E402
from hookguard.llm import LLMError, _request, make_backend  # noqa: E402
from hookguard.models import Severity  # noqa: E402
from hookguard.prompts import PROMPT_VERSION  # noqa: E402

sys.path.insert(0, str(HERE))
from fake_secrets import materialize  # noqa: E402


SPLITS = ("train", "dev", "test")

# Static rules use finer category names than the LLM's closed list; map them onto it
# so a finding from either layer can be compared with the label.
CANONICAL = {
    "sql-injection": "injection", "command-injection": "injection", "code-injection": "injection",
    "insecure-tls": "crypto",
}


def canonical(category: str) -> str:
    return CANONICAL.get(category, category)


def strict_hit(findings, label, block_on) -> bool:
    """A positive is truly *found* only if a blocking finding has the right category on a labelled line."""
    wanted = {label.get("category")} | set(label.get("also", []))
    lines = set(label.get("lines", []))
    return any(
        f.severity >= block_on and canonical(f.category) in wanted and (not lines or f.line in lines)
        for f in findings
    )


def load_cases(cases_dir: Path, labels_path: Path, split: str = "dev"):
    labels = {k: v for k, v in json.loads(labels_path.read_text()).items() if not k.startswith("_")}
    cases = []
    for name, label in sorted(labels.items()):
        if split != "all" and label.get("split", "dev") != split:
            continue
        cases.append((name, materialize((cases_dir / name).read_text("utf-8")), label))
    return cases


def make_cfg(mode: str, model: str, backend: str, host: str, llm_overrides: dict = None) -> dict:
    cfg = copy.deepcopy(DEFAULTS)
    cfg["exclude"] = []
    cfg["llm"].update(model=model or "", backend=backend, host=host, cache=False, total_timeout=600)
    cfg["llm"].update(llm_overrides or {})
    if mode == "static":
        cfg["llm"]["enabled"] = False
    elif mode == "llm":
        cfg["secrets"]["enabled"] = False
        cfg["rules"]["enabled"] = False
        cfg["llm"]["skip_if_blocked"] = False
    return cfg


def pct(values, q):
    if not values:
        return 0.0
    values = sorted(values)
    k = max(0, min(len(values) - 1, round(q * (len(values) - 1))))
    return values[k]


def evaluate(cases, mode, model, backend, host, warmup=True, llm_overrides=None):
    cfg = make_cfg(mode, model, backend, host, llm_overrides)
    if mode != "static" and warmup:
        # First call loads the model into memory; exclude that from latency numbers.
        run_pipeline([file_as_change("warmup.py", "x = 1\n")], cfg, progress=False)
    rows = []
    for name, content, label in cases:
        t0 = time.monotonic()
        rep = run_pipeline([file_as_change(name, content)], cfg, progress=False)
        dt = time.monotonic() - t0
        rows.append({
            "case": name,
            "expected_block": label["block"],
            "blocked": rep.blocked,
            "correct": rep.blocked == label["block"],
            "strict_hit": bool(label["block"]) and rep.blocked and strict_hit(
                rep.findings, label, Severity.parse(cfg.get("block_on", "high"))),
            "seconds": round(dt, 3),
            "findings": [f"{f.source}:{f.category}:{f.severity.label()}@L{f.line}" for f in rep.findings],
            "warnings": rep.warnings,
            "dropped_invalid": rep.llm_stats.dropped_invalid if rep.llm_stats else 0,
            "raw": rep.llm_raw,
            "usage": {k: round(sum(u.get(k, 0) for u in rep.llm_usage), 3)
                      for k in ("tokens_in", "tokens_out", "load_s", "prompt_s", "gen_s")},
        })
    tp = sum(r["blocked"] and r["expected_block"] for r in rows)
    fp = sum(r["blocked"] and not r["expected_block"] for r in rows)
    fn = sum(not r["blocked"] and r["expected_block"] for r in rows)
    tn = sum(not r["blocked"] and not r["expected_block"] for r in rows)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    positives = sum(r["expected_block"] for r in rows)
    strict_tp = sum(r["strict_hit"] for r in rows)
    secs = [r["seconds"] for r in rows]
    summary = {
        "mode": mode, "model": model or "-", "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3),
        "accuracy": round((tp + tn) / len(rows), 3),
        # strict: right category on a labelled line, not just "blocked for some reason"
        "strict_recall": round(strict_tp / positives, 3) if positives else 0.0,
        "strict_precision": round(strict_tp / (tp + fp), 3) if tp + fp else 0.0,
        "fp_rate": round(fp / (fp + tn), 3) if fp + tn else 0.0,
        "latency_mean_s": round(statistics.mean(secs), 3),
        "latency_p95_s": round(pct(secs, 0.95), 3),
        "hallucinated_lines": sum(r["dropped_invalid"] for r in rows),
        "llm_errors": sum(1 for r in rows for w in r["warnings"] if w.startswith("LLM:")),
    }
    gen_s = sum(r["usage"]["gen_s"] for r in rows)
    if gen_s:
        summary["gen_tok_per_s"] = round(sum(r["usage"]["tokens_out"] for r in rows) / gen_s, 1)
        summary["mean_tokens_out"] = round(statistics.mean(r["usage"]["tokens_out"] for r in rows), 1)
    return summary, rows


def ollama_memory(host: str, model: str) -> dict:
    """Resident size of a loaded model, from Ollama's /api/ps (bytes -> GB)."""
    try:
        resp = _request(f"{(host or 'http://127.0.0.1:11434').rstrip('/')}/api/ps", None, 5)
    except LLMError:
        return {}
    for m in resp.get("models", []):
        if m.get("name") == model or m.get("model") == model:
            return {"ram_gb": round(m.get("size", 0) / 1e9, 2),
                    "gpu_gb": round(m.get("size_vram", 0) / 1e9, 2),
                    "context": m.get("context_length")}
    return {}


def swap_used_gb():
    """macOS swap in use (GB), or None. Heavy swap makes latency numbers meaningless."""
    try:
        out = subprocess.check_output(["sysctl", "-n", "vm.swapusage"], text=True)
        used = out.split("used =")[1].split()[0]
        return round(float(used.rstrip("MG")) / (1024 if used.endswith("M") else 1), 2)
    except (OSError, subprocess.CalledProcessError, IndexError, ValueError):
        return None


def machine_info(backend: str, host: str) -> dict:
    info = {"python": platform.python_version(), "os": f"{platform.system()} {platform.release()}",
            "arch": platform.machine()}
    try:
        info["cpu"] = subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"], text=True).strip()
        info["ram_gb"] = round(int(subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True)) / 2**30)
    except (OSError, subprocess.CalledProcessError, ValueError):
        pass
    if backend == "ollama":
        try:
            info["ollama"] = _request(f"{(host or 'http://127.0.0.1:11434').rstrip('/')}/api/version", None, 5).get("version")
        except LLMError:
            pass
    return info


def to_markdown(summaries):
    cols = ["mode", "model", "precision", "recall", "f1", "strict_recall", "strict_precision", "fp_rate", "fp", "fn",
            "latency_mean_s", "latency_p95_s", "gen_tok_per_s", "hallucinated_lines", "llm_errors", "ram_gb", "swap_gb_end"]
    lines = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for s in summaries:
        lines.append("| " + " | ".join(str(s.get(c, "-")) for c in cols) + " |")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--models", nargs="*", default=[], help="local models to compare")
    ap.add_argument("--backend", default="ollama", choices=["ollama", "llamacpp"])
    ap.add_argument("--host", default="")
    ap.add_argument("--modes", nargs="*", default=["llm", "hybrid"], help="modes to run per model")
    ap.add_argument("--cases", default=str(HERE / "cases"))
    ap.add_argument("--labels", default=str(HERE / "labels.json"))
    ap.add_argument("--split", default="dev", choices=[*SPLITS, "all"],
                    help="which labelled split to run (tune on dev; run test only for final numbers)")
    ap.add_argument("--num-ctx", type=int, help="override llm.num_ctx")
    ap.add_argument("--timeout", type=float, help="override llm.timeout (seconds per request)")
    ap.add_argument("--think", choices=["auto", "true", "false"], help="override llm.think")
    ap.add_argument("--tag", default="", help="free-text label stored with the results")
    args = ap.parse_args()

    overrides = {}
    if args.num_ctx:
        overrides["num_ctx"] = args.num_ctx
    if args.timeout:
        overrides["timeout"] = args.timeout
    if args.think:
        overrides["think"] = args.think

    cases = load_cases(Path(args.cases), Path(args.labels), args.split)
    if not cases:
        raise SystemExit(f"no cases in split '{args.split}'")
    print(f"split={args.split}: {len(cases)} cases ({sum(c[2]['block'] for c in cases)} should block), "
          f"prompt v{PROMPT_VERSION}\n")

    swap_start = swap_used_gb()
    summaries, detail = [], {}
    s, rows = evaluate(cases, "static", "", args.backend, args.host)
    summaries.append(s)
    detail["static"] = rows

    for model in args.models:
        cfg = make_cfg("hybrid", model, args.backend, args.host, overrides)
        ok, msg = make_backend(cfg["llm"]).health()
        if not ok:
            print(f"skipping {model}: {msg}")
            continue
        for mode in args.modes:
            print(f"running {mode} with {model} ...", flush=True)
            s, rows = evaluate(cases, mode, model, args.backend, args.host, llm_overrides=overrides)
            if args.backend == "ollama":
                s.update(ollama_memory(args.host, model))
            s["swap_gb_end"] = swap_used_gb()
            summaries.append(s)
            detail[f"{mode}:{model}"] = rows

    meta = {
        "split": args.split, "n_cases": len(cases), "prompt_version": PROMPT_VERSION,
        "hookguard": __version__, "backend": args.backend, "llm_overrides": overrides,
        "tag": args.tag, "machine": machine_info(args.backend, args.host),
        "swap_gb_start": swap_start, "swap_gb_end": swap_used_gb(),
    }
    table = to_markdown(summaries)
    print("\n" + table)
    if args.models and meta["swap_gb_end"] and meta["swap_gb_end"] > 1.0:
        print(f"\nWARNING: {meta['swap_gb_end']} GB of swap in use - latency numbers from this run are not reliable.")
    out_dir = HERE / "results"
    out_dir.mkdir(exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    header = (f"# hookguard eval {stamp}\n\nsplit **{args.split}** ({len(cases)} cases), prompt v{PROMPT_VERSION}, "
              f"overrides {overrides or 'none'}{', tag: ' + args.tag if args.tag else ''}\n\n")
    (out_dir / f"{stamp}.md").write_text(header + table + "\n", "utf-8")
    (out_dir / f"{stamp}.json").write_text(
        json.dumps({"meta": meta, "summary": summaries, "cases": detail}, indent=2), "utf-8")
    print(f"\nSaved eval/results/{stamp}.md and .json")
    misses = [r["case"] for rows in detail.values() for r in rows if not r["correct"]]
    if misses:
        print("Misclassified (any mode):", ", ".join(sorted(set(misses))))


if __name__ == "__main__":
    main()

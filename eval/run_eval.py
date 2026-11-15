"""Evaluation harness: how well does each layer / model decide "block or allow"?

Modes
  static   secret scanner + regex rules only (the baseline, no model)
  llm      the local model alone (secret/static layers disabled) - ablation
  hybrid   the real tool: static layers first, then the model

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
import statistics
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from hookguard.config import DEFAULTS  # noqa: E402
from hookguard.diff import file_as_change  # noqa: E402
from hookguard.engine import run_pipeline  # noqa: E402
from hookguard.llm import make_backend  # noqa: E402

sys.path.insert(0, str(HERE))
from fake_secrets import materialize  # noqa: E402


def load_cases(cases_dir: Path, labels_path: Path):
    labels = {k: v for k, v in json.loads(labels_path.read_text()).items() if not k.startswith("_")}
    cases = []
    for name, label in sorted(labels.items()):
        cases.append((name, materialize((cases_dir / name).read_text("utf-8")), label))
    return cases


def make_cfg(mode: str, model: str, backend: str, host: str) -> dict:
    cfg = copy.deepcopy(DEFAULTS)
    cfg["exclude"] = []
    cfg["llm"].update(model=model or "", backend=backend, host=host, cache=False, total_timeout=600)
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


def evaluate(cases, mode, model, backend, host, warmup=True):
    cfg = make_cfg(mode, model, backend, host)
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
            "seconds": round(dt, 3),
            "findings": [f"{f.source}:{f.category}:{f.severity.label()}@L{f.line}" for f in rep.findings],
            "warnings": rep.warnings,
            "dropped_invalid": rep.llm_stats.dropped_invalid if rep.llm_stats else 0,
        })
    tp = sum(r["blocked"] and r["expected_block"] for r in rows)
    fp = sum(r["blocked"] and not r["expected_block"] for r in rows)
    fn = sum(not r["blocked"] and r["expected_block"] for r in rows)
    tn = sum(not r["blocked"] and not r["expected_block"] for r in rows)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    secs = [r["seconds"] for r in rows]
    summary = {
        "mode": mode, "model": model or "-", "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3),
        "accuracy": round((tp + tn) / len(rows), 3),
        "latency_mean_s": round(statistics.mean(secs), 3),
        "latency_p95_s": round(pct(secs, 0.95), 3),
        "hallucinated_lines": sum(r["dropped_invalid"] for r in rows),
        "llm_errors": sum(1 for r in rows for w in r["warnings"] if w.startswith("LLM:")),
    }
    return summary, rows


def to_markdown(summaries):
    cols = ["mode", "model", "precision", "recall", "f1", "accuracy", "fp", "fn",
            "latency_mean_s", "latency_p95_s", "hallucinated_lines", "llm_errors"]
    lines = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for s in summaries:
        lines.append("| " + " | ".join(str(s[c]) for c in cols) + " |")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--models", nargs="*", default=[], help="local models to compare")
    ap.add_argument("--backend", default="ollama", choices=["ollama", "llamacpp"])
    ap.add_argument("--host", default="")
    ap.add_argument("--modes", nargs="*", default=["llm", "hybrid"], help="modes to run per model")
    ap.add_argument("--cases", default=str(HERE / "cases"))
    ap.add_argument("--labels", default=str(HERE / "labels.json"))
    args = ap.parse_args()

    cases = load_cases(Path(args.cases), Path(args.labels))
    print(f"{len(cases)} cases ({sum(c[2]['block'] for c in cases)} should block)\n")

    summaries, detail = [], {}
    s, rows = evaluate(cases, "static", "", args.backend, args.host)
    summaries.append(s)
    detail["static"] = rows

    for model in args.models:
        cfg = make_cfg("hybrid", model, args.backend, args.host)
        ok, msg = make_backend(cfg["llm"]).health()
        if not ok:
            print(f"skipping {model}: {msg}")
            continue
        for mode in args.modes:
            print(f"running {mode} with {model} ...", flush=True)
            s, rows = evaluate(cases, mode, model, args.backend, args.host)
            summaries.append(s)
            detail[f"{mode}:{model}"] = rows

    table = to_markdown(summaries)
    print("\n" + table)
    out_dir = HERE / "results"
    out_dir.mkdir(exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    (out_dir / f"{stamp}.md").write_text(f"# hookguard eval {stamp}\n\n{table}\n", "utf-8")
    (out_dir / f"{stamp}.json").write_text(json.dumps({"summary": summaries, "cases": detail}, indent=2), "utf-8")
    print(f"\nSaved eval/results/{stamp}.md and .json")
    misses = [r["case"] for rows in detail.values() for r in rows if not r["correct"]]
    if misses:
        print("Misclassified (any mode):", ", ".join(sorted(set(misses))))


if __name__ == "__main__":
    main()

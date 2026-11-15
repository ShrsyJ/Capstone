# Capstone roadmap

A suggested plan from the working prototype in this folder to a finished capstone.
Each phase ends with something you can demo.

## Phase 0 — Setup (this week)
- [ ] Install Ollama, `ollama pull qwen2.5-coder:3b` (and `:1.5b`, `:7b` if RAM allows)
- [ ] `pip install -e ".[dev]"`, run `pytest` (all green), `hookguard doctor --smoke`
- [ ] `git init` this folder, then `hookguard install` so the project reviews itself
- [ ] Write the problem statement: cloud copilots send code off-machine; secrets leak via commits;
      existing scanners (gitleaks, detect-secrets, semgrep) are pattern-only and miss context

## Phase 1 — Core tool (done in the prototype, harden it)
- [x] Staged-diff parsing with new-file line numbers
- [x] Secret scanner: provider regexes + entropy + placeholder filter + redaction
- [x] Static anti-pattern rules (Python, JS/TS, Go, Java, shell)
- [x] Ollama + llama.cpp backends, JSON-schema output, line-number validation, cache, time budget
- [x] Hook install/uninstall, fail-open/closed, bypass, inline suppression
- [ ] Try it on 2–3 of your real repos; log every false positive and fix the rules/prompt

## Phase 2 — Evaluation (the heart of the report)
- [ ] Grow `eval/cases` from 23 to 100+ cases. Good sources:
  - Real vulnerability-fixing commits (the CVEfixes dataset, GitHub security advisories): use the
    *pre-fix* diff as a positive, the *fix* as a negative
  - OWASP Benchmark (Java) / intentionally vulnerable apps (DVWA, Juice Shop, PyGoat)
  - Ordinary clean commits from popular repos as negatives (false-positive rate matters most for adoption)
- [ ] Run `python eval/run_eval.py --models ...` for several models and quantizations, e.g.
  `qwen2.5-coder:1.5b`, `qwen2.5-coder:3b`, `qwen2.5-coder:7b`, and a general small model
  (`llama3.2:3b`, `gemma3:4b`, or a newer small Qwen). Check the Ollama library for newer
  small coder models when you run it.
- [ ] Compare against baselines: `gitleaks protect --staged`, `detect-secrets`, `semgrep --config auto`
- [ ] Report: precision / recall / F1 per mode (static, llm-only, hybrid), p95 latency, RAM use,
      hallucination rate, and a plot of quality vs. latency per model size
- [ ] Ablations: with/without the static layer, prompt variants (bump `PROMPT_VERSION`),
      Q4_K_M vs Q8_0 quantization, context size

## Phase 3 — Make it better (pick 2–3, driven by what the eval shows)
- [ ] **Few-shot examples** in the prompt for the categories the model misses
- [ ] **Two-pass verification**: a second, cheap call asks "is this finding real? yes/no" to cut false positives
- [ ] **Context enrichment**: send the enclosing function (not just ±3 diff lines) so the model can tell
      whether input is user-controlled
- [ ] **Parallel requests** per file (Ollama `OLLAMA_NUM_PARALLEL`) to cut latency on multi-file commits
- [ ] **Fine-tune** a 1.5B model with LoRA on your labelled diffs (stretch goal)
- [ ] **SARIF output** so results show up in GitHub code scanning / VS Code
- [ ] `hookguard explain` — ask the model for a longer fix suggestion for one finding

## Phase 4 — Polish and present
- [ ] Package (`pipx install hookguard`), Homebrew formula or single-file binary (PyInstaller)
- [ ] Short user study: 3–5 developers use it for a week; collect blocked commits, overrides, annoyance
- [ ] Demo script: a commit with a leaked key (blocked instantly, model not needed), a path-traversal bug
      (blocked by the model), a clean commit (passes in ~2s), Wi-Fi off to prove it's offline
- [ ] Final report sections: motivation, related work, architecture, evaluation, limitations
      (small-model recall, latency on large diffs, languages covered), future work

## Things to measure and quote
- Median and p95 hook latency per model on an M-series Mac / typical laptop
- Peak RAM of the model (`ollama ps`)
- False-positive rate on clean commits (the number that decides whether people keep the hook)
- % of findings dropped by the hallucination guard

# hookguard

**A local-first, offline alternative to cloud code review for git hooks.**
Before each commit, `hookguard` reviews your *staged* changes on your own machine and
blocks the commit if it finds hardcoded credentials or severe anti-patterns. No code
ever leaves the laptop: the language model runs locally through **Ollama** or **llama.cpp**.

```
$ git commit -m "add billing client"
  reviewing billing/client.py with qwen2.5-coder:3b ...
    done in 2.4s, 1 raw finding(s)
hookguard  reviewed 2 file(s)

billing/client.py
   MEDIUM       L18  TLS certificate verification disabled. [static:py-requests-verify-false]
                  > resp = requests.get(url, verify=False)
   HIGH         L31  User-controlled path passed to open() [llm:path-traversal]
                  > return open(os.path.join(UPLOAD_DIR, name)).read()
                  fix: Resolve the path and check it stays inside UPLOAD_DIR

✖ Commit blocked: 1 finding(s) at or above 'high'
```

## How it works

```
 git commit
     │
     ▼
 pre-commit hook ──► git diff --cached ──► parse added lines (+ line numbers)
                                              │
            ┌─────────────────────────────────┼─────────────────────────────────┐
            ▼                                 ▼                                 ▼
  1. Secret scanner (ms)           2. Static rules (ms)              3. Local LLM (seconds)
  provider regexes + entropy       eval, shell=True, SQL f-strings,  Ollama / llama-server,
  works with no model running      yaml.load, innerHTML, TLS off …   JSON-schema output,
                                                                     line-number validation,
                                                                     cache, time budget
            └─────────────────────────────────┬─────────────────────────────────┘
                                              ▼
                         dedupe ─► severity ≥ block_on ? exit 1 (block) : exit 0
```

Design decisions worth defending in the capstone report:

| Decision | Why |
|---|---|
| **Hybrid: deterministic layers before the LLM** | Secrets must be caught 100% of the time, in milliseconds, even when the model is off. Small LLMs are good at context ("is this path user-controlled?") but unreliable at exact pattern matching. |
| **Skip the LLM when already blocked** | No need to wait seconds for the model if a leaked key already stops the commit. |
| **JSON-schema constrained output** | Ollama's `format` and llama-server's `response_format` force parseable JSON even from 1–3B models. |
| **Hallucination guard** | Model findings must point at a line that was actually *added*; off-by-1–2 is snapped, anything else is dropped and counted. |
| **Secrets are masked before prompting and in output** | The model never sees the full key, so it can't echo it in logs. |
| **Fail-open by default** (`on_error = "warn"`) | If Ollama is down the commit still goes through (with a warning), so the tool never blocks your work. Set `"block"` for strict teams. |
| **Result cache in `.git/hookguard/`** | Re-running a commit after fixing one file doesn't re-review unchanged chunks. |
| **Standard library only** | Installs and runs fully offline; no dependency supply-chain risk in a security tool. |

## Quick start

```bash
# 1. Install the local model runtime (once)
brew install ollama            # or download from ollama.com
ollama serve &                 # the desktop app starts this automatically
ollama pull qwen2.5-coder:3b   # ~2 GB; use :1.5b on 8 GB machines

# 2. Install hookguard (from this folder)
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# 3. Turn it on in any repository
cd /path/to/some/repo
hookguard init        # optional: writes .hookguard.toml
hookguard install     # writes .git/hooks/pre-commit
hookguard doctor --smoke   # checks Ollama + model and sends a tiny test review
```

Other commands:

```bash
hookguard run                 # review what's staged right now (what the hook calls)
hookguard run --no-llm        # secrets + static rules only (instant)
hookguard scan src/           # review whole files/folders, e.g. for a demo
hookguard run --json          # machine-readable output
hookguard uninstall
git commit --no-verify        # bypass once
HOOKGUARD_SKIP=1 git commit   # bypass via env
```

Mark a known false positive by ending the line with `# hookguard: ignore`.

### Using llama.cpp instead of Ollama

```bash
llama-server -m qwen2.5-coder-3b-instruct-q4_k_m.gguf --port 8080 -c 8192
HOOKGUARD_BACKEND=llamacpp hookguard doctor --smoke
```
or set `backend = "llamacpp"` in `.hookguard.toml`.

### Using it with the `pre-commit` framework

```yaml
# .pre-commit-config.yaml in the target repo
repos:
  - repo: local
    hooks:
      - id: hookguard
        name: hookguard
        entry: hookguard run
        language: system
        pass_filenames: false
```

## Configuration

`hookguard init` writes a fully commented `.hookguard.toml`. The important keys:

```toml
block_on = "high"              # low | medium | high | critical
exclude  = ["tests/fixtures/*"]

[llm]
backend = "ollama"             # or "llamacpp"
model = "qwen2.5-coder:3b"
min_severity = "medium"        # ignore model findings below this
can_block = true               # false = model findings only warn
on_error = "warn"              # or "block" (fail closed)
total_timeout = 120            # seconds for the whole LLM stage
```

Environment overrides: `HOOKGUARD_MODEL`, `HOOKGUARD_HOST`, `HOOKGUARD_BACKEND`, `HOOKGUARD_NO_LLM=1`, `HOOKGUARD_SKIP=1`.

## Tests and evaluation

```bash
pytest                                   # 28 tests, incl. real git commits against a fake Ollama server
python eval/run_eval.py                  # static-only baseline
python eval/run_eval.py --models qwen2.5-coder:1.5b qwen2.5-coder:3b qwen2.5-coder:7b
```

The eval compares three modes on a labelled dataset (`eval/cases`, `eval/labels.json`):
`static` (no model), `llm` (model alone) and `hybrid` (the real tool), reporting precision,
recall, F1, false positives, latency (mean / p95) and how many model findings were dropped
as hallucinated line numbers. Current static baseline on the seed set: precision 1.00,
recall 0.54. The six cases it misses (SQL built outside `execute`, path traversal, auth
bypass, SSRF, MD5 passwords, unverified JWT) are what the LLM layer has to earn its keep on.

## Project layout

```
src/hookguard/
  cli.py        commands
  diff.py       git plumbing + unified-diff parser (tracks new-file line numbers)
  secrets.py    secret regexes, entropy, placeholder filter, redaction
  rules.py      static anti-pattern rules per language
  llm.py        Ollama + llama.cpp clients (stdlib HTTP, proxies bypassed)
  prompts.py    system prompt tuned for small models
  reviewer.py   chunking, prompting, JSON parsing, line validation, cache
  engine.py     the pipeline and block/allow verdict
  report.py     terminal output
  hook.py       hook install/uninstall
tests/          unit + end-to-end tests (fake Ollama server, no model needed)
eval/           labelled dataset + metrics script
```

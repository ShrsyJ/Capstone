# Experiments log

Every prompt version and ablation, with its scores. Raw per-case output is in
`eval/results/<timestamp>.json`; that folder is git-ignored, so the tables below are the
record of what each run produced.

## How to read the numbers

- **Split.** Phase 1 uses the 23 hand-written toy cases (`eval/cases`) as the **dev split**.
  Prompts were tuned on them, so **none of these are held-out results**. Held-out test
  numbers will come from the Phase 2 dataset.
- **Block-level** precision and recall ask "did the hook block the right commits?" This is
  what a developer experiences.
- **Strict recall** asks "was a positive blocked *for the right reason*?" A blocking
  finding must have the labelled category (or an accepted alternative) **on a labelled
  line**, meaning the vulnerable sink or the line where untrusted input enters it. This
  metric was added after the 1.5B model scored block-level recall 1.00 by flagging almost
  every file as "injection".
- **Strict precision** is the share of blocked commits that were blocked for the right
  reason.
- **FP rate** is the share of clean cases that were blocked. There are 10 clean cases, so
  **one case = 0.1**. Differences of 0.1 are a single file and should not be presented as
  meaningful.
- **Determinism.** temperature = 0 and seed = 7, so quality numbers are reproducible for
  a given model, prompt and Ollama version. Latency is not.
- **Modes.** `llm` is the model alone (secret and static layers off). `hybrid` is the real
  tool.

Setup: Apple M3, 8 GB RAM, macOS 26.5, Ollama 0.40.16, Q4_K_M weights (Ollama defaults),
num_ctx 8192.

## Static baseline (no model)

| mode | precision | recall | strict recall | FP rate |
|---|---|---|---|---|
| static | 1.00 | 0.54 | 0.54 | 0.0 |

It misses p08 (SQL built with `%` and then executed), p09 (path traversal), p10 (auth
bypass), p11 (SSRF), p12 (MD5 passwords) and p13 (JWT decoded without verification).

## Prompt iterations (dev split)

| prompt | model | mode | strict recall | strict precision | FP rate | block recall |
|---|---|---|---|---|---|---|
| v1 | qwen2.5-coder:1.5b | llm | 0.69 | 0.47 | 0.6 | 1.00 |
| v1 | qwen2.5-coder:1.5b | hybrid | 0.85 | 0.58 | 0.6 | 1.00 |
| v2 | qwen2.5-coder:1.5b | llm | 0.54 | 0.37 | 0.7 | 0.92 |
| v2 | qwen2.5-coder:1.5b | hybrid | 0.77 | 0.53 | 0.7 | 0.92 |
| v3 | qwen2.5-coder:1.5b | llm | 0.69 | 0.56 | 0.5 | 0.85 |
| v3 | qwen2.5-coder:1.5b | hybrid | 0.77 | 0.63 | 0.5 | 0.85 |
| v1 | qwen2.5-coder:3b | llm | 0.54 | 0.39 | 0.6 | 0.92 |
| v1 | qwen2.5-coder:3b | hybrid | 0.69 | 0.50 | 0.6 | 0.92 |
| v2 | qwen2.5-coder:3b | llm | 0.38 | 0.28 | 0.5 | 1.00 |
| v2 | qwen2.5-coder:3b | hybrid | 0.69 | 0.50 | 0.5 | 1.00 |
| **v3** | **qwen2.5-coder:3b** | llm | **0.85** | **0.85** | **0.2** | 0.85 |
| **v3** | **qwen2.5-coder:3b** | hybrid | **0.85** | **0.85** | **0.2** | 0.85 |
| v3 | qwen3:4b (think off) | llm | 0.62 | 1.00 | 0.0 | 0.62 |
| v3 | qwen3:4b (think off) | hybrid | 0.69 | 1.00 | 0.0 | 0.69 |

The v1 and v2 runs on 3B were made from git worktrees of commit `206b149`, so each
version ran with its own code. v2 was never committed; its exact text is reproduced in
the history comment in `src/hookguard/prompts.py` and described below.

### v1: prototype prompt
- **Failure mode, 1.5B:** almost every file gets exactly one `high` / `injection` finding.
  Parameterised SQL (n03, n09), bcrypt (n10) and `ast.literal_eval` (n08) were all called
  injection. MD5 (p12) and JWT (p13) were "found", but labelled injection.
- **Line numbers:** mostly right, with some off-by-one errors (p06; the smoke test flagged
  line 2 instead of 3).

### v2: "source + sink" rule and a list of SAFE idioms. **Rejected**
- **Hypothesis:** telling the model what is *not* a bug (parameterised queries, env-var
  reads, `safe_load`, bcrypt, `subprocess` with an argument list) cuts false positives.
- **Result:** worse on both models. On 1.5B the FP rate went from 0.6 to 0.7; on 3B
  strict recall went from 0.54 to 0.38. Small models **echoed the list back** ("Untrusted
  input used in a file path without checking it stays inside the intended folder" on
  safe YAML code), and the longer prompt was slower.
- **Lesson:** for 1–3B models, extra instructions give them more text to copy, not more
  understanding.

### v3: message-first schema, closed category enum, neutral example. **Kept**
- **Hypothesis 1:** the JSON schema asked for `category` and `severity` *before*
  `message`. Ollama generates fields in schema order, so the model committed to a label
  before explaining it. 1.5B often wrote a correct message ("Hardcoded AWS access key
  ID") under a wrong category ("injection").
- **Hypothesis 2:** the prompt's only example was a `high` / `injection` finding, which
  the model copied.
- **Change:** the schema order is now line → message → category → severity → suggestion,
  `category` is limited to the 8 allowed values, and the example is a neutral template
  shown after the empty answer `{"findings": []}`.
- **Result:** a large gain on 3B (strict recall 0.54 → 0.85, FP rate 0.6 → 0.2) and a small
  one on 1.5B (FP rate 0.6 → 0.5, a single case).
- **Side effect seen on our own repo:** the enum forces a valid category even for a
  nonsense finding. Example: "crypto: Ollama reports durations in nanoseconds", a code
  comment echoed back. It was only `medium`, so it warned and did not block.

### Why prompt tuning stopped at v3
The remaining 1.5B errors are comprehension failures, not formatting failures ("SQL
injection via ast.literal_eval"; "bcrypt password hash is a secret"). Fixing them with
case-specific instructions would mean fitting the prompt to 23 dev cases. That doesn't
generalise, and it would inflate dev scores.

## Model-specific findings

### qwen3:4b needs `think = false`
With Ollama's default (thinking on), qwen3:4b generated more than 668 tokens of reasoning
for `x = 1` and hit the 120 s timeout. With `think: false` it answered in 0.7 s. Ollama
also accepts `think: false` for non-thinking models (checked on qwen2.5-coder:1.5b), so
hookguard now sends it by default (`llm.think = false`).

### qwen3:4b misses context-dependent bugs
With thinking off it is very conservative: zero false positives, but it missed p10 (auth
bypass), p11 (SSRF), p12 (MD5 passwords), p13 (unverified JWT) and p02 (DB URL). These
are exactly the context-dependent categories the research question is about. Thinking
would probably help, but it is unaffordable in a hook on this hardware.

### 7B does not fit
qwen2.5-coder:7b is 4.7 GB of weights plus about 0.5 GB of KV cache at 8k context. On an
8 GB Mac, even qwen3:4b (3.8 GB resident) caused continuous paging while idle (about
150 MB in and 230 MB out per 30 s). 7B was therefore not run.

## Latency and memory

Earlier latency numbers in Phase 1 are **not valid**: a model download and an
already-swapping system inflated them. For example, 3B time per positive case drifted
from 4 s to 10 s within one run with no change in output length. The eval now unloads
other models before each run and records swap traffic during it (`paging_mb`). Runs
with more than 200 MB of paging are flagged.

### Clean run: prompt v3, all models (2026-11-15, `eval/results/20261115-121327`)

Each model ran alone; others were unloaded first. Quality scores were **identical** to the
earlier runs of the same prompt and model, which is a check that the eval is
deterministic.

| model | mode | resident RAM | gen tok/s | latency mean | latency p95 | paging during run | valid? |
|---|---|---|---|---|---|---|---|
| qwen2.5-coder:1.5b | llm | 1.37 GB | 28.8 | 1.8 s | 2.5 s | 238 MB | borderline |
| qwen2.5-coder:1.5b | hybrid | 1.37 GB | 28.1 | 1.2 s | 2.5 s | 45 MB | yes |
| qwen2.5-coder:3b | llm | 2.32 GB | 16.2 | 2.9 s | 4.7 s | 39 MB | yes |
| qwen2.5-coder:3b | hybrid | 2.32 GB | 16.3 | 1.7 s | 4.3 s | 89 MB | yes |
| qwen3:4b | llm | 3.81 GB | 11.6 | 3.9 s | 11.2 s | 2274 MB | **no** |
| qwen3:4b | hybrid | 3.81 GB | 11.8 | 1.5 s | 6.7 s | 768 MB | **no** |

Per-case breakdown (3B, model alone): clean files take a median of **0.9 s**, because the
answer is just `{"findings": []}`. Files with a finding take a median of **3.9 s**,
dominated by about 60 output tokens at 16 tok/s. Latency is mostly **output length**,
which favours prompts and schemas that keep findings short. In hybrid mode, files the
static layer already blocks take about 0 s, because the model is skipped.

**Caveats that must go in the report:**
- Every case is a single file of 3–10 lines. Real commits are bigger. hookguard
  reviewing one of its own 4-file commits took about 26 s, sequentially and with swap
  active, so it is an upper bound but far over 5 s. Phase 2's real diffs will give
  honest numbers; Phase 4's parallel requests and context-size work target this.
- qwen3:4b's latency can't be measured cleanly on 8 GB. At 3.8 GB resident the system
  pages heavily, so its numbers show what a user of this laptop would actually get, not
  the model's intrinsic speed.

## Dogfooding: hookguard on its own commits

The hook is installed in this repo, using qwen2.5-coder:3b and the default config.

| commit | what happened | action |
|---|---|---|
| eval token timings (4 files) | ~26 s total, files reviewed one after another while the machine was swapping; 2 `medium` warnings, both nonsense ("crypto: Ollama reports durations in nanoseconds") | none (warnings don't block); logged |
| Phase 1 docs | **blocked**: a `high` "injection" on a line of `docs/AI_LOG.md` that *describes* labelled vulnerable lines; a `medium` "hardcoded model version" on `ROADMAP.md` | fixed: prose files (`.md .rst .txt .adoc`) skip the model but are still secret-scanned (`llm.skip_extensions`) |

## Open questions after Phase 1
1. Is 3B's 0.2 FP rate (2 of 10 clean cases) real or noise? Only Phase 2's larger set of
   negatives can say.
2. Would a smaller `num_ctx` (e.g. 4096) cut RAM enough to make qwen3:4b usable? This is
   an ablation for Phase 4. Changing `num_ctx` forces a model reload (about 4 s), so
   compare warm runs only.
3. qwen3.5:4b (3.3 GB, newer) exists in the Ollama library. It's worth one run if Phase 2
   shows qwen3:4b's misses are systematic.

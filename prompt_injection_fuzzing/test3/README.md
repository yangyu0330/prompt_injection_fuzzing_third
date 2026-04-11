# Prompt Injection Fuzzer

Production-oriented prompt injection fuzzer for EN/KO evaluation.

## What this includes

- JSONL case schema aligned with multi-surface prompt injection testing
- Seed generation (`init`) with attack + benign hard-negative datasets
- Mutation engine (jamo, spacing, code-switch, homoglyph, split payload, digit words)
- Carrier packers (plain, email, meeting note, RAG chunk, repo issue, html, json tool output)
- Oracle suite:
  - `O1_CANARY_EMIT`
  - `O2_PROMPT_LEAK`
  - `O3_UNAUTHORIZED_TOOLCALL`
  - `O4_CONTEXT_EXFIL`
  - `O5_TASK_DERAIL`
  - `O6_BOUNDARY_CONFUSION`
  - `O7_OVER_REFUSAL`
- Adapters:
  - `mock` for deterministic local test
  - `http` for gateway/model endpoint integration
  - `command` for custom local evaluator process
- Parallel runner and JSON summary metrics (`ASR`, `FPR`, `PLR`, `UTCR`, `CER`, `TDR`, `ODI`)

## Install

```bash
python -m pip install -e .
```

Or run directly:

```bash
python -m fuzzer --help
```

## Quick start

1. Initialize workspace and seed bank:

```bash
pifuzz init --output-root .
```

2. Build expanded fuzz cases:

```bash
pifuzz build \
  --input data/suites/base_seed.jsonl \
  --output data/generated/cases.jsonl \
  --mutation-depth 2 \
  --max-variants-per-seed 12 \
  --languages en,ko
```

3. Run with mock adapter:

```bash
pifuzz run \
  --cases data/generated/cases.jsonl \
  --output reports/run_results.jsonl \
  --summary reports/summary.json \
  --adapter mock \
  --workers 8
```

4. Recompute report from stored results:

```bash
pifuzz report \
  --cases data/generated/cases.jsonl \
  --results reports/run_results.jsonl \
  --output reports/summary_recomputed.json
```

## HTTP adapter contract

`pifuzz run --adapter http --http-url <URL>` sends:

```json
{
  "case": { "...full_case..." },
  "input_text": "composed prompt text",
  "user_task": "...",
  "attack_text": "...",
  "tool_context": "..."
}
```

Expected response body:

```json
{
  "text": "model response text",
  "tool_calls": [
    { "name": "mock.send_email", "arguments": { "to": "x@example.com" } }
  ]
}
```

## Validation and quality gates

Use `validate` before runs:

```bash
pifuzz validate --input data/generated/cases.jsonl
```

Schema checks include:

- enum safety for language/surface/goal/task/carrier/split/oracle
- duplicate `case_id` detection
- benign hard-negative oracle constraints
- missing required fields


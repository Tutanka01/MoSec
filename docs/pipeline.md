# MoSec Pipeline — Technical Reference

## Table of Contents

1. [Overview](#1-overview)
2. [Data Flow](#2-data-flow)
3. [Phase 0 — Ingestion](#3-phase-0--ingestion)
4. [Phase 1 — Triage](#4-phase-1--triage)
5. [Phase 2 — Taint Specification](#5-phase-2--taint-specification)
6. [Phase 3 — Data Flow Verification](#6-phase-3--data-flow-verification)
7. [Phase 4 — Exploit Hypothesis](#7-phase-4--exploit-hypothesis)
8. [Phase 5 — Report Generation](#8-phase-5--report-generation)
9. [Resuming from a Phase](#9-resuming-from-a-phase)
10. [LLM Interaction Patterns](#10-llm-interaction-patterns)
11. [CI/CD Pipeline](#11-cicd-pipeline)

---

## 1. Overview

MoSec is a multi-phase SAST pipeline that combines static analysis engines (Semgrep, CodeQL, tree-sitter) with LLM reasoning to produce **confirmed, exploitable** vulnerabilities — not a raw list of pattern matches.

The pipeline has a single entry point (`pipeline.py`) and six sequential phases (0–5). Each phase persists its output as a JSON file, enabling re-runs from any checkpoint without re-executing earlier phases.

```
Target repo
    │
    ▼
[Phase 0] Ingestion     →  manifest.json
    │
    ▼
[Phase 1] Triage        →  findings.json
    │
    ▼
[Phase 2] Taint Spec    →  taint_specs.json + rule YAMLs
    │
    ▼
[Phase 3] Data Flow     →  confirmed_flows.json
    │
    ▼
[Phase 4] Exploit       →  validated_vulns.json
    │
    ▼
[Phase 5] Report        →  results.sarif + report.md
```

Each phase acts as a funnel: findings that cannot be confirmed are dropped early, keeping the final report signal-to-noise ratio high.

---

## 2. Data Flow

| File | Written by | Read by | Contents |
|---|---|---|---|
| `manifest.json` | Phase 0 | Phase 1, 3 | File list, entry points, dependencies, AST summary, CodeQL DB path |
| `findings.json` | Phase 1 | Phase 2 | Per-file LLM findings with CWE, line, confidence |
| `taint_specs.json` | Phase 2 | Phase 3 | Source/sink/sanitizer triples + Semgrep rule paths |
| `{finding_id}.yaml` | Phase 2 | Phase 3 | Generated Semgrep taint-mode rules, one per finding |
| `confirmed_flows.json` | Phase 3 | Phase 4 | Taint paths verified by ReAct loop + Verifier |
| `validated_vulns.json` | Phase 4 | Phase 5 | Exploitable findings with concrete PoC payloads |
| `results.sarif` | Phase 5 | IDE / GitHub | SARIF 2.1.0 with `codeFlows` evidence traces |
| `report.md` | Phase 5 | Humans | Markdown report sorted by CVSS score |
| `token_usage.json` | Phase 5 | Monitoring | Total prompt/completion/total token counts |
| `pipeline.log` | All | Debugging | Structured log with per-phase reasoning |

All Pydantic schemas for these structures live in `models/schemas.py`.

---

## 3. Phase 0 — Ingestion

**Agent:** `agents/ingestion.py` → `IngestionAgent`

### What it does

Builds a complete structural picture of the target repository before any LLM is involved:

- **File collection** — walks the repo for `.py`, `.js`, `.ts`, `.jsx`, `.tsx`, `.php` files, skipping `node_modules`, `venv`, `__pycache__`, `vendor`, etc.
- **AST extraction** — uses tree-sitter (Python, JavaScript, PHP) to extract function names, class names, and imports per file. Falls back gracefully if tree-sitter packages are missing.
- **Entry point detection** — regex patterns detect HTTP routes (Flask/Express/PHP), file reads, subprocess calls, `eval`/`exec`, and deserialization sinks.
- **Dependency extraction** — parses `requirements.txt`, `pyproject.toml`, and `package.json` to map the dependency graph.
- **CodeQL database** — optionally builds a CodeQL DB for the repository. Degrades gracefully if `codeql` is not in `PATH`.

### Output: `manifest.json`

```json
{
  "repo_path": "/path/to/repo",
  "files": ["src/app.py", "src/auth.py"],
  "entry_points": [
    {"file": "src/app.py", "line": 12, "type": "http_route", "name": "@app.route"}
  ],
  "dependencies": [
    {"name": "flask", "version": "3.0.0", "ecosystem": "pip"}
  ],
  "ast_summary": [...],
  "codeql_db_path": "/path/to/repo/codeql-db"
}
```

---

## 4. Phase 1 — Triage

**Agent:** `agents/triage.py` → `TriageAgent`

### What it does

Performs a **Carlini-sweep** — named after the adversarial evaluation methodology — over every source file independently. For each file:

1. Reads and optionally truncates the file (hard cap: 60 000 chars, keeping beginning + end to preserve function signatures and business logic).
2. Prefixes every line with its line number so the LLM can be precise.
3. Sends a single-shot prompt instructing the LLM to act as an offensive security researcher and return a JSON array of findings with `line`, `cwe`, `description`, and `confidence`.
4. Applies a confidence filter: findings below **0.6** are dropped.

### Prompt design

The system prompt deliberately frames the task as offensive ("find real, exploitable vulnerabilities") to suppress the model's tendency to refuse or add caveats. The instruction "Do NOT say the code is safe" and "Only report what you can PROVE exists in THIS file" reduces hallucinations from other contexts.

### Error handling

`EmptyResponseError` is caught specifically (model returned nothing — context overflow or refusal) and logged with a targeted warning before moving on, rather than treating it as a generic JSON parse failure.

### Output: `findings.json`

```json
[
  {
    "finding_id": "a1b2c3d4-...",
    "file": "src/auth.py",
    "line": 47,
    "cwe": "CWE-89",
    "description": "User-controlled `user_id` concatenated directly into SQL query",
    "confidence": 0.95
  }
]
```

---

## 5. Phase 2 — Taint Specification

**Agent:** `agents/taint_spec.py` → `TaintSpecAgent`

### What it does

For each finding from Phase 1, Phase 2 precisely identifies the **taint flow** and generates a matching Semgrep rule:

1. **AST candidate extraction** (`utils/ast_extractor.py`) — uses tree-sitter to extract all candidate sources (user-controlled inputs) and sinks (dangerous callsites) in the file. These are passed to the LLM as a grounded list so it selects from real names rather than inventing them.

2. **LLM taint analysis** — the LLM receives the code context (±50 lines around the finding) plus the AST candidates, and returns:
   - `source`: the exact variable/function where untrusted data enters
   - `sink`: the named callable where it becomes dangerous (never an f-string or expression — enforced in the prompt)
   - `sink_kind`: one of `call`, `method_call`, `property_assignment`, `subscript_assignment`
   - `sanitizers`: list of functions that might clean the data
   - `taint_path_summary`: one-sentence description of the flow

3. **Semgrep rule generation** (`utils/sast.py` → `generate_semgrep_rule`) — generates a taint-mode YAML rule using `sink_kind`-aware pattern templates and runs `semgrep --validate` before writing it to disk. Invalid rules are logged and skipped rather than written.

### Sink kind patterns

| `sink_kind` | Semgrep pattern |
|---|---|
| `call` | `{sink}(...)` |
| `method_call` | `$X.{sink}(...)` |
| `property_assignment` | `$X.{sink} = $TAINT` |
| `subscript_assignment` | `$X[...] = $TAINT` |

### Output: `taint_specs.json` + rule YAMLs

```json
[
  {
    "finding_id": "a1b2c3d4-...",
    "source": "request.args.get",
    "sink": "cursor.execute",
    "sink_kind": "method_call",
    "sanitizers": [],
    "taint_path_summary": "user_id from query string flows directly into cursor.execute",
    "semgrep_rule_path": "/tmp/audit_rules/a1b2c3d4.yaml",
    "source_line": 44,
    "sink_line": 47
  }
]
```

---

## 6. Phase 3 — Data Flow Verification

**Agents:** `agents/dataflow.py` → `DataFlowAgent` + `agents/verifier.py` → `VerifierAgent`

This is the most complex phase. It combines a **ReAct loop** for evidence gathering with a **three-stage verification** for the final verdict.

### 6.1 ReAct Loop (`DataFlowAgent`)

For each taint spec, the agent runs up to **5 iterations** of Reason → Act → Observe:

**Available actions:**

| Action | What it does |
|---|---|
| `run_semgrep` | Executes the generated Semgrep rule against the file |
| `grep_sanitizers` | Regex-greps the file for sanitizer patterns |
| `read_context` | Reads a wider code slice (±80 lines, or a custom range) |
| `run_codeql` | Runs an inline CodeQL TaintTracking query against the DB |
| `conclude` | Ends the loop and hands off to the Verifier |

**Deduplication:** if the LLM repeats an already-played `(action, param)` pair, the iteration is not consumed — instead a synthetic "DEDUP: action already performed" observation is injected so the model understands why it was skipped.

**Evidence format (`StructuredEvidence`):** each observation is stored both as raw text and as a typed struct with `kind` (`semgrep_matches`, `grep_hits`, `code_slice`, `codeql_paths`, `no_flow`) and a list of `CodeLocation` hits. This structured form is used in the SARIF `codeFlows` output.

### 6.2 Verifier — Propose → Falsify → Decide (`VerifierAgent`)

After the ReAct loop, the collected evidence is passed through a three-stage pipeline inspired by VulnSage's ThinkAndVerify strategy:

**Stage 1 — Propose:** the LLM makes an initial verdict (`confirmed` / `sanitized` / `unreachable`) citing specific evidence items.

**Stage 2 — Falsify:** a second prompt adopts an adversarial reviewer role and finds at least 2 concrete weaknesses in the proposed verdict.

**Stage 3 — Decide:** a third prompt weighs the initial verdict against the rebuttals under an explicit burden-of-proof rule:
- `confirmed` requires **affirmative** evidence of exploitability
- `unreachable` is the **default** when evidence is ambiguous

**Fail-closed design:** any LLM or parse failure at any stage defaults to `unreachable`, not `confirmed`.

**Self-consistency (optional):** setting `MOSEC_VERIFIER_N=3` runs the entire Propose → Falsify → Decide chain 3 times independently and takes the majority vote. Use this for maximum precision at the cost of 3× LLM calls.

### Output: `confirmed_flows.json`

```json
[
  {
    "finding_id": "a1b2c3d4-...",
    "source": "request.args.get",
    "sink": "cursor.execute",
    "taint_path_summary": "...",
    "verification_iterations": 3,
    "verification_evidence": [
      {
        "iteration": 1,
        "action": "run_semgrep()",
        "result": "Semgrep matched 1 location: src/auth.py:47",
        "structured": {"kind": "semgrep_matches", "hits": [...]}
      }
    ]
  }
]
```

---

## 7. Phase 4 — Exploit Hypothesis

**Agent:** `agents/exploit.py` → `ExploitAgent`

### What it does

For each confirmed flow, Phase 4 attempts to generate a **concrete proof-of-concept payload** and statically verify it can reach the sink:

1. **LLM PoC generation** — the prompt instructs the model to produce a minimal, specific payload (e.g. `'; DROP TABLE users; --`) rather than a generic description. If the model responds with `{"poc": null, ...}`, the finding is discarded as a false positive.

2. **Static trace** (`_static_trace`) — two-layer verification:
   - **AST-based BFS** (via `utils/ast_extractor.py`) — attempts an intra-procedural control-flow BFS from source to sink. If the extractor is unavailable, falls back to the lexical check.
   - **Lexical check** — scans the containing function body (not a ±30-line window, which could cross function boundaries) for strong sanitizer patterns. A sanitizer is only counted if it appears on the **same line** as the sink variable — preventing false negatives from unrelated `sanitize_input` definitions elsewhere in the file.

   Strong sanitizers recognized: `parameterize`, `prepare`, `escape_string`, `html.escape`, `markupsafe.escape`, `bleach.clean`, `django.utils.html`.

3. Findings that fail the static trace are dropped with a debug log.

### Output: `validated_vulns.json`

```json
[
  {
    "finding_id": "a1b2c3d4-...",
    "cwe": "CWE-89",
    "file": "src/auth.py",
    "line": 47,
    "poc": "1' OR '1'='1",
    "attack_scenario": "Attacker sends id=1' OR '1'='1 to bypass authentication",
    "exploitability": "high"
  }
]
```

---

## 8. Phase 5 — Report Generation

**Agent:** `agents/reporter.py` → `ReporterAgent`

### What it does

For each validated vulnerability:

1. **CVSS 3.1 scoring** — asks the LLM to select metric values (AV/AC/PR/UI/S/C/I/A) given the exploit scenario. The actual base score is computed locally using the analytic CVSS 3.1 formula (`models/schemas.py` → `calculate_cvss31`) — no external service involved. Falls back to a conservative default (`AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`) if the LLM call fails.

2. **SARIF 2.1.0 output** (`results.sarif`) — produces a compliant SARIF file with:
   - `ruleId` = CWE identifier
   - `level` = mapped from CVSS severity (CRITICAL/HIGH → error, MEDIUM → warning, LOW → note)
   - `codeFlows` = the structured evidence from Phase 3 converted to SARIF thread flow locations
   - `properties` = CVSS score, vector string, exploitability

3. **Markdown report** (`report.md`) — one section per finding sorted by CVSS descending, with a summary table, description, attack scenario, PoC, taint flow pointer, and specific remediation.

4. **Token accounting** — writes `token_usage.json` with total prompt/completion/total token counts for the full run.

---

## 9. Resuming from a Phase

Every phase checks whether `start_phase` allows it to run. If skipped, it loads the previous phase's JSON output from `output_dir`.

```bash
# Run phases 4 and 5 only, loading confirmed_flows.json from a previous run
python pipeline.py --repo-path /path/to/repo --phase 4 --output-dir ./output
```

The pipeline will fail fast with a clear error if the required JSON file is missing (it does not silently skip).

**Phase dependency chain:**

```
Phase 0 → manifest.json
Phase 1 → requires manifest.json
Phase 2 → requires findings.json
Phase 3 → requires taint_specs.json + rule YAMLs
Phase 4 → requires confirmed_flows.json
Phase 5 → requires validated_vulns.json
```

---

## 10. LLM Interaction Patterns

All LLM calls go through `utils/llm.py` → `LLMClient`, which wraps any OpenAI-compatible endpoint.

### Retry logic

- Up to 3 attempts with exponential backoff (2s, 4s) on `RateLimitError`, `APIConnectionError`, `APIStatusError`.
- Empty responses (context overflow, model refusal) are retried up to 2 additional times before being returned as-is with a warning.
- Non-transient errors re-raise immediately.

### JSON extraction (`extract_json`)

Six-stage extraction in order of preference:
1. Strip markdown fences (```` ```json ... ``` ````)
2. Direct `json.loads`
3. Find first `[` or `{` and match to last `]` or `}`
4. Fix trailing commas + single quotes
5. Append common closing suffixes for truncated responses (`"}`, `}`, `"}}`)
6. Regex extraction of individual key-value pairs from partially-valid JSON

### Temperature by phase

| Phase | Temperature | Rationale |
|---|---|---|
| 1 — Triage | 0.1 | Light creativity to catch varied patterns |
| 2 — Taint Spec | 0.05 | Near-deterministic source/sink selection |
| 3 — ReAct Reason | 0.05 | Consistent action selection |
| 3 — Verifier Propose | 0.1 | Some variation for self-consistency runs |
| 3 — Verifier Falsify | 0.2 | More creative adversarial critique |
| 3 — Verifier Decide | 0.0 | Fully deterministic final verdict |
| 4 — Exploit | 0.2 | Creative payload generation |
| 5 — CVSS | 0.0 | Deterministic metric selection |

---

## 11. CI/CD Pipeline

The GitHub Actions workflow (`.github/workflows/ci.yml`) runs three parallel jobs on every push to `main` and every pull request.

### Jobs

**`lint`** — Ruff (linter + formatter check)
```bash
ruff check .
ruff format --check .
```
Configuration in `ruff.toml`: pipeline.py is exempted from E402 (imports after `load_dotenv()` is intentional).

**`typecheck`** — mypy
```bash
mypy --ignore-missing-imports agents/ utils/ models/
```

**`security`** — four tools in sequence:

| Tool | Command | Catches |
|---|---|---|
| Bandit | `bandit -r agents/ utils/ models/ -ll -q` | Dangerous Python patterns (medium+ severity) |
| pip-audit | `pip-audit -r requirements.txt` | CVEs in dependencies |
| Semgrep | `semgrep/semgrep-action@v1` with `p/python` + `p/secrets` | OWASP patterns, hardcoded secrets |
| Gitleaks | `gitleaks/gitleaks-action@v2` | Secrets leaked in git history |

### False positive management

- **`benchmarks/cases/`** is listed in `.semgrepignore` — these files are intentionally vulnerable test fixtures, not production code.
- `logger.debug("... tokens: %s")` lines carry `# nosemgrep` — the word "tokens" triggers Semgrep's credential-leak rule but refers to LLM token counts, not API secrets.

### Benchmark gate

The benchmark runner exits with code 1 if F1 score < 0.5, making it suitable as a CI quality gate:
```bash
python -m benchmarks.runner --suite benchmarks/cases --output output/bench_report.json
```
Note: the benchmark runner requires a live LLM endpoint and is not included in the standard CI job (it would need `LLM_BASE_URL`/`LLM_API_KEY` secrets).

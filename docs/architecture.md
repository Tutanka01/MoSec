# Architecture

## Design philosophy

MoSec is built around three principles that distinguish it from traditional SAST tools:

**1. Certainty over coverage.**
Every finding that exits the pipeline has been validated by at least three independent mechanisms — LLM triage, AST-grounded symbolic data-flow (Semgrep/CodeQL/CFG), and a counterfactual PoC that must be constructible by the LLM. If any mechanism cannot confirm a finding, it is dropped. A false negative is acceptable. A false positive wastes an engineer's time and destroys trust in the tool.

**2. Transparency through persistence.**
Every intermediate state is serialised to disk as typed JSON before the next phase starts. This means the pipeline is fully resumable (`--phase N`), fully inspectable, and fully auditable. You can open `confirmed_flows.json` and read exactly what actions were taken in the ReAct loop, what each action returned, and the full Propose-Falsify-Decide reasoning chain that led to each verdict.

**3. Zero external dependencies at runtime.**
All LLM calls go to a local OpenAI-compatible endpoint. No telemetry. No cloud storage. No third-party APIs. The tool is designed to run inside an air-gapped network and to process proprietary codebases without any data leaving the host.

---

## System overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                           pipeline.py                               │
│                                                                     │
│  Orchestrates agents sequentially, loading/saving JSON state        │
│  between phases.  Accepts --phase N to resume from any point.       │
│  Passes consistency_n to DataFlowAgent (MOSEC_VERIFIER_N env var).  │
│                                                                     │
│  LLMClient ──► all agents (single shared instance per run)          │
└──────┬──────────────────────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────────────────┐
│  utils/llm.py  — LLMClient                                          │
│                                                                      │
│  • Wraps openai.OpenAI pointed at local endpoint                     │
│  • Exponential-backoff retry (max 3, delays 2/4/8 s)                │
│  • Empty-response detection with retry (EmptyResponseError)         │
│  • Accumulates token counts across all calls                         │
│  • extract_json(): 4-strategy robust JSON extraction                │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│  utils/sast.py                                                       │
│                                                                      │
│  SemgrepRunner          — run rules, grep_pattern, validate          │
│  CodeQLRunner           — create_database, run_inline_query          │
│  generate_semgrep_rule()— AST-aware taint-mode YAML with validation │
│  to_semgrep_pattern()   — sink_kind-aware pattern generation         │
│  _validate_semgrep_rule()— semgrep --validate before write           │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│  utils/ast_extractor.py                                              │
│                                                                      │
│  TaintCandidateExtractor — stdlib ast (Python), tree-sitter (JS/TS) │
│  SimpleCFG               — intra-procedural def-use graph            │
│  SimpleCFG.taint_bfs()   — BFS from source vars to sink name        │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Data model

Every inter-agent handoff is typed with a Pydantic v2 model defined in `models/schemas.py`. The chain:

```
RepositoryManifest                (Phase 0 → 1)
    │
    └─► list[FileFinding]         (Phase 1 → 2)
             │
             └─► list[TaintSpec]  (Phase 2 → 3)
                  │  now carries: sink_kind, source_line/col, sink_line/col
                  │
                  └─► list[ConfirmedFlow]       (Phase 3 → 4/5)
                       │  evidence: list[VerificationEvidence]
                       │    each: action, result, structured: StructuredEvidence
                       │
                       └─► list[ValidatedVuln]  (Phase 4 → 5)
                                │
                                └─► PipelineReport
                                     ├─ results.sarif  (with codeFlows)
                                     └─ report.md
```

New shared types in `models/schemas.py`:

| Type | Purpose |
|---|---|
| `ReActStep` | Pydantic-validated LLM response for the ReAct reasoning step |
| `StructuredEvidence` | Rich evidence record with `hits: list[CodeLocation]` and summary |
| `CodeLocation` | Precise file/line range for a single evidence hit |
| `TraceResult` | Return value of the AST-based static trace |
| `ASTCandidate` | Source or sink candidate extracted from the AST |

---

## Phase 0 — Ingestion

**Input:** repository path (local or to be cloned)
**Output:** `manifest.json` (`RepositoryManifest`)

### File collection

Recursively walks the repository, collecting `.py`, `.js`, `.ts`, `.jsx`, `.tsx` files. Excludes `node_modules`, `__pycache__`, `.git`, `dist`, `build`, `.venv`, `site-packages` to avoid analysing vendored or compiled code.

### AST extraction (tree-sitter)

For each source file, a tree-sitter parser generates a concrete syntax tree. The agent walks the tree to extract function/class/import names. Falls back gracefully when tree-sitter packages are absent.

### Entry point extraction (regex)

Detected via per-language regex pattern sets applied line-by-line — intentionally simpler than AST-based detection for speed and resilience to partial syntax. Covers Flask/FastAPI/Django/Express routes, subprocess, eval, pickle, yaml.load, innerHTML, child_process.

### CodeQL database

Attempts to build a CodeQL database for the dominant language. Fails gracefully if the binary is absent or times out.

---

## Phase 1 — Triage (Carlini Sweep)

**Input:** `RepositoryManifest`
**Output:** `findings.json` (`list[FileFinding]`)

Per-file isolation — each file is analysed independently. Files > 60K characters are truncated (first 30K + last 30K). Code is sent with explicit 5-digit line numbers. Findings with `confidence < 0.6` are hard-filtered before any downstream work.

---

## Phase 2 — Taint Specification (AST-Grounded)

**Input:** `list[FileFinding]`
**Output:** `taint_specs.json` (`list[TaintSpec]`) + Semgrep rule YAMLs

### AST candidate extraction (new)

Before calling the LLM, `TaintCandidateExtractor.extract()` scans the code with the stdlib `ast` module (Python) or tree-sitter (JS/TS) to produce a structured list of source/sink candidates with line/column coordinates and sink kinds.

This list is passed to the LLM in the prompt so it **selects from grounded positions** rather than inventing function names:

```
AST-extracted candidates (prefer these over guessing):
  Sources:
    - request.args.get (line 42) → var user_id
  Sinks:
    - innerHTML [property_assignment] (line 87) ← var rendered
```

### sink_kind-aware Semgrep rule generation (fixed)

`generate_semgrep_rule()` now accepts a `sink_kind` parameter and uses a pattern template table:

| sink_kind | Semgrep pattern |
|---|---|
| `call` | `{name}(...)` |
| `method_call` | `$X.{name}(...)` |
| `property_assignment` | `$X.{name} = $TAINT` |
| `subscript_assignment` | `$X[...] = $TAINT` |

This eliminates the old `to_semgrep_pattern()` bug that turned `user['id']` into the invalid `user['id'](...)` and `innerHTML` into the nonsensical `innerHTML(...)`.

Every generated rule is validated with `semgrep --validate` before being written to disk. If validation fails, a simpler `pattern-regex` fallback rule is emitted — no invalid YAML ever reaches Phase 3.

---

## Phase 3 — Data Flow Verification (ReAct + Template Pre-Pass + VerifierAgent)

**Input:** `list[TaintSpec]`
**Output:** `confirmed_flows.json` (`list[ConfirmedFlow]`)

### Deterministic pre-pass: TemplateInjectionDetector (new)

Before the LLM ReAct loop, a deterministic structural detector runs a
CodeQL-style **additional taint step** analysis for JavaScript template literals.

**What it catches:**

```javascript
const query = req.query.q;                    // source
const html = `<script>                        // template taint step
  element.innerHTML = '${query}';             // DOM op inside server string
</script>`;
res.send(html);                               // real server-side sink
```

Semgrep and naive LLM analysis miss this because `innerHTML` appears inside a
string literal — not as a real property assignment in the server-side AST.
The `TemplateInjectionDetector` recognises the `${source_var}` → `res.send(html)`
pattern and injects structural evidence as `iteration=0` before the LLM loop.

**Algorithm:**
1. Extract all variables assigned from the declared source
2. Scan for `${source_var}` interpolations in backtick strings
3. Scan for `res.send(template_var)` / `res.write(...)` output calls
4. Check for XSS sanitizers (`DOMPurify`, `encodeURIComponent`, `htmlspecialchars`, …)
5. If steps 2+3 match and step 4 finds no sanitizer → inject `StructuredEvidence`

This implements the "additional taint step" concept from CodeQL's JavaScript
taint-tracking library (Avgustinov et al., 2016).

### ReAct loop

Each finding gets a loop of up to 5 iterations. Key improvements over the original:

**Validated action schema (new):** the LLM response is parsed into a `ReActStep` Pydantic model. Unknown action names (e.g. `"run_pylint"`) are replaced with `"conclude"` rather than silently burning an iteration. On schema validation failure, the agent retries once with the error message surfaced to the model.

**Action deduplication (new):** a `played: set[tuple[str, str]]` tracks (action, param) pairs. If the LLM repeats an already-performed action, it receives a `DEDUP` observation and the iteration budget is not consumed, forcing the model to try something different.

**Structured evidence (new):** each `VerificationEvidence` now carries a `StructuredEvidence` with `hits: list[CodeLocation]` (precise file/line/snippet) in addition to the raw text. This feeds into SARIF `codeFlows` and prevents the silent truncation of evidence to 300 characters.

**Template literal knowledge in `_REASON_PROMPT` (new):** the reasoning prompt
carries explicit instruction that `${expr}` in backtick strings propagates taint,
and that DOM operations inside server-sent HTML strings are server-side XSS.

**CodeQL query (improved):** the `_act_codeql` action now uses different query strategies based on `sink_kind` — a TaintTracking query for function calls, and an assignment-based query for property assignments.

```
[Pre-pass] TemplateInjectionDetector.detect(file, source, sink)
  → if match: inject iteration=0 StructuredEvidence

Iteration 1..5:
  REASON: LLM → ReActStep (validated)
    - if action already in played → inject DEDUP observation, don't consume iteration
  ACT:    execute chosen action → (str, StructuredEvidence)
  OBSERVE: store VerificationEvidence with structured hits
  →  stop early if action == "conclude"

After loop:
  VerifierAgent.verify(spec, evidence) → verdict
```

### VerifierAgent — Propose → Falsify → Decide (new)

Replaces the single-prompt `_conclude()` with a three-stage pipeline inspired by VulnSage's ThinkAndVerify strategy:

1. **Propose:** LLM makes an initial verdict, citing specific evidence items by iteration number.
2. **Falsify:** A second, adversarial prompt asks the model to find at least two reasons the initial verdict could be wrong. This is the red-team step.
3. **Decide:** A third prompt weighs both sides. The burden-of-proof rule is explicit: confirm only if there is affirmative evidence that untrusted data flows to the sink AND no sanitizer is on the path. Ambiguous evidence defaults to `"unreachable"`.

**Fail-closed (fixed):** any LLM failure in the Decide stage returns `"unreachable"`. The old code defaulted to `"confirmed"` — creating a false positive on every LLM failure.

**Self-consistency (optional):** set `MOSEC_VERIFIER_N=3` to run the full Propose-Falsify-Decide cycle N times and take the majority vote (reduces FPR by ~18-25% at 3× the verify cost).

---

## Phase 4 — Exploit Hypothesis

**Input:** `list[ConfirmedFlow]`
**Output:** `validated_vulns.json` (`list[ValidatedVuln]`)

### PoC generation

Unchanged from original — the LLM must produce a minimal, concrete payload or declare `{"poc": null, "reason": "..."}` (false positive). The "real CVE" framing activates the model's knowledge of specific exploitation techniques.

### AST-based static trace (new)

The `_static_trace()` method now has three layers:

**Layer 1 — AST CFG BFS (primary):**
`TaintCandidateExtractor.get_cfg()` builds an intra-procedural def-use graph for the function containing the finding. `SimpleCFG.taint_bfs()` searches for a path from source variables to the sink, respecting barrier (sanitizer) functions.

Example: for `user_id = request.args.get('id')` / `cursor.execute(query)`, the CFG records `user_id ← {request}` and `query ← {user_id}`, and `execute ← {query}`, so BFS from `{user_id, get}` to `execute` returns `(reachable=True, path=['user_id → query', 'query → execute'])`.

**Layer 2 — Lexical fallback (improved):**
When AST analysis cannot determine source variables (e.g. the source is in an imported module), falls back to a lexical check. Key improvement: the sanitizer window is now scoped to the **containing function body** (detected via indentation/braces), not a fixed ±30-line window. A sanitizer pattern only kills a finding when it appears on the **same line** as the sink — preventing false kills from `def sanitize_input()` definitions elsewhere in the file.

**Returns `TraceResult(reachable, reason, path)`** — a typed object rather than a bare bool, allowing the reporter to embed the trace path in SARIF `codeFlows`.

---

## Phase 5 — Report

**Input:** `list[ValidatedVuln]` + `list[ConfirmedFlow]`
**Output:** `results.sarif`, `report.md`, `pipeline_report.json`

### CVSS 3.1 scoring

Unchanged — LLM selects metric values, Python computes the score from the specification formula.

### SARIF 2.1.0 with codeFlows (new)

The reporter now receives `confirmed_flows` and builds `codeFlows[].threadFlows` from `VerificationEvidence.structured.hits`. Each hit carries a precise `CodeLocation` (file, line_start, line_end, snippet), making the taint trace navigable in any SARIF-aware viewer (VS Code, GitHub Code Scanning).

```json
"codeFlows": [{
  "message": {"text": "Taint flow verified in 3 ReAct iteration(s)"},
  "threadFlows": [{
    "locations": [
      {"location": {"physicalLocation": {"region": {"startLine": 42}},
                    "message": {"text": "[run_semgrep()] src/auth.py:42 — CWE-89 match"}}},
      {"location": {"physicalLocation": {"region": {"startLine": 47}},
                    "message": {"text": "[grep_sanitizers()] No sanitizers found"}}}
    ]
  }]
}]
```

---

## Quality assurance — Benchmark harness

**Location:** `benchmarks/`

A ground-truth benchmark suite for measuring pipeline quality end-to-end:

```
benchmarks/
  runner.py                    # P/R/F1 runner, CI gate (F1 ≥ 0.5)
  cases/
    tp_flask_xss.py            # True Positive: Flask XSS (CWE-79)
    tp_flask_sqli.py           # True Positive: SQL injection (CWE-89)
    tp_flask_cmdi.py           # True Positive: command injection (CWE-78)
    tp_flask_path_traversal.py # True Positive: path traversal (CWE-22)
    tp_js_xss.js               # True Positive: server-side template injection → XSS (CWE-79)
    tp_php_cmdi.php            # True Positive: PHP shell_exec injection (CWE-78)
    tp_php_sqli.php            # True Positive: PHP mysqli_query injection (CWE-89)
    tp_php_xss.php             # True Positive: PHP echo XSS (CWE-79)
    fp_flask_xss_escaped.py    # False Positive: html.escape applied
    fp_flask_sqli_parameterized.py # False Positive: parameterized query
    fp_flask_cmdi_shlex.py     # False Positive: shlex.quote applied
    fp_php_sqli_prepared.php   # False Positive: PHP prepared statement
    edge_interproc_xss.py      # Edge: inter-procedural source → sink
    edge_sanitizer_bypass.py   # Edge: conditional sanitizer bypass
```

Run: `python -m benchmarks.runner --suite benchmarks/cases`

Reports per-CWE and per-difficulty (normal / hard) breakdown. Exit code 1 if F1 < 0.5 (CI gate).

### Known failure mode: `tp_js_xss.js` (fixed in this version)

**Symptom**: Phase 3 incorrectly dropped the finding with verdict `"unreachable"`.

**Root cause**: The sink was identified as `innerHTML`, a DOM property that
appears only inside a server-side template literal string. Semgrep rules for
`$X.innerHTML = $TAINT` did not match because there is no real property
assignment in the server-side AST. The LLM reasoned that `innerHTML` is a
client-side DOM operation and concluded the flow was unreachable in Node.js code.

**Fix**: `TemplateInjectionDetector` pre-pass + updated prompts in Phase 2/3/4.
See `docs/taint-analysis-design.md §7` for full root cause analysis.

---

## Error handling

The pipeline follows **fail-soft** at the finding level and **fail-hard** at the structural level:

- LLM call fails after retries → skip that finding, continue
- JSON parse fails → fallback struct or skip; never silent propagation
- Semgrep not installed → `run_semgrep` returns empty result
- CodeQL not installed → `run_codeql` returns empty result
- Phase input JSON missing when resuming → **abort**
- Pydantic validation fails when loading a phase output → **abort**
- **VerifierAgent LLM failure → verdict defaults to `"unreachable"` (fail-closed)**

The last point is a hard security invariant: the pipeline must never produce false positives as a side-effect of infrastructure failures.

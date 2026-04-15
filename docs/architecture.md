# Architecture

## Design philosophy

MoSec is built around three principles that distinguish it from traditional SAST tools:

**1. Certainty over coverage.**
Every finding that exits the pipeline has been validated by at least three independent mechanisms — LLM triage, symbolic data-flow (Semgrep/CodeQL), and a static reachability trace of a concrete PoC payload. If any mechanism cannot confirm a finding, it is dropped. A false negative is acceptable. A false positive wastes an engineer's time and destroys trust in the tool.

**2. Transparency through persistence.**
Every intermediate state is serialised to disk as typed JSON before the next phase starts. This means the pipeline is fully resumable (`--phase N`), fully inspectable, and fully auditable. You can open `taint_specs.json` and read exactly what the LLM concluded about each finding, including the reasoning that led it there.

**3. Zero external dependencies at runtime.**
All LLM calls go to a local OpenAI-compatible endpoint. No telemetry. No cloud storage. No third-party APIs. The tool is designed to run inside an air-gapped network and to process proprietary codebases without any data leaving the host.

---

## System overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                           pipeline.py                               │
│                                                                     │
│  Orchestrates six agents sequentially, loading/saving JSON state    │
│  between phases.  Accepts --phase N to resume from any point.       │
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
│  • Accumulates token counts across all calls                         │
│  • extract_json(): 4-strategy robust JSON extraction                │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│  utils/sast.py                                                       │
│                                                                      │
│  SemgrepRunner     — run rules, grep_pattern, grep_pattern_repo      │
│  CodeQLRunner      — create_database, run_inline_query               │
│  generate_semgrep_rule() — build taint-mode YAML from source/sink   │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Data model

Every inter-agent handoff is typed with a Pydantic v2 model defined in `models/schemas.py`. The chain:

```
RepositoryManifest          (Phase 0 → 1)
    │
    └─► list[FileFinding]   (Phase 1 → 2)
             │
             └─► list[TaintSpec]        (Phase 2 → 3)
                      │
                      └─► list[ConfirmedFlow]   (Phase 3 → 4)
                               │
                               └─► list[ValidatedVuln]   (Phase 4 → 5)
                                        │
                                        └─► PipelineReport
                                                 ├─ results.sarif
                                                 └─ report.md
```

Strict Pydantic validation happens at each phase load boundary. If a JSON file is corrupt or from an incompatible version, the pipeline refuses to continue rather than silently proceeding with bad data.

---

## Phase 0 — Ingestion

**Input:** repository path (local or to be cloned)
**Output:** `manifest.json` (`RepositoryManifest`)

### File collection

Recursively walks the repository, collecting `.py`, `.js`, `.ts`, `.jsx`, `.tsx` files. Excludes `node_modules`, `__pycache__`, `.git`, `dist`, `build`, `.venv`, `site-packages` to avoid analysing vendored or compiled code.

### AST extraction (tree-sitter)

For each source file, a tree-sitter parser generates a concrete syntax tree. The agent walks the tree recursively to extract:
- **Function definitions** (Python: `function_definition`, `async_function_definition`; JS: `function_declaration`, `method_definition`, `arrow_function`)
- **Class definitions**
- **Import statements**

If tree-sitter is not installed, AST summaries are skipped and the pipeline continues with empty summaries. AST data is used primarily to give the LLM structural context about a file.

### Entry point extraction (regex)

Entry points are detected via per-language regex pattern sets applied line-by-line. This is intentionally simpler than AST-based detection: regex is faster, more readable, and handles partial/invalid syntax that tree-sitter would reject.

Python patterns cover: Flask/FastAPI/Django HTTP routes, `open()`, `subprocess.*`, `os.system/popen`, `eval()`, `exec()`, `pickle.loads`, `yaml.load`, `json.loads`, `marshal.loads`.

JavaScript patterns cover: Express routes (`app.get/post/...`, `router.*`), `fs.readFile/readFileSync`, `child_process.*`, `exec/spawn/execSync`, `eval()`, `new Function()`, `JSON.parse()`.

### CodeQL database

Attempts to build a CodeQL database for the dominant language in the repository. Fails gracefully (logs a warning) if the CodeQL binary is not in `PATH` or database creation times out. The pipeline continues without CodeQL for Phase 3 in that case.

### Dependency extraction

Parses `requirements.txt`, `pyproject.toml` (via `tomllib`/`tomli`), and `package.json` to build a flat dependency list with name, version, and ecosystem. This is included in the manifest for analyst context but is not used directly by any downstream agent in the current version.

---

## Phase 1 — Triage (Carlini Sweep)

**Input:** `RepositoryManifest`
**Output:** `findings.json` (`list[FileFinding]`)

### Naming

Named after the "Carlini attack" mindset: approach every file as if you are an adversary trying to find *one real bug*, not a compliance tool generating a report. The system prompt embeds this mindset explicitly and instructs the LLM not to generate hedged or speculative findings.

### Per-file isolation

Each file is analysed **independently** with no cross-file context. This is a deliberate design decision: cross-file context at scale would require massive context windows and would produce unfocused LLM outputs. Cross-file reasoning is deferred to Phase 3's ReAct loop, where it is applied only to confirmed single-file findings.

### File size handling

Files larger than 60,000 characters are truncated: the first 30,000 and last 30,000 characters are kept, with a truncation notice inserted. This preserves both the file header (imports, class definitions) and the tail (often where main() or route handlers live) while staying within typical context limits.

### Line numbering

Source code is sent to the LLM with explicit 5-digit line numbers prepended to each line. This dramatically improves the accuracy of line-number citations in findings, since the LLM can reference concrete numbers rather than counting lines.

### Confidence threshold

Findings with `confidence < 0.6` are silently dropped. The threshold is not a soft suggestion — it is a hard filter applied before any downstream work is done. Tuning this value is the primary knob for trading precision against recall.

---

## Phase 2 — Taint Specification

**Input:** `list[FileFinding]`
**Output:** `taint_specs.json` (`list[TaintSpec]`) + Semgrep rule YAMLs

### Context window

For each finding, the agent fetches a ±50 line slice of the file centred on the finding's line number. This is enough context to understand the surrounding function without overwhelming the LLM with irrelevant code.

### LLM output contract

The LLM must return a single JSON object with exactly these keys:
- `source` — the function/parameter where untrusted data enters
- `sink` — the function call where the data becomes dangerous  
- `sanitizers` — list of functions that validate or escape on the path
- `unresolved_calls` — dynamic dispatch or callbacks that the LLM cannot resolve statically
- `taint_path_summary` — one-to-two sentence human-readable description

If parsing fails, a minimal fallback struct (`unknown_source → unknown_sink`) is used so the finding is not silently dropped. Phase 3 will later fail to confirm it.

### Semgrep rule generation

`generate_semgrep_rule()` in `utils/sast.py` converts the source and sink strings to valid Semgrep taint-mode patterns:

1. Strip concrete argument values: `request.args.get('id')` → `request.args.get(...)`
2. Ensure the pattern ends with `(...)` (Semgrep ellipsis wildcard for argument lists)
3. Map file suffix to Semgrep language identifier (`.py` → `python`, `.ts` → `typescript`, etc.)
4. Emit a full `mode: taint` rule with `pattern-sources`, `pattern-sinks`, and optionally `pattern-sanitizers`

Rules are written to `/tmp/audit_rules/{finding_id}.yaml` (configurable via `--rules-dir`).

---

## Phase 3 — Data Flow Verification (ReAct)

**Input:** `list[TaintSpec]`
**Output:** `confirmed_flows.json` (`list[ConfirmedFlow]`)

### ReAct loop

Each finding gets a loop of up to 5 iterations:

```
Iteration 1..5:
  REASON: ask LLM to analyse current evidence and choose an action
  ACT:    execute the chosen action
  OBSERVE: collect output, store as VerificationEvidence
  →  stop early if action == "conclude"

After loop:
  CONCLUDE: separate LLM call with all evidence → verdict {confirmed|sanitized|unreachable}
```

The `REASON` step returns structured JSON `{reasoning, action, action_param}`. The `CONCLUDE` step is a separate call with the full evidence log and returns `{verdict, reasoning}`.

### Available actions

| Action | Implementation |
|---|---|
| `run_semgrep` | Runs the generated rule YAML via `SemgrepRunner.run_rule_file()` |
| `grep_sanitizers` | Regex search across the file for sanitizer-like function names |
| `read_context` | Returns a wider code slice (default ±80 lines, or a custom `start-end` range) |
| `run_codeql` | Writes an inline CodeQL QL query and executes it against the DB |
| `conclude` | Signals the loop to stop; the LLM's reasoning becomes the final evidence entry |

### Drop conditions

A finding is dropped (does not appear in `confirmed_flows.json`) if the verdict is `sanitized` or `unreachable`. Only `confirmed` verdict flows proceed to Phase 4. If the LLM verdict call itself fails, the finding is conservatively passed through as `confirmed` to avoid silent false negatives.

---

## Phase 4 — Exploit Hypothesis

**Input:** `list[ConfirmedFlow]`
**Output:** `validated_vulns.json` (`list[ValidatedVuln]`)

### PoC generation

The LLM is asked to produce a *minimal, concrete* payload. The system prompt explicitly bans generic descriptions:

- ❌ "malicious input" → drop
- ❌ "attacker-controlled string" → drop
- ✅ `'; DROP TABLE users; --` → keep
- ✅ `../../../etc/passwd` → keep
- ✅ `${7*7}` → keep

If the LLM responds with `{"poc": null, "reason": "..."}` it is declaring a false positive. The finding is dropped without any static trace.

### Static reachability trace

Even after PoC generation, the agent performs a lightweight static check:

1. **Sink presence:** the bare sink function name (e.g. `execute` from `cursor.execute(...)`) must appear in the source file. If it does not, the finding is a hallucination — dropped.
2. **Source presence:** the source name must appear in the file. Soft failure only (the source may be an imported symbol — the file has it but the LLM named the import source).
3. **Sanitizer window check:** within ±30 lines of the finding, search for patterns matching strong sanitizers (`html.escape`, `bleach.clean`, `parameterize`, `escape_string`, Django's `mark_safe`, etc.). If found, drop the finding — the confirmed flow's sanitizer detection missed it or the LLM described an already-safe path.

This trace is intentionally not a full symbolic execution. Full symbolic execution would require orders of magnitude more compute and would be redundant given the upstream ReAct verification. The trace here is a final sanity check for the most obvious false-positive scenarios.

---

## Phase 5 — Report

**Input:** `list[ValidatedVuln]`
**Output:** `results.sarif`, `report.md`, `pipeline_report.json`

### CVSS 3.1 scoring

The LLM is prompted to select the eight CVSS 3.1 base metric values (AV, AC, PR, UI, S, C, I, A) for each vulnerability. The response is validated against the set of legal values for each metric before use. Invalid values fall back to a predefined conservative default.

The CVSS 3.1 base score is computed analytically from the specification formula — no external scoring libraries are used:

```
ISCBase = 1 − [(1−C) × (1−I) × (1−A)]
Impact  = 6.42 × ISCBase                            (Scope Unchanged)
        = 7.52 × (ISCBase−0.029) − 3.25 × (ISCBase−0.02)^15  (Scope Changed)
Exploitability = 8.22 × AV × AC × PR × UI
BaseScore = Roundup(min(Impact + Exploitability, 10))   (Scope Unchanged)
          = Roundup(min(1.08 × (Impact + Exploitability), 10)) (Scope Changed)
```

The calculator is validated in the test suite against Log4Shell (10.0 CRITICAL) and a high-privilege RCE (7.2 HIGH).

### SARIF 2.1.0

The SARIF output is designed to be immediately importable into:
- **VS Code** via the SARIF Viewer extension
- **GitHub Code Scanning** (upload as a workflow artifact)
- **Any SARIF-compatible platform** (SonarQube, Defect Dojo, etc.)

Each result carries the PoC, CVSS vector, exploitability rating, and finding ID as `properties`, so downstream tools can surface them without re-parsing the message text.

### Token accounting

After each run, `token_usage.json` records the cumulative prompt and completion token counts across all LLM calls. This lets you estimate the cost per repository at scale, tune context window sizes, and compare model efficiency.

---

## Error handling

The pipeline follows a **fail-soft** strategy at the finding level and **fail-hard** at the structural level:

- If the LLM call for a single finding fails after retries → log error, skip that finding, continue
- If JSON parsing of an LLM response fails → log warning, use a fallback struct or skip
- If Semgrep is not installed → log warning, `run_semgrep` action returns an empty result
- If CodeQL is not installed → log warning, `run_codeql` action returns an empty result
- If a phase's input JSON is missing when resuming → log error, **abort** (no silent partial runs)
- If Pydantic validation fails when loading a phase's output → log error, **abort**

The distinction is intentional: a single broken finding should never kill an entire audit. But a structurally corrupt pipeline state should never silently propagate.

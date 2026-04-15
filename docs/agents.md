# Agent Reference

Each agent is a standalone Python class with a single `run(input) -> output` method. Agents share a `LLMClient` instance but are otherwise independent — they do not call each other, do not hold shared state, and are safe to unit-test in isolation.

---

## IngestionAgent

**File:** `agents/ingestion.py`
**Phase:** 0
**Input:** `str` (repo path) + optional clone URL
**Output:** `RepositoryManifest`

### Constructor

```python
IngestionAgent(output_dir: str, codeql_bin: str = "codeql")
```

`codeql_bin` is the path to the CodeQL CLI binary. If the binary is not found, CodeQL steps are silently skipped and `codeql_db_path` is `None` in the manifest.

### run()

```python
def run(self, repo_path: str, clone_url: Optional[str] = None) -> RepositoryManifest
```

Steps:
1. If `clone_url` is set, runs `git clone --depth=1 <url> <repo_path>`
2. Collects all `.py/.js/.ts/.jsx/.tsx` files excluding vendored dirs
3. Runs tree-sitter parser on each file to extract function/class/import names
4. Runs regex entry-point detection on each file
5. Parses `requirements.txt`, `pyproject.toml`, `package.json` for dependencies
6. Attempts to build a CodeQL database (`python` or `javascript` language)
7. Serialises `RepositoryManifest` to `{output_dir}/manifest.json`

### Tree-sitter integration

Uses `tree_sitter_python` and `tree_sitter_javascript` packages. The agent initialises parsers in `_init_parsers()` with a try/except — if either package is missing the method logs a warning and sets `self._py_parser = None`. All subsequent AST calls check for `None` before proceeding.

Tree traversal uses a simple recursive `walk(node)` function rather than the tree-sitter Query API. This is intentional: the Query API has changed its return format between versions (dict in 0.22, list in 0.24+), whereas recursive walking is stable across all versions.

### Entry point patterns

Patterns are defined as two module-level dicts `_PY_PATTERNS` and `_JS_PATTERNS`, mapping type names to lists of compiled-on-use regex strings. Adding a new entry point type is a one-line change in either dict.

---

## TriageAgent

**File:** `agents/triage.py`
**Phase:** 1
**Input:** `RepositoryManifest`
**Output:** `list[FileFinding]`

### Constructor

```python
TriageAgent(llm: LLMClient, output_dir: str)
```

### run()

```python
def run(self, manifest: RepositoryManifest) -> list[FileFinding]
```

Iterates over `manifest.files`. For each file: reads content, prepends line numbers, sends to LLM with the Carlini sweep system prompt, parses the JSON array response, filters by confidence ≥ 0.6, assigns a UUID to each surviving finding.

### System prompt strategy

The prompt is adversarial in tone by design. It tells the LLM it is a CTF participant competing to find real bugs, not a safety tool. It explicitly instructs: "Do NOT say the code is safe. Do NOT hallucinate." Testing showed this framing produces significantly fewer hedged non-findings compared to neutral or defensive framings.

The JSON-only output constraint (`Respond ONLY in JSON array format`) combined with the exact field names in the example prevents the LLM from wrapping its output in prose, which would break JSON extraction.

### Confidence semantics

The LLM assigns confidence scores between 0.0 and 1.0. The intended interpretation:
- **0.9–1.0:** sink is directly reachable with user-controlled data, no visible sanitization
- **0.7–0.9:** strong suspicion; may need cross-file context to confirm
- **0.6–0.7:** marginal; the code pattern is present but reachability is unclear

Findings below 0.6 are not "low severity" findings — they are findings the LLM itself is not confident about. Passing them downstream would make Phase 3's verification work meaningless.

### Token considerations

A 500-line Python file typically generates ~2,000 prompt tokens with line numbering added. At this rate, a 100-file codebase requires ~200K prompt tokens for Phase 1 alone. Check `token_usage.json` after a run to calibrate expectations for your endpoint.

---

## TaintSpecAgent

**File:** `agents/taint_spec.py`
**Phase:** 2
**Input:** `list[FileFinding]`
**Output:** `list[TaintSpec]` + Semgrep YAML files

### Constructor

```python
TaintSpecAgent(llm: LLMClient, output_dir: str, rules_dir: str = "/tmp/audit_rules")
```

`rules_dir` is where generated Semgrep rule YAMLs are written. They are cleaned up after the run unless `--keep-rules` is passed.

### run()

```python
def run(self, findings: list[FileFinding]) -> list[TaintSpec]
```

For each finding:
1. Extracts ±50 line context centred on `finding.line`
2. Sends to LLM with the taint analysis system prompt
3. Parses `{source, sink, sanitizers, unresolved_calls, taint_path_summary}`
4. Calls `generate_semgrep_rule()` to build a YAML rule file
5. Returns a `TaintSpec` linking all fields

### Fallback behaviour

If JSON parsing of the LLM response fails entirely, the agent creates a `TaintSpec` with `source="unknown_source"` and `sink="unknown_sink"`. This allows the finding to proceed to Phase 3, where it will fail the Semgrep run (no match for `unknown_source(...)`) and be dropped with a `unreachable` verdict rather than silently disappearing from the pipeline.

### Semgrep rule structure

Generated rules use `mode: taint` which enables Semgrep's inter-procedural taint tracking. This is more powerful than simple pattern matching: Semgrep will track data flow through intermediate variable assignments, function return values, and method calls within the same file.

Example of a generated rule for a command injection finding:

```yaml
rules:
  - id: sast-3f7a2c1b-...
    mode: taint
    pattern-sources:
      - pattern: request.args.get(...)
    pattern-sinks:
      - pattern: subprocess.run(...)
    pattern-sanitizers:
      - pattern: shlex.quote(...)
    message: >
      CWE-78: Unsanitised user input passed to subprocess.run
      Source: request.args.get('cmd')
      Sink: subprocess.run(cmd, shell=True)
    languages: [python]
    severity: ERROR
    metadata:
      cwe: "CWE-78"
      finding_id: "3f7a2c1b-..."
```

---

## DataFlowAgent

**File:** `agents/dataflow.py`
**Phase:** 3
**Input:** `list[TaintSpec]`
**Output:** `list[ConfirmedFlow]`

### Constructor

```python
DataFlowAgent(
    llm: LLMClient,
    output_dir: str,
    codeql_db_path: Optional[str] = None,
    codeql_bin: str = "codeql",
)
```

### run()

```python
def run(self, specs: list[TaintSpec], repo_path: str) -> list[ConfirmedFlow]
```

For each spec, calls `_verify_flow()`. Flows with a `confirmed` verdict are collected into the output list.

### ReAct loop internals

The `_verify_flow()` method runs the loop and then calls `_conclude()` separately. Separating the iterative reasoning from the final verdict call allows the conclude prompt to receive the full evidence log without mixing it with action-selection instructions.

**`_reason()`** — sends the current spec + evidence log to the LLM with `_REASON_PROMPT`. Returns `(action, action_param, reasoning)`. The action is one of 5 string literals; unknown actions are treated as no-ops.

**`_conclude()`** — sends the spec + evidence log with `_CONCLUDE_PROMPT`. Returns `(verdict, reasoning)`. Temperature is set to 0.0 for maximum determinism. Defaults to `confirmed` on LLM failure (conservative — avoids silent false negatives).

### Action implementations

**`_act_semgrep(spec, runner)`**
Runs the rule YAML generated in Phase 2. Returns a summary of the first 5 matches. If the rule file does not exist (Phase 2 fallback path), returns an explanatory string rather than raising.

**`_act_grep(file_path, pattern)`**
Uses Python `re.search()` on each line of the file. The pattern defaults to a union of known sanitizer function names or can be supplied by the LLM as `action_param`. Invalid regex patterns are automatically escaped before use.

**`_act_read_context(file_path, center, param)`**
Returns a wider slice of the file with line numbers. The `param` can be `"start-end"` for a precise line range or empty for ±80 lines centred on the finding. Handles bounds correctly for files shorter than the window.

**`_act_codeql(spec, param)`**
Writes a fresh inline QL query that searches for calls to the sink function name (bare, extracted by splitting on `.` and `(`). Executes it via `CodeQLRunner.run_inline_query()`. Returns `[]` gracefully if the DB does not exist.

---

## ExploitAgent

**File:** `agents/exploit.py`
**Phase:** 4
**Input:** `list[ConfirmedFlow]`
**Output:** `list[ValidatedVuln]`

### Constructor

```python
ExploitAgent(llm: LLMClient, output_dir: str)
```

### run()

```python
def run(self, flows: list[ConfirmedFlow]) -> list[ValidatedVuln]
```

For each flow, calls `_process_flow()`. Only flows that survive both the LLM PoC check and the static trace are collected.

### PoC generation prompt

The system prompt defines a strict binary contract:

- **False positive declaration:** `{"poc": null, "reason": "..."}`
- **Valid exploit:** `{"poc": "exact_payload", "attack_scenario": "...", "exploitability": "high|medium|low"}`

The prompt lists concrete examples of good and bad PoCs. Without these examples, LLMs tend to produce overly generic descriptions ("crafted input") rather than actual payloads.

### `_static_trace()` — how it works

```python
def _static_trace(self, flow: ConfirmedFlow, poc: str) -> bool
```

1. Read the source file (returns `True` if unreadable — conservative)
2. Extract bare sink name: `cursor.execute(query)` → `execute`
3. `re.search(re.escape(sink_name), code)` — drop if absent
4. Extract bare source name: `request.args.get('id')` → `get`
5. `re.search(re.escape(source_name), code)` — soft drop if absent (may be imported)
6. Check ±30 line window for strong sanitizer patterns — drop if found

The list of strong sanitizers (`_STRONG_SANITIZERS` in the source) currently covers html.escape, bleach.clean, parameterize, escape_string, and Django/Jinja2 safe-marking functions. This list is easily extended.

### `_bare_name()` helper

```python
def _bare_name(ref: str) -> str
```

Strips arguments and dotted prefixes: `"subprocess.run(cmd, shell=True)"` → `"run"`.
Used to convert LLM source/sink strings to bare function names for regex matching.

---

## ReporterAgent

**File:** `agents/reporter.py`
**Phase:** 5
**Input:** `list[ValidatedVuln]`
**Output:** `PipelineReport`, `results.sarif`, `report.md`

### Constructor

```python
ReporterAgent(llm: LLMClient, output_dir: str, pipeline_stats: dict | None = None)
```

`pipeline_stats` carries counts from upstream phases (files scanned, findings per phase) for inclusion in the summary.

### CVSS scoring flow

1. LLM called with `_CVSS_SYSTEM_PROMPT` → returns 8 metric values + title + impact + remediation
2. Each metric value validated against its legal set (`{"N","A","L","P"}` for AV, etc.)
3. Invalid values replaced with safe defaults
4. `calculate_cvss31(metrics)` called to compute the score analytically
5. A `CVSSScore` struct is returned with `base_score`, `severity`, `vector_string`, and the `CVSSMetrics`

The LLM is not asked to compute the score itself — only to select the metric values. Numeric computation is done in Python from the CVSS 3.1 specification formula. This eliminates a class of hallucination where LLMs fabricate plausible-sounding but incorrect score values.

### SARIF structure

```
SarifLog
  └─ runs[0]
      ├─ tool.driver
      │    ├─ name: "MoSec-SAST"
      │    ├─ version: "1.0.0"
      │    └─ rules: [SarifRule per unique CWE]
      └─ results: [SarifResult per validated vuln]
           ├─ ruleId: "CWE-89"
           ├─ level: "error" | "warning" | "note"
           ├─ message: full description with PoC and remediation
           ├─ locations: [physicalLocation with file URI and start line]
           ├─ fingerprints: {finding_id/v1: UUID}
           └─ properties: {cvss_score, cvss_vector, poc, exploitability}
```

Results are sorted by CVSS descending before serialisation, so the highest-severity findings appear first in every consumer (VS Code, GitHub, etc.).

### Fallback on CVSS failure

If the LLM call fails or returns unparseable output, `_DEFAULT_METRICS` is used:
`AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` → CVSS 6.5 (Medium). This is chosen to be visible enough that an analyst will notice it without being artificially catastrophised.

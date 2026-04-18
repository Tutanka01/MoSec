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

Per-file isolation. Each file is line-numbered and sent to the LLM with the adversarial Carlini sweep prompt. Findings with `confidence < 0.6` are hard-filtered. Each surviving finding receives a stable UUID carried through all subsequent phases.

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

### run()

```python
def run(self, findings: list[FileFinding]) -> list[TaintSpec]
```

For each finding:
1. **AST candidate extraction** — `TaintCandidateExtractor.extract()` scans the file and returns structured source/sink candidates with line/column coordinates and `sink_kind`
2. Extracts ±50 line context centred on `finding.line`
3. Sends prompt to LLM that includes the candidate list (LLM selects from grounded positions)
4. Parses `{source, sink, sink_kind, sanitizers, unresolved_calls, taint_path_summary, source_line, sink_line}`
5. Calls `generate_semgrep_rule(sink_kind=...)` to build a validated YAML rule
6. Returns a `TaintSpec` linking all fields including AST metadata

### New fields in TaintSpec

| Field | Type | Source |
|---|---|---|
| `sink_kind` | `str` | LLM-confirmed, AST-suggested |
| `source_line` | `Optional[int]` | AST coordinate |
| `source_col` | `Optional[int]` | AST coordinate |
| `sink_line` | `Optional[int]` | AST coordinate |
| `sink_col` | `Optional[int]` | AST coordinate |

### Semgrep rule generation

`generate_semgrep_rule()` uses a `sink_kind` → pattern template table:

| sink_kind | Generated Semgrep pattern |
|---|---|
| `call` | `os.system(...)` |
| `method_call` | `$X.execute(...)` |
| `property_assignment` | `$X.innerHTML = $TAINT` |
| `subscript_assignment` | `$X[...] = $TAINT` |

Every rule is validated with `semgrep --validate` before being written. If validation fails, a `pattern-regex` fallback rule is emitted so the file is always syntactically correct.

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
    consistency_n: int = 1,
)
```

`consistency_n` controls self-consistency voting in the VerifierAgent. Set via `MOSEC_VERIFIER_N` environment variable.

### run()

```python
def run(self, specs: list[TaintSpec], repo_path: str) -> list[ConfirmedFlow]
```

For each spec, calls `_verify_flow()`. Flows with a `confirmed` verdict are collected into the output list.

### ReAct loop internals

**`_reason(spec, evidence, played, iteration) → ReActStep`**

The LLM's JSON response is parsed and validated against `ReActStep`:
- `reasoning: str` — must be at least one sentence
- `action: Literal["run_semgrep", "grep_sanitizers", "read_context", "run_codeql", "conclude"]`
- `action_param: str`
- `confidence: float` (0.0–1.0)

Unknown action names are replaced with `"conclude"` (never silently dropped). On validation failure, the agent retries once with the error surfaced to the model.

**Action deduplication:** `played: set[tuple[str, str]]` tracks `(action, param)`. If the LLM repeats an already-executed action, the loop inserts a `DEDUP:` observation and does not consume the iteration budget, forcing the LLM to try something new.

**Action implementations:**

| Action | Returns |
|---|---|
| `_act_semgrep(spec, runner)` | `(str, StructuredEvidence)` with `hits: list[CodeLocation]` |
| `_act_grep(file_path, pattern)` | `(str, StructuredEvidence)` with per-line matches |
| `_act_read_context(file_path, center, param)` | `(str, StructuredEvidence)` with code slice |
| `_act_codeql(spec, param)` | `(str, StructuredEvidence)` — TaintTracking or assignment query based on `sink_kind` |

All actions return a structured tuple. The `StructuredEvidence.hits` list carries `CodeLocation` (file, line_start, line_end, snippet) for downstream SARIF `codeFlows` generation.

**Final verdict:** delegated to `VerifierAgent.verify(spec, evidence)`.

---

## VerifierAgent

**File:** `agents/verifier.py`
**Called by:** `DataFlowAgent._verify_flow()`
**Input:** `TaintSpec` + `list[VerificationEvidence]`
**Output:** `(verdict: str, reasoning: str)` where verdict ∈ `{"confirmed", "sanitized", "unreachable"}`

### Constructor

```python
VerifierAgent(llm: LLMClient, consistency_n: int = 1)
```

### verify()

```python
def verify(self, spec: TaintSpec, evidence: list[VerificationEvidence]) -> tuple[str, str]
```

Runs `_single_verify()` N times when `consistency_n > 1`, takes majority vote.

### Propose → Falsify → Decide pipeline

**Stage 1 — Propose (`_PROPOSE_PROMPT`):**
The LLM states an initial verdict, citing evidence items by iteration number. Temperature 0.1 to allow slight variation across self-consistency runs.

**Stage 2 — Falsify (`_FALSIFY_PROMPT`):**
A second, adversarial prompt frames the LLM as a "skeptical red-team reviewer" and asks for at least two concrete reasons the initial verdict could be wrong. This step cannot produce a verdict — it can only surface weaknesses.

**Stage 3 — Decide (`_DECIDE_PROMPT`):**
A third prompt weighs the initial reasoning against the rebuttals. The burden-of-proof rule is explicit in the prompt:
> "confirmed" only if there is AFFIRMATIVE evidence that untrusted data flows to the sink AND no effective sanitizer is on the path.

Any LLM failure in this stage returns `("unreachable", "Decide stage failed (fail-closed): ...")`. This is the fail-closed invariant — a broken infrastructure must never create false positives.

### Evidence formatting

`_format_evidence()` uses `StructuredEvidence.summary` when available (rich, no truncation) and falls back to `result[:600]` otherwise. `DEDUP:` entries are excluded from the formatted log.

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

### PoC generation

The LLM is constrained to either produce a minimal concrete payload or declare `{"poc": null, "reason": "..."}`. Without specific examples of good vs bad PoCs in the prompt, models converge on generic descriptions.

### `_static_trace()` — multi-layer reachability check

```python
def _static_trace(self, flow: ConfirmedFlow, poc: str) -> bool
```

**Layer 1 — AST CFG BFS (primary):**
```python
from utils.ast_extractor import TaintCandidateExtractor
extractor = TaintCandidateExtractor()
cfg = extractor.get_cfg(flow.file, flow.line)
source_vars = _extract_source_vars(flow.source, code, flow.line)
reached, path = cfg.taint_bfs(source_vars, sink_bare, barriers)
```
`SimpleCFG.taint_bfs()` performs BFS on the intra-procedural def-use graph. Returns `(True, path)` if any source variable reaches the sink through a chain of assignments. `barriers` contains the declared sanitizers — they break the taint chain.

When the CFG runs but finds no path AND source variables were identified, the finding is dropped. When source variables cannot be found (external/imported source), control falls to Layer 2.

**Layer 2 — `_lexical_trace()` (improved fallback):**
The old implementation used a fixed ±30-line window and would drop findings when words like `sanitize` appeared anywhere nearby. The new implementation:
1. Locates the **containing function body** via `_find_function_body()` (indentation-based heuristic)
2. Checks sanitizer patterns **only on lines that also contain the sink name** — a `def sanitize_input()` definition in a different function no longer kills a finding

### Helper functions

**`_extract_source_vars(source, code, center_line) → set[str]`**
Scans ±60 lines for `varname = <source_name>(...)` patterns and returns all variable names that receive tainted data.

**`_find_function_body(lines, target_idx) → (start, end)`**
Heuristically locates the function containing `target_idx` by scanning backwards for `def`/`function` keywords and forwards for the next function at the same or lower indentation.

---

## ReporterAgent

**File:** `agents/reporter.py`
**Phase:** 5
**Input:** `list[ValidatedVuln]` + optional `list[ConfirmedFlow]`
**Output:** `PipelineReport`, `results.sarif`, `report.md`

### Constructor

```python
ReporterAgent(llm: LLMClient, output_dir: str, pipeline_stats: dict | None = None)
```

### run()

```python
def run(
    self,
    vulns: list[ValidatedVuln],
    confirmed_flows: list[ConfirmedFlow] | None = None,
) -> PipelineReport
```

`confirmed_flows` is used to build SARIF `codeFlows` evidence traces.

### SARIF codeFlows (new)

`_build_code_flows(flow, default_uri)` builds the `codeFlows` array from `VerificationEvidence`:

- When `ev.structured.hits` is present: uses precise `CodeLocation` (file, line_start, line_end, snippet)
- Fallback: records the action and raw result text at the finding's line number

The resulting SARIF `codeFlows[0].threadFlows[0].locations` array lets any SARIF viewer (VS Code, GitHub) render the exact code locations that were examined during verification.

### CVSS 3.1 scoring

LLM selects eight metric values (AV, AC, PR, UI, S, C, I, A). Python computes the score analytically from the CVSS 3.1 specification — no external scoring library. Invalid metric values fall back to `_DEFAULT_METRICS` (CVSS 6.5 Medium).

---

## TaintCandidateExtractor

**File:** `utils/ast_extractor.py`
**Used by:** `TaintSpecAgent`, `ExploitAgent`

### Constructor

```python
TaintCandidateExtractor()
```

No required arguments. Parsers are initialised lazily.

### extract()

```python
def extract(
    self,
    file_path: str,
    center_line: int,
    cwe: str,
    radius: int = 80,
) -> list[ASTCandidate]
```

Returns source/sink candidates near `center_line`:
- `.py` files → stdlib `ast` (accurate, always available)
- `.js/.jsx/.ts/.tsx` → tree-sitter (optional; regex fallback when absent)
- Other → regex fallback

Each `ASTCandidate` carries `{kind, name, line, col, sink_kind, returns_var, assigned_from, args}`.

### get_cfg()

```python
def get_cfg(self, file_path: str, center_line: int) -> SimpleCFG
```

Builds an intra-procedural def-use graph by walking the AST of the function containing `center_line`. Tracks:
- Variable assignments: `target ← {source_vars}`
- Function call arguments: `sink_bare ← {arg_vars}`
- Property assignments: `prop_name ← {rhs_vars}`

### SimpleCFG.taint_bfs()

```python
def taint_bfs(
    self,
    source_vars: set[str],
    sink_name: str,
    barriers: set[str],
) -> tuple[bool, list[str]]
```

BFS over the def-use graph. Returns `(True, path)` when any variable in `source_vars` can reach `sink_name` without passing through `barriers`. The path is a list of `"a → b"` strings describing the data flow.

Example:
```python
# code: user_id = request.args.get('id')
#       query = "SELECT ... WHERE id = " + user_id
#       cursor.execute(query)

cfg.taint_bfs({'user_id', 'get'}, 'execute', barriers=set())
# → (True, ['user_id → query', 'query → execute'])
```

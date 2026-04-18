# Output Formats

MoSec produces six categories of output file. All are written to `--output-dir` (default `./output`).

---

## Intermediate JSON files

These files are the source of truth for the pipeline. They are typed with Pydantic models and can be read, inspected, or modified by hand before resuming from a later phase.

### `manifest.json` — `RepositoryManifest`

```json
{
  "repo_path": "/absolute/path/to/repo",
  "files": [
    "/absolute/path/to/repo/src/app.py",
    "/absolute/path/to/repo/src/auth.py"
  ],
  "entry_points": [
    {"file": "src/app.py", "line": 12, "type": "http_route", "name": "@app.route('/login')"}
  ],
  "dependencies": [
    {"name": "flask", "version": ">=3.0.0", "ecosystem": "pip"}
  ],
  "ast_summary": [
    {
      "file": "src/app.py",
      "functions": ["login", "get_user"],
      "classes": ["UserController"],
      "imports": ["from flask import Flask, request"]
    }
  ],
  "codeql_db_path": "/absolute/path/to/output/codeql_db"
}
```

---

### `findings.json` — `list[FileFinding]`

```json
[
  {
    "finding_id": "3f7a2c1b-4e8d-4f2a-b3c1-9d0e5f6a7b8c",
    "file": "/absolute/path/to/repo/src/auth.py",
    "line": 47,
    "cwe": "CWE-89",
    "description": "User-supplied 'id' parameter concatenated directly into SQL query.",
    "confidence": 0.95
  }
]
```

Only findings with `confidence ≥ 0.6` appear here. The `finding_id` UUID is stable across all subsequent phases.

---

### `taint_specs.json` — `list[TaintSpec]`

```json
[
  {
    "finding_id": "3f7a2c1b-...",
    "file": "/absolute/path/to/repo/src/auth.py",
    "line": 47,
    "cwe": "CWE-89",
    "description": "...",
    "confidence": 0.95,
    "source": "request.args.get('id')",
    "sink": "cursor.execute",
    "sanitizers": [],
    "unresolved_calls": [],
    "taint_path_summary": "The 'id' parameter is assigned to 'user_id', concatenated into 'query', and passed to cursor.execute without sanitisation.",
    "semgrep_rule_path": "/tmp/audit_rules/3f7a2c1b-....yaml",
    "sink_kind": "method_call",
    "source_line": 42,
    "source_col": 15,
    "sink_line": 47,
    "sink_col": 4
  }
]
```

**New fields (AST grounding):**

| Field | Description |
|---|---|
| `sink_kind` | How the sink is used: `call`, `method_call`, `property_assignment`, `subscript_assignment` |
| `source_line` / `source_col` | AST coordinates of the source expression |
| `sink_line` / `sink_col` | AST coordinates of the sink expression |

These fields drive the Semgrep pattern template selection and the intra-procedural CFG BFS in Phase 4.

---

### `confirmed_flows.json` — `list[ConfirmedFlow]`

```json
[
  {
    "finding_id": "3f7a2c1b-...",
    "file": "/absolute/path/to/repo/src/auth.py",
    "line": 47,
    "cwe": "CWE-89",
    "source": "request.args.get('id')",
    "sink": "cursor.execute",
    "sanitizers": [],
    "taint_path_summary": "...",
    "verification_iterations": 3,
    "verification_evidence": [
      {
        "iteration": 1,
        "action": "run_semgrep()",
        "result": "Semgrep matched 1 location:\n  src/auth.py:47 — CWE-89: ...",
        "conclusion": "Semgrep confirms the sink is reachable with the source pattern.",
        "structured": {
          "kind": "semgrep_matches",
          "hits": [
            {"file": "src/auth.py", "line_start": 47, "line_end": 47, "snippet": "cursor.execute(query)"}
          ],
          "summary": "Semgrep matched 1 location:\n  src/auth.py:47 — CWE-89"
        }
      },
      {
        "iteration": 2,
        "action": "grep_sanitizers(validate|sanitize|escape|quote|encode)",
        "result": "No matches for pattern in src/auth.py.",
        "conclusion": "No sanitizers found. Taint path is unimpeded.",
        "structured": {
          "kind": "no_flow",
          "hits": [],
          "summary": "No matches for pattern 'validate|sanitize|...' in src/auth.py."
        }
      },
      {
        "iteration": 3,
        "action": "conclude()",
        "result": "Flow confirmed: request.args.get('id') → cursor.execute.",
        "conclusion": "High confidence this is exploitable.",
        "structured": {
          "kind": "conclude",
          "hits": [],
          "summary": "Flow confirmed: request.args.get('id') → cursor.execute."
        }
      }
    ]
  }
]
```

**`structured` field (new):** Each evidence entry now carries a `StructuredEvidence` with:
- `kind` — `semgrep_matches`, `grep_hits`, `code_slice`, `codeql_paths`, `no_flow`, `conclude`
- `hits` — list of `CodeLocation` with precise `file`, `line_start`, `line_end`, `snippet`
- `summary` — clean description used in the VerifierAgent prompt (no truncation)

`DEDUP:` entries (when the LLM tried to repeat an action) appear as `action: "DEDUP:run_semgrep(...)"` with `result: "Action already performed — no new information."` and are excluded from the VerifierAgent evidence summary.

---

### `validated_vulns.json` — `list[ValidatedVuln]`

```json
[
  {
    "finding_id": "3f7a2c1b-...",
    "file": "/absolute/path/to/repo/src/auth.py",
    "line": 47,
    "cwe": "CWE-89",
    "source": "request.args.get('id')",
    "sink": "cursor.execute",
    "taint_path_summary": "...",
    "poc": "1' OR '1'='1'; --",
    "attack_scenario": "An unauthenticated attacker sends GET /user?id=1' OR '1'='1'; -- causing the query to return all rows, bypassing authentication.",
    "exploitability": "high"
  }
]
```

---

### `pipeline_report.json` — `PipelineReport`

```json
{
  "total_files_scanned": 24,
  "total_findings_phase1": 8,
  "total_taint_specs": 8,
  "total_confirmed_flows": 5,
  "total_validated_vulns": 3,
  "vulnerabilities": [ ... ],
  "sarif_path": "/absolute/path/to/output/results.sarif",
  "markdown_path": "/absolute/path/to/output/report.md"
}
```

The funnel shape (24 files → 8 findings → 5 confirmed → 3 validated) is the key quality signal. A healthy run drops roughly 40-60% of findings at each stage. A run that retains everything through all stages indicates the confidence threshold or VerifierAgent settings are too permissive.

---

## `token_usage.json`

```json
{
  "total_prompt_tokens": 487234,
  "total_completion_tokens": 18431,
  "total_tokens": 505665
}
```

Use this to estimate cost per repository at scale, and to detect regressions when model or prompt changes affect token consumption. With `MOSEC_VERIFIER_N=3`, expect Phase 3 verify tokens to increase by ~2.5× (3 Propose-Falsify-Decide cycles, not 3×, because Falsify and Decide share context).

---

## `results.sarif` — SARIF 2.1.0

Importable into:
- **VS Code** — install the [SARIF Viewer](https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer), then `Ctrl+Shift+P` → "SARIF: Open SARIF file"
- **GitHub Code Scanning** — upload as a workflow artifact with `security-events` permission
- **SonarQube / Defect Dojo / any SARIF-compatible platform**

### Result structure

| SARIF field | Contents |
|---|---|
| `ruleId` | The CWE identifier (e.g. `CWE-89`) |
| `level` | `error` for HIGH/CRITICAL, `warning` for MEDIUM, `note` for LOW |
| `message.text` | Title, attack scenario, PoC, and remediation |
| `locations[0].physicalLocation` | File URI + start line |
| `fingerprints.finding_id/v1` | Stable UUID for deduplication across runs |
| `properties.cvss_score` | CVSS 3.1 base score |
| `properties.cvss_vector` | Full CVSS vector string |
| `properties.poc` | The concrete PoC payload |
| `codeFlows[0].threadFlows[0].locations` | Evidence trace from ReAct loop (new) |

### `codeFlows` — taint evidence trace (new)

Each result now includes a `codeFlows` array built from `VerificationEvidence.structured.hits`:

```json
"codeFlows": [{
  "message": {"text": "Taint flow verified in 3 ReAct iteration(s)"},
  "threadFlows": [{
    "locations": [
      {
        "location": {
          "physicalLocation": {
            "artifactLocation": {"uri": "src/auth.py", "uriBaseId": "%SRCROOT%"},
            "region": {"startLine": 47, "endLine": 47}
          },
          "message": {"text": "[run_semgrep()] src/auth.py:47 — CWE-89: SQL injection match"}
        }
      },
      {
        "location": {
          "physicalLocation": {
            "artifactLocation": {"uri": "src/auth.py", "uriBaseId": "%SRCROOT%"},
            "region": {"startLine": 47, "endLine": 47}
          },
          "message": {"text": "[grep_sanitizers()] No sanitizers found in function body"}
        }
      }
    ]
  }]
}]
```

In VS Code SARIF Viewer, these locations appear as a navigable taint trace. Click any location to jump to the relevant line.

---

## `report.md` — Markdown Security Report

Human-readable, self-contained security report sorted by CVSS descending.

```
# MoSec SAST Security Report
Generated: 2025-10-14 09:22 UTC

## Summary
| # | Severity | CVSS | CWE | File | Title |
|---|----------|------|-----|------|-------|
| 1 | CRITICAL  | 9.8  | CWE-89 | auth.py:47 | SQL Injection in login |

---

## 1. SQL Injection in login  🔴 CRITICAL

| Field | Value |
|-------|-------|
| File | `src/auth.py:47` |
| CWE | CWE-89 |
| CVSS 3.1 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` → **9.1** (CRITICAL) |
| Exploitability | high |
| Finding ID | `3f7a2c1b-...` |

### Description
[description]

### Attack Scenario
[attack scenario]

### Impact
[impact]

### Proof of Concept
```
1' OR '1'='1'; --
```

### Taint Flow
*See `confirmed_flows.json` → finding `3f7a2c1b-...` for the full ReAct trace.*

### Remediation
Use parameterised queries: `cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))`
```

---

## `bench_report.json` — Benchmark results

Produced by `python -m benchmarks.runner`. Contains precision/recall/F1 per CWE and per difficulty level:

```json
{
  "summary": {
    "total": 10, "tp": 5, "fp": 0, "tn": 3, "fn": 2,
    "precision": 1.0, "recall": 0.71, "f1": 0.83,
    "accuracy": 0.80, "elapsed_s": 312.4
  },
  "per_cwe": {
    "CWE-79": {"tp": 2, "fp": 0, "tn": 1, "fn": 1},
    "CWE-89": {"tp": 2, "fp": 0, "tn": 1, "fn": 0}
  },
  "per_difficulty": {
    "normal": {"tp": 5, "fp": 0, "tn": 3, "fn": 0},
    "hard":   {"tp": 0, "fp": 0, "tn": 0, "fn": 2}
  },
  "cases": [
    {
      "case": "tp_flask_xss", "label": "TP", "cwe": "CWE-79",
      "expected": true, "predicted": true, "correct": true,
      "tp": true, "fp": false, "tn": false, "fn": false,
      "elapsed_s": 28.4
    }
  ]
}
```

The CI gate exits with code 1 when `f1 < 0.5`. Run with `make bench` or `python -m benchmarks.runner` after any change to agents, prompts, or schemas.

---

## `pipeline.log`

Structured log with per-phase start/end markers, per-finding taint spec results, per-finding ReAct iteration log (action, structured observation, confidence), VerifierAgent stage transitions (propose → falsify → decide), and token usage summary.

For verbose LLM call inspection, set `LOG_LEVEL=DEBUG` in `.env` or change `logging.basicConfig(level=logging.DEBUG)` in `pipeline.py`.

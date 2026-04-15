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
    {
      "file": "src/app.py",
      "line": 12,
      "type": "http_route",
      "name": "@app.route('/login', methods=['POST'])"
    }
  ],
  "dependencies": [
    { "name": "flask", "version": ">=3.0.0", "ecosystem": "pip" },
    { "name": "lodash", "version": "^4.17.21", "ecosystem": "npm" }
  ],
  "ast_summary": [
    {
      "file": "src/app.py",
      "functions": ["login", "get_user", "create_session"],
      "classes": ["UserController"],
      "imports": ["from flask import Flask, request", "import sqlite3"]
    }
  ],
  "codeql_db_path": "/absolute/path/to/output/codeql_db"
}
```

**`entry_points.type`** values: `http_route`, `file_read`, `subprocess`, `eval`, `deserialization`

**`codeql_db_path`** is `null` if CodeQL is not installed or database creation failed.

---

### `findings.json` — `list[FileFinding]`

```json
[
  {
    "finding_id": "3f7a2c1b-4e8d-4f2a-b3c1-9d0e5f6a7b8c",
    "file": "/absolute/path/to/repo/src/auth.py",
    "line": 47,
    "cwe": "CWE-89",
    "description": "User-supplied 'id' parameter concatenated directly into SQL query string.",
    "confidence": 0.95
  }
]
```

Only findings with `confidence ≥ 0.6` appear here. The `finding_id` is a UUID generated at Phase 1 and carried through every subsequent phase — it is the stable identifier for a finding across all outputs.

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
    "sink": "cursor.execute(query)",
    "sanitizers": [],
    "unresolved_calls": [],
    "taint_path_summary": "The 'id' parameter from the HTTP request is assigned to 'user_id', which is concatenated into 'query' and passed to cursor.execute without any sanitisation.",
    "semgrep_rule_path": "/tmp/audit_rules/3f7a2c1b-....yaml"
  }
]
```

The `semgrep_rule_path` points to the generated rule YAML. If `--keep-rules` was not passed, this file will have been deleted after the run.

---

### `confirmed_flows.json` — `list[ConfirmedFlow]`

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
    "sink": "cursor.execute(query)",
    "sanitizers": [],
    "taint_path_summary": "...",
    "verification_iterations": 3,
    "verification_evidence": [
      {
        "iteration": 1,
        "action": "run_semgrep()",
        "result": "Semgrep matched 1 location:\n  src/auth.py:47 — CWE-89: ...",
        "conclusion": "Semgrep confirms the sink is present with the source pattern."
      },
      {
        "iteration": 2,
        "action": "grep_sanitizers(validate|sanitize|escape|quote|encode)",
        "result": "No matches for pattern in src/auth.py.",
        "conclusion": "No sanitizers found. The taint path is unimpeded."
      },
      {
        "iteration": 3,
        "action": "conclude",
        "result": "Flow confirmed: request.args.get('id') → cursor.execute with no sanitizers.",
        "conclusion": "High confidence this is exploitable."
      }
    ]
  }
]
```

The `verification_evidence` array is the audit trail of the ReAct loop. Each entry shows exactly what action was taken, what it returned, and how the LLM interpreted it. This is the primary artefact for human review of the pipeline's reasoning.

---

### `validated_vulns.json` — `list[ValidatedVuln]`

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
    "sink": "cursor.execute(query)",
    "taint_path_summary": "...",
    "poc": "1' OR '1'='1'; --",
    "attack_scenario": "An unauthenticated attacker sends a GET request to /user?id=1' OR '1'='1'; -- which causes the query to return all rows in the users table, bypassing authentication and exposing all user records.",
    "exploitability": "high"
  }
]
```

---

### `pipeline_report.json` — `PipelineReport`

Summary statistics for the entire run.

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

The funnel shape (24 files → 8 findings → 5 confirmed → 3 validated) is the key quality signal. A pipeline where Phase 1 produces 8 findings and Phase 5 retains 7 suggests the confidence threshold or Phase 3 verification is too permissive. A pipeline that retains 0 from 8 suggests the LLM is being overly conservative in Phase 4.

---

## `token_usage.json`

```json
{
  "total_prompt_tokens": 487234,
  "total_completion_tokens": 18431,
  "total_tokens": 505665
}
```

Use this to estimate cost per repository at scale, and to detect regressions when model or prompt changes affect token consumption.

---

## `results.sarif` — SARIF 2.1.0

The SARIF file is compliant with [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) and importable into:

- **VS Code** — install the [SARIF Viewer](https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer) extension, then `Ctrl+Shift+P` → "SARIF: Open SARIF file"
- **GitHub Code Scanning** — upload as a workflow artifact to the `security-events` permission
- **SonarQube** — via the Generic Issue import format (requires conversion)
- **Defect Dojo** — direct SARIF import supported

### SARIF result structure

Each result includes:

| SARIF field | Contents |
|---|---|
| `ruleId` | The CWE identifier (e.g. `CWE-89`) |
| `level` | `error` for HIGH/CRITICAL, `warning` for MEDIUM, `note` for LOW |
| `message.text` | Title, attack scenario, PoC, and remediation in human-readable text |
| `locations[0].physicalLocation.artifactLocation.uri` | File path relative to `%SRCROOT%` |
| `locations[0].physicalLocation.region.startLine` | Line number of the sink |
| `fingerprints.finding_id/v1` | Stable UUID — allows deduplication across runs |
| `properties.cvss_score` | CVSS 3.1 base score (float) |
| `properties.cvss_vector` | Full CVSS vector string |
| `properties.poc` | The concrete PoC payload |
| `properties.exploitability` | `high` / `medium` / `low` |

### Importing into VS Code

```bash
# Install the extension (once)
code --install-extension MS-SarifVSCode.sarif-viewer

# Open your audit results
code ./output/results.sarif
```

The SARIF viewer will annotate the vulnerable lines directly in the editor with severity icons and the full finding detail panel on click.

---

## `report.md` — Markdown Security Report

Human-readable, self-contained security report. Structure:

```
# MoSec SAST Security Report
Generated: 2025-06-12 14:23 UTC

## Summary
| # | Severity | CVSS | CWE | File | Title |
...

---

## 1. <Title>  🔴 CRITICAL

| Field      | Value                          |
|------------|--------------------------------|
| File       | `src/auth.py:47`               |
| CWE        | CWE-89                         |
| CVSS 3.1   | CVSS:3.1/AV:N/... → 9.1 CRITICAL |
| Exploitability | high                       |

### Description
...

### Attack Scenario
...

### Impact
...

### Proof of Concept
```
1' OR '1'='1'; --
```

### Taint Flow
*See confirmed_flows.json → finding <UUID> for the full ReAct trace.*

### Remediation
Use parameterised queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
```

Findings are sorted by CVSS descending. The report is designed to be sent directly to a development team or included in a security audit document without further editing.

---

## `pipeline.log`

Structured log in `asctime  LEVEL  logger_name  message` format. Contains:
- Per-phase start/end markers
- Per-file finding counts (Phase 1)
- Per-finding taint spec results (Phase 2)
- Per-finding ReAct iteration log (Phase 3)
- Per-finding PoC result and static trace result (Phase 4)
- CVSS scores (Phase 5)
- Token usage summary

Set `--log-level DEBUG` (not currently a CLI arg — change `logging.basicConfig(level=...)` in `pipeline.py`) to see individual LLM call inputs and outputs.

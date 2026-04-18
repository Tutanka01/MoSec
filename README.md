<div align="center">

# MoSec

**LLM-Augmented Static Application Security Testing**

*Find real, exploitable vulnerabilities — not noise.*

[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://python.org)
[![Semgrep](https://img.shields.io/badge/Semgrep-≥1.75-1E90FF?logo=semgrep&logoColor=white)](https://semgrep.dev)
[![Ruff](https://img.shields.io/badge/code%20style-ruff-D7FF64?logo=ruff&logoColor=black)](https://docs.astral.sh/ruff)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/Tutanka01/MoSec/ci.yml?label=CI&logo=github)](https://github.com/Tutanka01/MoSec/actions)

</div>

---

## The problem

Every SAST tool on the market has the same problem: it reports hundreds of *possible* issues and leaves a human to figure out which ones are actually exploitable. Junior developers dismiss the alerts. Senior engineers waste hours triaging them. Real vulnerabilities get buried.

**MoSec inverts the workflow.**

Instead of flagging possible issues, it runs a multi-stage reasoning pipeline that ends with a list of vulnerabilities that each have:

| | |
|---|---|
| **Confirmed taint path** | Source → sink verified by AST-grounded ReAct loop using Semgrep + CodeQL |
| **Concrete PoC payload** | Not "malicious input" — a real string like `'; DROP TABLE users; --` |
| **CVSS 3.1 score** | Calculated from the actual exploit scenario, not a generic estimate |
| **Specific remediation** | Not "sanitise your inputs" — the exact parameterised query to use instead |

---

## Architecture

```
 ┌──────────────────────────────────────────────────────────┐
 │                    TARGET REPOSITORY                     │
 └──────────────────────────┬───────────────────────────────┘
                            │
              ╔═════════════▼══════════════╗
              ║   PHASE 0 · INGESTION      ║  tree-sitter ASTs · CodeQL DB
              ║   IngestionAgent           ║  entry points · dependency graph
              ╚═════════════╦══════════════╝
                            │  manifest.json
              ╔═════════════▼══════════════╗
              ║   PHASE 1 · TRIAGE         ║  Carlini-sweep
              ║   TriageAgent              ║  per-file LLM · confidence ≥ 0.6
              ╚═════════════╦══════════════╝
                            │  findings.json
              ╔═════════════▼══════════════╗
              ║   PHASE 2 · TAINT SPEC     ║  AST candidate grounding
              ║   TaintSpecAgent           ║  source/sink/sanitizer extraction
              ║                            ║  Semgrep taint-mode rule generation
              ╚═════════════╦══════════════╝
                            │  taint_specs.json + rule YAMLs
              ╔═════════════▼══════════════╗
              ║   PHASE 3 · DATA FLOW      ║  ReAct loop (max 5 iterations)
              ║   DataFlowAgent            ║  Semgrep · grep · CodeQL · context
              ║        +                   ║
              ║   VerifierAgent            ║  Propose → Falsify → Decide
              ║                            ║  fail-closed · self-consistency
              ╚═════════════╦══════════════╝
                            │  confirmed_flows.json
              ╔═════════════▼══════════════╗
              ║   PHASE 4 · EXPLOIT        ║  concrete PoC generation
              ║   ExploitAgent             ║  AST CFG taint BFS
              ║                            ║  function-scoped sanitizer check
              ╚═════════════╦══════════════╝
                            │  validated_vulns.json
              ╔═════════════▼══════════════╗
              ║   PHASE 5 · REPORT         ║  CVSS 3.1 scoring (local formula)
              ║   ReporterAgent            ║  SARIF 2.1.0 · markdown report
              ╚════════════════════════════╝

        LLM backend: any OpenAI-compatible endpoint
        Zero telemetry · Zero cloud · Air-gap ready
```

---

## Output

Given a vulnerable Flask application, MoSec produces two files:

<details>
<summary><strong>results.sarif</strong> — load directly in VS Code or GitHub Code Scanning</summary>

```json
{
  "ruleId": "CWE-89",
  "level": "error",
  "message": {
    "text": "SQL Injection in user endpoint\n\nPoC: `1' OR '1'='1`\n\nRemediation: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
  },
  "locations": [{
    "physicalLocation": {
      "artifactLocation": { "uri": "src/auth.py" },
      "region": { "startLine": 47 }
    }
  }],
  "codeFlows": [{ "threadFlows": [{ "locations": ["..."] }] }],
  "properties": { "cvss_score": 9.8, "exploitability": "high" }
}
```

</details>

<details>
<summary><strong>report.md</strong> — one section per finding, sorted by CVSS</summary>

```markdown
## 1. SQL Injection in user endpoint  🔴 CRITICAL

| Field  | Value                                                          |
|--------|----------------------------------------------------------------|
| File   | `src/auth.py:47`                                               |
| CWE    | CWE-89                                                         |
| CVSS   | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N → 9.1 CRITICAL  |

### Proof of Concept
1' OR '1'='1'; --

### Remediation
cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
```

</details>

---

## Quick Start

### Option 1 — Python

```bash
git clone https://github.com/Tutanka01/MoSec && cd MoSec
pip install -r requirements.txt

# Configure your LLM endpoint
cp .env.example .env
# edit .env → LLM_BASE_URL, LLM_MODEL

python pipeline.py --repo-path /path/to/target-repo --output-dir ./output
```

### Option 2 — Docker

```bash
cp .env.example .env  # edit LLM_BASE_URL and LLM_MODEL

export REPO_PATH=/absolute/path/to/target-repo
export OUTPUT_DIR=./output

docker compose up --build
```

Results land in `./output/`.

---

## CLI Reference

```
python pipeline.py --repo-path PATH [options]
```

| Option | Default | Description |
|---|---|---|
| `--repo-path PATH` | *(required)* | Local path to the repository to audit |
| `--clone-url URL` | — | Clone this URL into `--repo-path` first |
| `--output-dir DIR` | `./output` | Where to write all outputs |
| `--phase 0-5` | `0` | Resume from this phase (earlier outputs must exist) |
| `--keep-rules` | `false` | Keep generated Semgrep rule YAMLs after the run |
| `--rules-dir DIR` | *(temp dir)* | Where to write Semgrep rules |
| `--codeql-bin PATH` | `codeql` | Path to CodeQL CLI binary |

> [!TIP]
> Every phase persists its output as JSON. If a run crashes, resume from the last completed phase without re-running everything:
> ```bash
> python pipeline.py --repo-path /path/to/repo --phase 4
> ```

---

## Configuration

All settings are read from environment variables or a `.env` file:

| Variable | Default | Description |
|---|---|---|
| `LLM_BASE_URL` | `https://llm.eva.univ-pau.fr/v1` | OpenAI-compatible API endpoint |
| `LLM_MODEL` | `gemma-4-31b-it-q8_0` | Model identifier |
| `LLM_API_KEY` | *(empty)* | API key — leave empty for local endpoints |
| `MOSEC_VERIFIER_N` | `1` | Self-consistency runs for Phase 3 (set to `3` for maximum precision) |

Point `LLM_BASE_URL` at any OpenAI-compatible server: llama.cpp (`http://localhost:8080/v1`), vLLM, Ollama (`http://localhost:11434/v1`), or a standard OpenAI key.

---

## Intermediate Outputs

Each phase writes a JSON checkpoint that can be inspected or used to resume:

| File | Phase | Contents |
|---|---|---|
| `manifest.json` | 0 | Files, entry points, dependencies, AST summary, CodeQL DB path |
| `findings.json` | 1 | Per-file LLM findings with CWE, line, confidence |
| `taint_specs.json` | 2 | Source/sink/sanitizer triples + Semgrep rule paths |
| `confirmed_flows.json` | 3 | ReAct-verified taint paths with structured evidence |
| `validated_vulns.json` | 4 | Exploitable findings with concrete PoC payloads |
| `results.sarif` | 5 | SARIF 2.1.0 with `codeFlows` evidence traces |
| `report.md` | 5 | Human-readable security report sorted by CVSS |
| `token_usage.json` | 5 | Total prompt/completion token counts for the run |
| `pipeline.log` | all | Structured log with per-phase reasoning |

---

## Supported Languages

| Language | AST extraction | CodeQL | Semgrep | Entry points detected |
|---|---|---|---|---|
| Python | tree-sitter | ✓ | ✓ | Flask/Django routes, subprocess, eval, pickle, open() |
| JavaScript | tree-sitter | ✓ | ✓ | Express routes, child_process, eval, innerHTML |
| TypeScript | tree-sitter (JS fallback) | ✓ | ✓ | Same as JS |
| PHP | tree-sitter | — | ✓ | $_GET/$_POST, exec, system, shell_exec, eval |

---

## Benchmark

```bash
python -m benchmarks.runner --suite benchmarks/cases --output output/bench_report.json
```

Emits Precision / Recall / F1 per CWE. Exit code 1 if F1 < 0.5.

```
════════════════════════════════════════════════════
  MoSec Benchmark Results
════════════════════════════════════════════════════
  Total cases : 12
  TP=8  FP=1  TN=2  FN=1
  Precision   : 88.9%
  Recall      : 88.9%
  F1          : 88.9%
  Accuracy    : 83.3%
════════════════════════════════════════════════════
```

---

## Requirements

- Python 3.12
- Semgrep ≥ 1.75.0
- An OpenAI-compatible LLM endpoint
- CodeQL CLI — optional, degrades gracefully if absent

---

## Documentation

Full technical reference in [`docs/pipeline.md`](docs/pipeline.md):

- Phase-by-phase internals and design decisions
- ReAct loop and Propose → Falsify → Decide verifier
- LLM interaction patterns, retry logic, JSON extraction
- CI/CD pipeline setup

---

## License

MIT — do whatever you want with it. If you find a real CVE with it, let me know.

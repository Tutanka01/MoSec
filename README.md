# MoSec SAST — LLM-Augmented Security Audit Pipeline

> **Find real, exploitable vulnerabilities. Not noise.**

A production-grade, fully self-hosted static application security testing pipeline that combines three industrial-strength SAST engines — Semgrep, CodeQL, tree-sitter — orchestrated by specialised LLM agents. Zero cloud dependencies. Every byte of your code stays on your infrastructure.

---

## Why this is different

Every SAST tool on the market has the same problem: it reports hundreds of potential issues and leaves a human to figure out which ones are actually exploitable. Junior developers dismiss the alerts. Senior engineers waste hours triaging them. Real vulnerabilities get buried.

MoSec inverts the workflow.

Instead of flagging *possible* issues and asking humans to verify, it runs a multi-stage reasoning pipeline that ends with a list of vulnerabilities that have:

- A **confirmed source-to-sink taint path** — verified by AST-grounded ReAct loop using Semgrep + CodeQL + intra-procedural CFG, not just pattern-matched
- A **concrete proof-of-concept payload** (not "malicious input" — a real string like `'; DROP TABLE users; --`)
- A **CVSS 3.1 score** calculated from the actual exploit scenario
- A **specific code-level remediation** — not "sanitise your inputs", but the exact parameterised query you should use instead

The output is a SARIF 2.1.0 file (with `codeFlows` evidence traces) you can load directly into VS Code or GitHub Code Scanning, and a markdown report your security team can read without a PhD in program analysis.

---

## Architecture at a glance

```
 ┌──────────────────────────────────────────────────────────────────┐
 │                     TARGET REPOSITORY                            │
 └──────────────────────────┬───────────────────────────────────────┘
                            │
              ╔═════════════▼══════════════╗
              ║   PHASE 0 · INGESTION      ║  tree-sitter ASTs
              ║                            ║  CodeQL database
              ║   IngestionAgent           ║  entry points
              ║                            ║  dependency graph
              ╚═════════════╦══════════════╝
                            │  manifest.json
              ╔═════════════▼══════════════╗
              ║   PHASE 1 · TRIAGE         ║  Carlini-sweep
              ║                            ║  per-file LLM analysis
              ║   TriageAgent              ║  confidence filter ≥ 0.6
              ║                            ║
              ╚═════════════╦══════════════╝
                            │  findings.json
              ╔═════════════▼══════════════╗
              ║   PHASE 2 · TAINT SPEC     ║  AST candidate extraction
              ║                            ║  source / sink grounding
              ║   TaintSpecAgent           ║  sink_kind-aware Semgrep rules
              ║                            ║  semgrep --validate before write
              ╚═════════════╦══════════════╝
                            │  taint_specs.json + rule YAMLs
              ╔═════════════▼══════════════╗
              ║   PHASE 3 · DATAFLOW       ║  ReAct loop (max 5 iters)
              ║                            ║  action dedup + validation
              ║   DataFlowAgent            ║  StructuredEvidence (hits+lines)
              ║          +                 ║  CodeQL TaintTracking query
              ║   VerifierAgent            ║  Propose → Falsify → Decide
              ║                            ║  fail-closed verdict
              ╚═════════════╦══════════════╝
                            │  confirmed_flows.json
              ╔═════════════▼══════════════╗
              ║   PHASE 4 · EXPLOIT        ║  concrete PoC generation
              ║                            ║  AST CFG taint BFS
              ║   ExploitAgent             ║  function-scoped sanitizer check
              ║                            ║  counterfactual PoC validation
              ╚═════════════╦══════════════╝
                            │  validated_vulns.json
              ╔═════════════▼══════════════╗
              ║   PHASE 5 · REPORT         ║  CVSS 3.1 scoring
              ║                            ║  SARIF 2.1.0 + codeFlows
              ║   ReporterAgent            ║  markdown security report
              ║                            ║
              ╚════════════════════════════╝

                LLM backend: any OpenAI-compatible endpoint
                Default: local llama-server (Qwen2.5-Coder)
                Zero telemetry. Zero cloud. Air-gap ready.
```

---

## What comes out

Given a vulnerable Flask application, MoSec produces:

**`output/results.sarif`** — load directly in VS Code or GitHub Code Scanning:
```json
{
  "ruleId": "CWE-89",
  "level": "error",
  "message": {
    "text": "SQL Injection in user endpoint\n\nPoC: `1' OR '1'='1`\n\nRemediation: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
  },
  "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/auth.py"}, "region": {"startLine": 47}}}],
  "codeFlows": [{"threadFlows": [{"locations": [...]}]}],
  "properties": {"cvss_score": 9.8, "exploitability": "high"}
}
```

**`output/report.md`** — one section per finding, sorted by CVSS:

```markdown
## 1. SQL Injection in user endpoint  🔴 CRITICAL

| Field   | Value                                                         |
|---------|---------------------------------------------------------------|
| File    | `src/auth.py:47`                                              |
| CWE     | CWE-89                                                        |
| CVSS    | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N → 9.1 CRITICAL |

### Proof of Concept

1' OR '1'='1'; --

### Remediation
Use parameterised queries: `cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))`
```

---

## Quick start

### Option 1 — Python directly

```bash
git clone <this-repo> && cd mosec

# Install dependencies (Python 3.12)
pip install -r requirements.txt

# Configure your LLM endpoint
cp .env.example .env
# edit .env → LLM_BASE_URL, LLM_MODEL

# Run
python pipeline.py --repo-path /path/to/target-repo --output-dir ./output
```

### Option 2 — Docker Compose

```bash
cp .env.example .env
# edit .env

export REPO_PATH=/absolute/path/to/target-repo
export OUTPUT_DIR=./output

docker compose up --build
```

Results land in `./output/`.

---

## Usage reference

```
python pipeline.py --repo-path PATH [options]

Required:
  --repo-path PATH        Local path to the repository to audit.

Optional:
  --clone-url URL         Clone this URL into --repo-path first.
  --output-dir DIR        Where to write outputs.           [default: ./output]
  --phase 0-5             Resume pipeline from this phase.
                          Intermediate JSON from earlier phases must exist.
  --keep-rules            Do not delete generated Semgrep rule YAMLs.
  --rules-dir DIR         Where to write Semgrep rules.     [default: /tmp/audit_rules]
  --codeql-bin PATH       Path to CodeQL CLI binary.        [default: codeql]
```

### Resuming from a specific phase

Every phase persists its output as JSON. If a phase crashes halfway through, you don't re-run everything:

```bash
# Re-run only Phase 4 and 5, loading Phase 3's output from disk
python pipeline.py --repo-path /path/to/repo --phase 4
```

### Running the benchmark suite

```bash
python -m benchmarks.runner --suite benchmarks/cases --output output/bench_report.json
```

Emits Precision / Recall / F1 per CWE. Exit code 1 if F1 < 0.5 (CI gate).

---

## Configuration

All settings are read from environment variables (or a `.env` file):

| Variable | Default | Description |
|---|---|---|
| `LLM_BASE_URL` | `http://localhost:8080/v1` | OpenAI-compatible API endpoint |
| `LLM_MODEL` | `qwen2.5-coder` | Model identifier |
| `LLM_API_KEY` | _(empty)_ | API key — leave empty for local endpoints |
| `MOSEC_VERIFIER_N` | `1` | Self-consistency runs for VerifierAgent (set to `3` for maximum precision) |

Point `LLM_BASE_URL` at any OpenAI-compatible server: llama.cpp, vLLM, Ollama, LM Studio, or an actual OpenAI key.

---

## Supported languages

| Language | AST extraction | CodeQL | Semgrep | Entry points |
|---|---|---|---|---|
| Python | stdlib `ast` | ✅ | ✅ | Routes, subprocess, eval, pickle, open() |
| JavaScript | tree-sitter | ✅ | ✅ | Express routes, child_process, eval, innerHTML |
| TypeScript | tree-sitter (JS fallback) | ✅ | ✅ | Same as JS |

---

## Intermediate outputs

| File | Phase | Contents |
|---|---|---|
| `manifest.json` | 0 | Files, entry points, deps, AST summary, CodeQL DB path |
| `findings.json` | 1 | Per-file LLM findings (confidence ≥ 0.6) |
| `taint_specs.json` | 2 | Source/sink/sanitizer + AST metadata (sink_kind, coordinates) |
| `confirmed_flows.json` | 3 | ReAct-verified taint paths with StructuredEvidence |
| `validated_vulns.json` | 4 | Exploitable vulns with concrete PoC |
| `results.sarif` | 5 | SARIF 2.1.0 with codeFlows evidence traces |
| `report.md` | 5 | Human-readable security report |
| `token_usage.json` | 5 | Prompt/completion token counts per run |
| `pipeline.log` | all | Structured log with per-phase reasoning |

---

## Requirements

- Python 3.12
- Semgrep ≥ 1.75.0 (`pip install semgrep`) or available in `PATH`
- `tree-sitter-python`, `tree-sitter-javascript` (already in `requirements.txt`)
- CodeQL CLI — optional, degrades gracefully if absent
- A reachable OpenAI-compatible LLM endpoint

---

## Technical documentation

See [`docs/`](docs/) for deep-dives:

| Document | Contents |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | System design, data flow, design decisions |
| [`docs/agents.md`](docs/agents.md) | Each agent's internals, prompts, algorithms |
| [`docs/llm-prompting.md`](docs/llm-prompting.md) | Prompting strategy, Carlini sweep, ThinkAndVerify |
| [`docs/output-formats.md`](docs/output-formats.md) | SARIF schema, codeFlows, markdown report |
| [`docs/deployment.md`](docs/deployment.md) | Docker, air-gap setup, resource tuning |
| [`docs/extending.md`](docs/extending.md) | Adding new languages, custom agent phases |

---

## License

MIT — do whatever you want with it. If you find a real CVE with it, please let me know.

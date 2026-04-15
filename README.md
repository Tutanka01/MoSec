# MoSec SAST — LLM-Centred Security Audit Pipeline

> **Find real, exploitable vulnerabilities. Not noise.**

A production-grade, fully self-hosted static application security testing pipeline that combines three industrial-strength SAST engines — Semgrep, CodeQL, tree-sitter — orchestrated by six specialised LLM agents running in sequence. Zero cloud dependencies. Every byte of your code stays on your infrastructure.

---

## Why this is different

Every SAST tool on the market has the same problem: it reports hundreds of potential issues and leaves a human to figure out which ones are actually exploitable. Junior developers dismiss the alerts. Senior engineers waste hours triaging them. Real vulnerabilities get buried.

MoSec inverts the workflow.

Instead of flagging *possible* issues and asking humans to verify, it runs a five-stage reasoning pipeline that ends with a list of vulnerabilities that have:

- A **confirmed source-to-sink taint path** (ReAct-verified, not just pattern-matched)
- A **concrete proof-of-concept payload** (not "malicious input" — a real string like `'; DROP TABLE users; --`)
- A **CVSS 3.1 score** calculated from the actual exploit scenario
- A **specific code-level remediation** — not "sanitise your inputs", but the exact parameterised query you should use instead

The output is a SARIF file you can load directly into VS Code or GitHub Code Scanning, and a markdown report your security team can read without a PhD in program analysis.

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
              ║   PHASE 2 · TAINT SPEC     ║  source / sink isolation
              ║                            ║  sanitizer detection
              ║   TaintSpecAgent           ║  Semgrep rule generation
              ║                            ║
              ╚═════════════╦══════════════╝
                            │  taint_specs.json + rule YAMLs
              ╔═════════════▼══════════════╗
              ║   PHASE 3 · DATAFLOW       ║  Semgrep execution
              ║                            ║  ReAct loop (max 5 iters)
              ║   DataFlowAgent            ║  CodeQL inline queries
              ║                            ║  sanitizer blocking check
              ╚═════════════╦══════════════╝
                            │  confirmed_flows.json
              ╔═════════════▼══════════════╗
              ║   PHASE 4 · EXPLOIT        ║  concrete PoC generation
              ║                            ║  static reachability trace
              ║   ExploitAgent             ║  false-positive elimination
              ║                            ║
              ╚═════════════╦══════════════╝
                            │  validated_vulns.json
              ╔═════════════▼══════════════╗
              ║   PHASE 5 · REPORT         ║  CVSS 3.1 scoring
              ║                            ║  SARIF 2.1.0 output
              ║   ReporterAgent            ║  markdown security report
              ║                            ║
              ╚════════════════════════════╝

                LLM backend: any OpenAI-compatible endpoint
                Default: gemma-4-31b-it-q8_0 (local llama-server)
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
  "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "src/auth.py" }, "region": { "startLine": 47 } } }],
  "properties": { "cvss_score": 9.8, "exploitability": "high" }
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
```
1' OR '1'='1'; --
```

### Remediation
Use parameterised queries: `cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))`
```

---

## Quick start

### Option 1 — Python directly

```bash
git clone <this-repo> && cd sast-agent

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
  --output-dir DIR        Where to write outputs.  [default: ./output]
  --phase 0-5             Resume pipeline from this phase.
                          Intermediate JSON from earlier phases must exist.
  --keep-rules            Do not delete generated Semgrep rule YAMLs.
  --rules-dir DIR         Where to write Semgrep rules.  [default: /tmp/audit_rules]
  --codeql-bin PATH       Path to CodeQL CLI binary.    [default: codeql]
```

### Resuming from a specific phase

Every phase persists its output as JSON. If the LLM call for Phase 4 crashes halfway through, you don't re-run everything from scratch:

```bash
# Re-run only Phase 4 and 5, loading Phase 3's output from disk
python pipeline.py --repo-path /path/to/repo --phase 4
```

---

## Configuration

All settings are read from environment variables (or a `.env` file):

| Variable | Default | Description |
|---|---|---|
| `LLM_BASE_URL` | `https://llm.eva.univ-pau.fr/v1` | OpenAI-compatible API endpoint |
| `LLM_MODEL` | `gemma-4-31b-it-q8_0` | Model identifier |
| `LLM_API_KEY` | _(empty)_ | API key — leave empty for local endpoints |

Point it at any OpenAI-compatible server: llama.cpp, vLLM, Ollama, LM Studio, or an actual OpenAI key.

---

## Supported languages (MVP)

| Language | AST | CodeQL | Semgrep | Entry points |
|---|---|---|---|---|
| Python | ✅ tree-sitter | ✅ | ✅ | Routes, subprocess, eval, pickle, open() |
| JavaScript | ✅ tree-sitter | ✅ | ✅ | Express routes, child_process, eval, JSON.parse |
| TypeScript | ✅ tree-sitter | ✅ | ✅ | Same as JS |

---

## Intermediate outputs

| File | Phase | Contents |
|---|---|---|
| `manifest.json` | 0 | Files, entry points, deps, AST summary, CodeQL DB path |
| `findings.json` | 1 | Per-file LLM findings (confidence ≥ 0.6) |
| `taint_specs.json` | 2 | Source/sink/sanitizer for each finding |
| `confirmed_flows.json` | 3 | ReAct-verified taint paths |
| `validated_vulns.json` | 4 | Exploitable vulns with concrete PoC |
| `results.sarif` | 5 | SARIF 2.1.0 — importable in VS Code / GitHub |
| `report.md` | 5 | Human-readable security report |
| `token_usage.json` | 5 | Prompt/completion token counts per run |
| `pipeline.log` | all | Structured log with per-phase reasoning |

---

## Requirements

- Python 3.12
- Semgrep (`pip install semgrep`) or available in `PATH`
- CodeQL CLI — optional, degrades gracefully if absent
- A reachable OpenAI-compatible LLM endpoint

---

## Technical documentation

See [`docs/`](docs/) for deep-dives:

| Document | Contents |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | System design, data flow, design decisions |
| [`docs/agents.md`](docs/agents.md) | Each agent's internals, prompts, algorithms |
| [`docs/llm-prompting.md`](docs/llm-prompting.md) | Prompting strategy, Carlini sweep, ReAct |
| [`docs/output-formats.md`](docs/output-formats.md) | SARIF schema, markdown report structure |
| [`docs/deployment.md`](docs/deployment.md) | Docker, air-gap setup, resource tuning |
| [`docs/extending.md`](docs/extending.md) | Adding new languages, custom agent phases |

---

## License

MIT — do whatever you want with it. If you find a real CVE with it, please let me know.

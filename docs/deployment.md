# Deployment Guide

## Local Python (fastest for development)

```bash
cd sast-agent

# Create a virtual environment
python3.12 -m venv .venv
source .venv/bin/activate       # Linux/macOS
.venv\Scripts\activate          # Windows

# Install dependencies
pip install -r requirements.txt

# Configure
cp .env.example .env
# Edit .env:
#   LLM_BASE_URL=https://llm.eva.univ-pau.fr/v1
#   LLM_MODEL=gemma-4-31b-it-q8_0
#   LLM_API_KEY=

# Run
python pipeline.py --repo-path /path/to/target-repo
```

Outputs land in `./output/` by default.

---

## Docker Compose (recommended for production)

### Build

```bash
cd sast-agent
docker compose build
```

The Dockerfile downloads the CodeQL bundle during build (~1 GB). If you don't need CodeQL, comment out the CodeQL block in the Dockerfile — this reduces image size significantly and speeds up the build.

### Run

```bash
export REPO_PATH=/absolute/path/to/target-repo
export OUTPUT_DIR=/absolute/path/to/output

# Ensure LLM settings are in .env
cp .env.example .env

docker compose up
```

### Override the command

```bash
# Resume from Phase 2, keep Semgrep rules
docker compose run sast-agent --repo-path /repo --output-dir /output --phase 2 --keep-rules

# Audit a public GitHub repo by cloning it first
docker compose run sast-agent \
  --repo-path /repo/myapp \
  --clone-url https://github.com/example/vulnerable-app \
  --output-dir /output
```

### Volume layout

| Container path | Purpose | Recommended host mount |
|---|---|---|
| `/repo` | Target repository (read-only) | `${REPO_PATH}:/repo:ro` |
| `/output` | All pipeline outputs | `${OUTPUT_DIR}:/output` |
| `/tmp/audit_rules` | Temporary Semgrep rules | `/tmp/audit_rules:/tmp/audit_rules` |

---

## Air-gap / offline deployment

MoSec makes no outbound connections at runtime except to the configured LLM endpoint. To run fully offline:

### 1. LLM backend

Run any OpenAI-compatible server locally:

**llama.cpp server:**
```bash
./llama-server \
  -m /models/gemma-4-31b-it-q8_0.gguf \
  --host 0.0.0.0 --port 8080 \
  --ctx-size 32768 \
  -np 4
```

Set `LLM_BASE_URL=http://localhost:8080/v1` in `.env`.

**vLLM:**
```bash
python -m vllm.entrypoints.openai.api_server \
  --model /models/gemma-3-4b-it \
  --host 0.0.0.0 --port 8080
```

**Ollama:**
```bash
ollama serve &
ollama pull gemma3:27b

# Ollama's OpenAI-compat endpoint
# LLM_BASE_URL=http://localhost:11434/v1
# LLM_MODEL=gemma3:27b
```

### 2. Semgrep offline

Semgrep does not require internet access to run custom rules. MoSec only uses the rules it generates itself — no Semgrep registry calls.

### 3. CodeQL offline

CodeQL queries run against the local database. No internet access needed. The CodeQL bundle can be downloaded once and baked into a Docker image.

### 4. Pre-built Docker image

```bash
# On a connected machine
docker build -t mosec-sast:offline .
docker save mosec-sast:offline | gzip > mosec-sast.tar.gz

# Transfer to air-gapped host, then
docker load < mosec-sast.tar.gz
```

---

## CI/CD integration

### GitHub Actions

```yaml
name: MoSec SAST Audit

on:
  push:
    branches: [main, develop]
  pull_request:

jobs:
  sast:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install MoSec SAST
        run: |
          cd sast-agent
          pip install -r requirements.txt

      - name: Run MoSec SAST
        env:
          LLM_BASE_URL: ${{ secrets.LLM_BASE_URL }}
          LLM_MODEL: ${{ secrets.LLM_MODEL }}
          LLM_API_KEY: ${{ secrets.LLM_API_KEY }}
        run: |
          cd sast-agent
          python pipeline.py \
            --repo-path ${{ github.workspace }} \
            --output-dir ./output

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: sast-agent/output/results.sarif

      - name: Upload full report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: mosec-sast-report
          path: |
            sast-agent/output/report.md
            sast-agent/output/validated_vulns.json
            sast-agent/output/token_usage.json
```

The SARIF upload to GitHub Code Scanning surfaces findings inline on pull requests. The action exits with code 1 if any validated vulnerabilities are found, which blocks merges on security regressions.

### GitLab CI

```yaml
mosec-sast:
  image: python:3.12-slim
  stage: test
  before_script:
    - cd sast-agent && pip install -r requirements.txt
  script:
    - python pipeline.py --repo-path $CI_PROJECT_DIR --output-dir ./output
  artifacts:
    when: always
    paths:
      - sast-agent/output/results.sarif
      - sast-agent/output/report.md
    reports:
      sast: sast-agent/output/results.sarif
  variables:
    LLM_BASE_URL: $LLM_BASE_URL
    LLM_MODEL: $LLM_MODEL
    LLM_API_KEY: $LLM_API_KEY
```

---

## Resource requirements

These are rough guidelines based on testing with Gemma 4 31B Q8.

| Codebase size | Files | Phase 1 tokens | Total time (Q8 local) |
|---|---|---|---|
| Small (< 5K LoC) | ~20 | ~40K | 2–5 min |
| Medium (5–20K LoC) | ~80 | ~160K | 10–20 min |
| Large (20–100K LoC) | ~400 | ~800K | 45–90 min |
| Very large (> 100K LoC) | ~2000+ | ~4M+ | Use `--phase` to split |

For very large repositories, consider:
1. Running Phase 0 and 1 once, then resuming Phase 2+ after reviewing findings
2. Using a faster/smaller model for Phase 1 (bulk triage) and a larger model for Phases 3–5 (verification)
3. Filtering `manifest.files` in `manifest.json` to focus on high-risk directories before running Phase 1

### Memory

The pipeline holds at most one phase's output in memory at a time (JSON-parsed). Memory usage is dominated by the LLM server, not the pipeline process itself.

### Disk

Each intermediate JSON file is typically 1–10 KB per finding. The CodeQL database can be 50–500 MB depending on repository size. The Semgrep rule files are negligible.

---

## Benchmark suite

The benchmark suite measures pipeline quality end-to-end against a ground-truth corpus of 10 cases: 5 true positives, 3 false positives, and 2 hard edge cases. Run it after every change to agents, prompts, or schemas.

### Quick start

```bash
# From the project root (LLM endpoint must be running)
python -m benchmarks.runner

# Custom suite directory and output path
python -m benchmarks.runner \
  --suite benchmarks/cases \
  --output output/bench_report.json
```

Exit code 0 when F1 ≥ 0.5, exit code 1 otherwise (CI gate).

---

### Reading the report

The runner prints a summary to stdout and writes `output/bench_report.json`:

```
============================================================
  MoSec Benchmark Results
============================================================
  Total cases : 10
  TP=5  FP=0  TN=3  FN=2
  Precision   : 100.0%
  Recall      : 71.4%
  F1          : 83.3%
  Accuracy    : 80.0%
  Elapsed     : 312.4s
============================================================

  Per-CWE breakdown:
    CWE-22               P=100%  R=100%  F1=100%  (TP=1 FP=0 FN=0)
    CWE-78               P=100%  R=100%  F1=100%  (TP=1 FP=0 FN=0)
    CWE-79               P=100%  R=67%   F1=80%   (TP=2 FP=0 FN=1)
    CWE-89               P=100%  R=100%  F1=100%  (TP=2 FP=0 FN=0)
```

**Reading the per-CWE table:**

| Metric | What it means when low |
|---|---|
| **Precision** | Pipeline is producing false positives for this CWE. Check VerifierAgent prompts, sanitizer detection. |
| **Recall** | Pipeline is missing real vulnerabilities. Check triage confidence threshold, ReAct loop depth. |
| **F1** | Combined. Below 0.7 is a sign something structural is wrong for that CWE. |

**Expected baseline after Lots A–D:**

| CWE | Expected P | Expected R | Notes |
|---|---|---|---|
| CWE-79 (XSS) | ≥ 90% | ≥ 60% | Inter-proc edge case (hard) may be a FN |
| CWE-89 (SQLi) | ≥ 95% | ≥ 80% | Parameterized FP is the canary |
| CWE-78 (CMDi) | ≥ 95% | ≥ 90% | shlex.quote FP is well-detected |
| CWE-22 (LFI) | ≥ 90% | ≥ 80% | path traversal is typically clear |

---

### Case inventory

| Case | Label | CWE | Difficulty | What it tests |
|---|---|---|---|---|
| `tp_flask_xss` | TP | CWE-79 | normal | `request.args.get` → `make_response` |
| `tp_flask_sqli` | TP | CWE-89 | normal | string concat → `cursor.execute` |
| `tp_flask_cmdi` | TP | CWE-78 | normal | `request.args.get` → `os.system` |
| `tp_flask_path_traversal` | TP | CWE-22 | normal | `request.args.get` → `open()` |
| `tp_js_xss` | TP | CWE-79 | normal | `req.query` → `innerHTML` in template |
| `fp_flask_xss_escaped` | FP | CWE-79 | normal | `html.escape` sanitizer — must NOT validate |
| `fp_flask_sqli_parameterized` | FP | CWE-89 | normal | `?` placeholder — must NOT validate |
| `fp_flask_cmdi_shlex` | FP | CWE-78 | normal | `shlex.quote` — must NOT validate |
| `edge_interproc_xss` | TP | CWE-79 | hard | Source and sink in different functions |
| `edge_sanitizer_bypass` | TP | CWE-89 | hard | Sanitizer only on one conditional branch |

**Hard cases** (`difficulty: hard`) test capabilities that require inter-procedural analysis or branch-sensitive reasoning. They are expected to be false negatives until the global taint graph (Lot E) is implemented. Their failures do not count against the CI F1 gate.

To run only normal-difficulty cases:

```bash
# Create a symlink or copy to a filtered suite dir, or
# filter manually by checking expected.json difficulty field
python -c "
import json, pathlib, shutil, tempfile, sys
src = pathlib.Path('benchmarks/cases')
dst = pathlib.Path('benchmarks/cases_normal')
dst.mkdir(exist_ok=True)
for exp in src.glob('*.expected.json'):
    d = json.loads(exp.read_text())
    if d.get('difficulty', 'normal') == 'normal':
        code = exp.with_suffix('').with_suffix(exp.suffix.replace('.expected.json', ''))
        # find the code file
        for ext in ['.py', '.js']:
            code = src / (exp.stem.replace('.expected', '') + ext)
            if code.exists():
                shutil.copy(code, dst / code.name)
                shutil.copy(exp, dst / exp.name)
"
python -m benchmarks.runner --suite benchmarks/cases_normal
```

---

### CI integration

#### GitHub Actions — benchmark gate

Add a benchmark job to your workflow. It runs in parallel with the full SAST audit and gates merges on F1 quality:

```yaml
jobs:
  sast:
    # ... existing audit job ...

  benchmark:
    name: Pipeline quality gate
    runs-on: ubuntu-latest
    needs: []   # runs in parallel with sast
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Run benchmark suite
        env:
          LLM_BASE_URL: ${{ secrets.LLM_BASE_URL }}
          LLM_MODEL: ${{ secrets.LLM_MODEL }}
          LLM_API_KEY: ${{ secrets.LLM_API_KEY }}
        run: |
          python -m benchmarks.runner \
            --suite benchmarks/cases \
            --output output/bench_report.json
        # exit 1 when F1 < 0.5 — blocks the merge

      - name: Upload benchmark report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: bench-report
          path: output/bench_report.json
```

#### GitLab CI

```yaml
benchmark:
  stage: test
  script:
    - pip install -r requirements.txt
    - python -m benchmarks.runner --suite benchmarks/cases --output output/bench_report.json
  artifacts:
    when: always
    paths:
      - output/bench_report.json
  variables:
    LLM_BASE_URL: $LLM_BASE_URL
    LLM_MODEL:    $LLM_MODEL
    LLM_API_KEY:  $LLM_API_KEY
```

---

### Debugging a failing case

When a TP case is a false negative (pipeline didn't find it), follow this checklist:

```
1. Phase 1 drop?
   Check output/bench_tmp/<run_id>/findings.json
   → Empty: triage missed it. Lower confidence threshold or
     check the LLM's context window for the test file.

2. Phase 2 drop?
   Check taint_specs.json
   → Empty: taint spec failed to parse. Look at pipeline.log for
     "Phase 2 | JSON parse failed". Run the case file directly
     through TaintSpecAgent with DEBUG logging.

3. Phase 3 drop?
   Check confirmed_flows.json
   → Empty: VerifierAgent returned "unreachable" or "sanitized".
     Inspect verification_evidence in confirmed_flows.json — look
     at each iteration's action and structured.summary.
     Common cause: Semgrep rule was invalid (check --keep-rules output).

4. Phase 4 drop?
   Check validated_vulns.json
   → Empty: ExploitAgent dropped it. Either:
     (a) LLM returned poc=null — hallucinated a false positive.
     (b) _static_trace returned False — check with DEBUG logging
         what the CFG BFS found (or didn't find).
```

**Debug a single case interactively:**

```python
# Drop into a REPL with the test case loaded
import sys; sys.path.insert(0, '.')
from utils.ast_extractor import TaintCandidateExtractor
from pathlib import Path

code_file = "benchmarks/cases/tp_flask_sqli.py"
extractor = TaintCandidateExtractor()

# Check what the AST extractor finds
candidates = extractor.extract(code_file, center_line=10, cwe="CWE-89")
for c in candidates:
    print(f"  {c.kind:6s} {c.name:40s} line={c.line} kind={c.sink_kind}")

# Check the CFG
cfg = extractor.get_cfg(code_file, center_line=10)
print("\ndef_use:", dict(cfg._def_use))
print("sink_args:", dict(cfg._sink_args))

reached, path = cfg.taint_bfs({'user_id', 'get'}, 'execute', barriers=set())
print(f"\nTaint BFS → reached={reached}, path={path}")
```

When a FP case is a false positive (pipeline validated when it shouldn't have):

```
1. Check Phase 2 taint_specs.json → sanitizers field
   → Should contain the sanitizer (html.escape, shlex.quote, etc.)
   → If empty: LLM missed the sanitizer despite the AST candidate.
     Add it to _PYTHON_SOURCES or strong_sanitizers in exploit.py.

2. Check Phase 3 confirmed_flows.json → verification_evidence
   → Look for grep_sanitizers action — did it find the sanitizer?
   → If not found: the pattern didn't match. Add a more specific
     regex to the sanitizer patterns in the VerifierAgent Decide prompt.

3. Phase 4 _static_trace: the sanitizer should appear on the same
   line as the sink call. If the sanitizer wraps the tainted variable
   in a separate assignment, add it to the barriers set passed to
   cfg.taint_bfs() via the TaintSpec.sanitizers field.
```

---

### Tracking quality over time

After each significant change (new agent logic, prompt tuning, model switch), run the benchmark and record the results:

```bash
# Tag the current results with the git commit
git_hash=$(git rev-parse --short HEAD)
cp output/bench_report.json "output/bench_${git_hash}.json"
```

Compare two runs:

```python
import json
from pathlib import Path

def load(path):
    return json.loads(Path(path).read_text())

before = load("output/bench_abc1234.json")["summary"]
after  = load("output/bench_report.json")["summary"]

for metric in ("precision", "recall", "f1", "accuracy"):
    delta = after[metric] - before[metric]
    sign  = "+" if delta >= 0 else ""
    print(f"  {metric:12s}  {before[metric]:.1%} → {after[metric]:.1%}  ({sign}{delta:.1%})")
```

```
  precision     100.0% → 100.0%  (+0.0%)
  recall         57.1% →  71.4%  (+14.3%)
  f1             72.7% →  83.3%  (+10.6%)
  accuracy       70.0% →  80.0%  (+10.0%)
```

A recall regression on normal-difficulty cases is a red flag — it means a real class of vulnerability is being missed. An F1 regression of more than 5 points should block a merge.

---

## Tuning for accuracy vs. speed

### Faster (less accurate)

- Lower `_MAX_FILE_CHARS` in `agents/triage.py` (e.g. 20K chars)
- Reduce `_MAX_ITERATIONS` in `agents/dataflow.py` (e.g. 3)
- Reduce context windows in Phase 2 and 4 (`_CONTEXT_LINES`, `_CODE_CONTEXT_LINES`)
- Use a smaller, faster model (trade reasoning quality for throughput)

### More accurate (slower)

- Raise `_MAX_FILE_CHARS` to include more of large files
- Increase `_MAX_ITERATIONS` to 7–10 for harder cross-file flows
- Increase context windows (more lines around each finding)
- Use a larger, more capable model for Phases 3–5

### Tuning the confidence threshold

Edit `MIN_CONFIDENCE` in `agents/triage.py`:
- `0.7` — fewer findings, higher precision (recommended for noisy codebases)
- `0.6` — current default, balanced
- `0.5` — more findings, lower precision (use only with strong Phase 3 filtering)

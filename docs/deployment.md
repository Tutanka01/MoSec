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

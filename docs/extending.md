# Extending MoSec SAST

MoSec is designed to be extended. This document covers the five most common extension scenarios.

---

## Adding a new language

Support for a new language requires changes in five places.

### 1. File collection (`agents/ingestion.py`)

Add the file extension to `_EXT`:

```python
_EXT = {".py", ".js", ".ts", ".jsx", ".tsx", ".rb"}  # add .rb for Ruby
```

### 2. Entry point patterns (`agents/ingestion.py`)

Add a pattern dict for the new language and wire it into `_extract_entry_points()`.

### 3. Semgrep language identifier (`utils/sast.py`)

`_LANG_MAP` in `utils/sast.py` maps file suffix to Semgrep language identifier:

```python
_LANG_MAP: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".rb": "ruby",           # add this
}
```

### 4. AST candidate extraction (`utils/ast_extractor.py`)

Add known sources/sinks for the new language to the dictionaries at the top of `ast_extractor.py`:

```python
_RUBY_SOURCES: set[str] = {
    "params[]", "params.require", "cookies[]",
    "request.body.read", "request.raw_post",
}

_RUBY_SINKS_BY_CWE: dict[str, list[tuple[str, str]]] = {
    "CWE-89": [("execute", "method_call"), ("exec_query", "method_call")],
    "CWE-78": [("system", "call"), ("exec", "call"), ("`", "call")],
    ...
}
```

Then add a handler in `TaintCandidateExtractor.extract()` and `get_cfg()`:

```python
elif suffix == ".rb":
    return self._extract_ruby(code, center_line, cwe, radius)
```

For Ruby, use tree-sitter if `pip install tree-sitter-ruby` is available, or add it to `requirements.txt`.

### 5. tree-sitter parser (`agents/ingestion.py`)

Install the grammar:

```bash
pip install tree-sitter-ruby
```

Add to `requirements.txt`:
```
tree-sitter-ruby>=0.22.0
```

Add the parser in `_init_parsers()`:

```python
import tree_sitter_ruby as tsruby
self._rb_parser = Parser(Language(tsruby.language()))
```

---

## Adding a custom agent phase

Example: a Phase 2.5 that cross-references taint specs against a known CVE database.

### 1. Create the agent class

```python
# agents/cve_check.py
from models.schemas import TaintSpec
import logging

logger = logging.getLogger(__name__)

class CVECheckAgent:
    """Phase 2.5: annotate taint specs with matching CVE references."""

    KNOWN_PATTERNS = {
        "pickle.loads": "CVE-2019-20907 (pickle deserialization)",
        "yaml.load":    "CVE-2017-18342 (PyYAML unsafe load)",
    }

    def run(self, specs: list[TaintSpec]) -> list[TaintSpec]:
        for spec in specs:
            for pattern, cve_ref in self.KNOWN_PATTERNS.items():
                if pattern in spec.sink.lower():
                    logger.info("CVE match | %s → %s", spec.finding_id, cve_ref)
        return specs  # annotates; does not filter
```

### 2. Wire it into `pipeline.py`

```python
from agents.cve_check import CVECheckAgent

# Between Phase 2 and Phase 3:
taint_specs = agent2.run(findings)
agent25 = CVECheckAgent()
taint_specs = agent25.run(taint_specs)
```

---

## Swapping or splitting the LLM backend

`LLMClient` talks to any OpenAI-compatible endpoint. Change the backend in `.env`:

```bash
# Local llama.cpp server
LLM_BASE_URL=http://localhost:8080/v1
LLM_MODEL=qwen2.5-coder-32b

# Ollama
LLM_BASE_URL=http://localhost:11434/v1
LLM_MODEL=llama3.3:70b

# vLLM (remote, with auth)
LLM_BASE_URL=https://vllm.internal.example.com/v1
LLM_MODEL=Qwen/Qwen2.5-Coder-32B-Instruct
LLM_API_KEY=your-bearer-token
```

### Using different models per phase

For maximum throughput, use a fast model for bulk triage (Phase 1) and a more capable model for reasoning phases:

```python
# pipeline.py
fast_llm  = LLMClient(base_url, api_key, os.environ.get("LLM_FAST_MODEL",  "qwen2.5-coder-7b"))
smart_llm = LLMClient(base_url, api_key, os.environ.get("LLM_SMART_MODEL", "qwen2.5-coder-32b"))

agent1 = TriageAgent(fast_llm, str(output_dir))
agent2 = TaintSpecAgent(smart_llm, str(output_dir))
# ... Phase 3-5 use smart_llm
```

---

## Tuning the VerifierAgent for precision vs cost

The VerifierAgent's self-consistency setting trades cost for precision:

| `MOSEC_VERIFIER_N` | Cost | Precision | Use case |
|---|---|---|---|
| `1` (default) | 1× | Baseline | Development, CI, large repos |
| `3` | ~2.5× | +15-20% F1 | Pre-release audits, critical components |

Set via environment variable:

```bash
MOSEC_VERIFIER_N=3 python pipeline.py --repo-path /path/to/repo
```

At N=3, the three independent Propose-Falsify-Decide cycles run with `temperature=0.1` for the Propose stage to generate variation, then take a majority vote.

---

## Extending taint sources and sinks

Add sources and sinks directly to `utils/ast_extractor.py` in the appropriate dict:

```python
# Python sources — add your framework
_PYTHON_SOURCES["myframework"] = {
    "get_request_param", "get_cookie", "form_data.get",
}

# Python sinks for a new CWE
_PYTHON_SINKS_BY_CWE["CWE-611"] = [
    ("etree.parse", "call"),
    ("lxml.etree.parse", "call"),
    ("xml.etree.ElementTree.parse", "call"),
]
```

Changes here affect both the candidate extraction in Phase 2 (guiding the LLM) and the CFG BFS in Phase 4 (ground-truth taint tracking).

---

## Extending the sanitizer list (Phase 4)

The lexical sanitizer check in `agents/exploit.py` uses a pattern list in `_lexical_trace()`. Unlike the old implementation (which searched anywhere in a ±30-line window), the current implementation only fires when a sanitizer pattern appears **on the same line as the sink**. This means the list can be more aggressive without causing false kills.

Existing patterns:
```python
strong_sanitizers = [
    r"\bparameterize\b",
    r"\bprepare\b",
    r"\bescape_string\b",
    r"html\.escape\b",
    r"markupsafe\.escape\b",
    r"bleach\.clean\b",
    r"django\.utils\.html\b",
]
```

To add framework-specific sanitizers:
```python
strong_sanitizers += [
    r"DOMPurify\.sanitize\(",     # JavaScript DOMPurify
    r"sanitize_html\(",           # Ruby sanitize_html gem
    r"ActionController::Base#sanitize",  # Rails
]
```

---

## Adding a new output format

To export results to Defect Dojo, add a method to `agents/reporter.py` and call it from `run()`:

```python
def _write_defect_dojo(self, entries: list[ReportEntry], path: str) -> None:
    findings = []
    for e in entries:
        findings.append({
            "title": e.title,
            "cwe": int(e.cwe.replace("CWE-", "")),
            "severity": e.cvss.severity.capitalize(),
            "description": e.description,
            "file_path": e.file,
            "line": e.line,
            "mitigation": e.remediation,
            "active": True,
            "verified": True,
            "false_p": False,
        })
    Path(path).write_text(json.dumps({"findings": findings}, indent=2), encoding="utf-8")

# In run():
self._write_defect_dojo(entries, str(self.output_dir / "defect_dojo.json"))
```

---

## Adding benchmark cases

Add a pair of files to `benchmarks/cases/`:

```
benchmarks/cases/
  tp_my_vuln.py               # the vulnerable code snippet
  tp_my_vuln.expected.json    # ground truth
```

Expected JSON format:
```json
{
  "label": "TP",
  "description": "Flask XSS via unescaped query parameter",
  "cwe": "CWE-79",
  "should_validate": true,
  "source_hint": "request.args.get",
  "sink_hint": "make_response",
  "exploitability": "high",
  "difficulty": "normal",
  "notes": "PoC: ?name=<script>alert(1)</script>"
}
```

| Field | Values | Meaning |
|---|---|---|
| `label` | `TP`, `FP`, `TN` | Ground truth label |
| `should_validate` | `true`/`false` | Whether the pipeline should produce a validated vuln |
| `difficulty` | `normal`, `hard` | Reported in per-difficulty breakdown |

Cases with `difficulty: "hard"` (inter-procedural, sanitizer bypass) are expected to fail until Lot E (global taint graph) is implemented.

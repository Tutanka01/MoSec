# Extending MoSec SAST

MoSec is designed to be extended. This document covers the four most common extension scenarios.

---

## Adding a new language

Support for a new language requires changes in four places.

### 1. File collection (`agents/ingestion.py`)

Add the file extension to `_EXT`:

```python
_EXT = {".py", ".js", ".ts", ".jsx", ".tsx", ".rb"}  # add .rb for Ruby
```

### 2. Entry point patterns (`agents/ingestion.py`)

Add a pattern dict for the new language:

```python
_RUBY_PATTERNS: dict[str, list[str]] = {
    "http_route": [
        r"get\s+['\"]\/",
        r"post\s+['\"]\/",
        r"put\s+['\"]\/",
        r"delete\s+['\"]\/",
        r"match\s+['\"]\/",
    ],
    "file_read": [
        r"\bFile\.open\b",
        r"\bFile\.read\b",
        r"\bIO\.read\b",
    ],
    "subprocess": [
        r"\bsystem\s*\(",
        r"\bexec\s*\(",
        r"\bspawn\s*\(",
        r"%x\{",
        r"`[^`]+`",
    ],
    "eval": [
        r"\beval\s*\(",
        r"\binstance_eval\b",
        r"\bclass_eval\b",
    ],
    "deserialization": [
        r"\bMarshal\.load\b",
        r"\bYAML\.load\b",
        r"\bJSON\.parse\b",
    ],
}
```

Wire it into `_extract_entry_points()`:

```python
if f.suffix == ".py":
    patterns = _PY_PATTERNS
elif f.suffix in {".js", ".ts", ".jsx", ".tsx"}:
    patterns = _JS_PATTERNS
elif f.suffix == ".rb":
    patterns = _RUBY_PATTERNS
else:
    continue
```

### 3. Semgrep language identifier (`utils/sast.py`)

Add the mapping in `generate_semgrep_rule()`:

```python
lang_map = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".rb": "ruby",           # add this
}
```

### 4. tree-sitter parser (`agents/ingestion.py`)

Install the tree-sitter grammar: `pip install tree-sitter-ruby`

Add the parser in `_init_parsers()`:

```python
import tree_sitter_ruby as tsruby
self._rb_parser = Parser(Language(tsruby.language()))
```

Add the file type in `_analyse_file_ast()`:

```python
elif path.suffix == ".rb" and self._rb_parser:
    tree = self._rb_parser.parse(code)
    return self._summarise_tree(tree, rel, is_python=False)
```

Add Ruby tree-sitter node types in `_summarise_tree()` if needed (Ruby uses `method`, `class` node types rather than `function_definition`/`class_definition`).

### 5. CodeQL database (optional)

CodeQL supports Ruby natively. Add Ruby detection in `_build_codeql_database()`:

```python
has_rb = any(repo.rglob("*.rb"))
lang = "python" if has_py else ("javascript" if has_js else ("ruby" if has_rb else None))
```

---

## Adding a custom agent phase

Suppose you want to add a Phase 2.5 that checks each taint spec against a known CVE database before proceeding to data flow verification.

### 1. Create the agent class

```python
# agents/cve_check.py
from __future__ import annotations
import json
import logging
from pathlib import Path
from models.schemas import TaintSpec

logger = logging.getLogger(__name__)

class CVECheckAgent:
    """Phase 2.5: cross-reference taint specs against known CVE patterns."""

    KNOWN_PATTERNS = {
        "pickle.loads": "CWE-502 / CVE-2019-20907 (pickle deserialization)",
        "yaml.load":    "CWE-502 / CVE-2017-18342 (PyYAML unsafe load)",
    }

    def __init__(self, output_dir: str) -> None:
        self.output_dir = Path(output_dir)

    def run(self, specs: list[TaintSpec]) -> list[TaintSpec]:
        for spec in specs:
            for pattern, cve_ref in self.KNOWN_PATTERNS.items():
                if pattern in spec.sink.lower():
                    logger.info(
                        "CVE match | %s → %s", spec.finding_id, cve_ref
                    )
                    # Annotate the spec (add field if you extend TaintSpec)
                    break
        # Return all specs — this agent annotates, doesn't filter
        return specs
```

### 2. Add the schema field (if needed)

In `models/schemas.py`, extend `TaintSpec`:

```python
class TaintSpec(BaseModel):
    ...
    cve_reference: Optional[str] = None  # added by CVECheckAgent
```

### 3. Wire it into `pipeline.py`

```python
from agents.cve_check import CVECheckAgent

# Between Phase 2 and Phase 3:
if start_phase <= 2:
    agent2 = TaintSpecAgent(llm, str(output_dir))
    taint_specs = agent2.run(findings)

    # Phase 2.5
    agent25 = CVECheckAgent(str(output_dir))
    taint_specs = agent25.run(taint_specs)
```

No new intermediate JSON file is required if the agent is purely annotating — the taint_specs.json from Phase 2 is overwritten. If you need separate resumability, save to `cve_specs.json` and add a loader in `pipeline.py`.

---

## Swapping the LLM backend

The `LLMClient` in `utils/llm.py` talks to any OpenAI-compatible endpoint. Changing the backend is a one-line change in `.env`:

```bash
# Local llama.cpp server
LLM_BASE_URL=http://localhost:8080/v1
LLM_MODEL=gemma-4-31b-it-q8_0

# Ollama
LLM_BASE_URL=http://localhost:11434/v1
LLM_MODEL=llama3.3:70b

# vLLM (remote, with auth)
LLM_BASE_URL=https://vllm.internal.example.com/v1
LLM_MODEL=Qwen/Qwen2.5-Coder-32B-Instruct
LLM_API_KEY=your-bearer-token

# Actual OpenAI (breaks the "no cloud" guarantee — use only for testing)
LLM_BASE_URL=https://api.openai.com/v1
LLM_MODEL=gpt-4o
LLM_API_KEY=sk-...
```

### Using different models per phase

For maximum performance, you may want a large model for reasoning phases (3, 4, 5) and a smaller/faster model for bulk triage (phase 1). To do this, instantiate two `LLMClient` objects in `pipeline.py`:

```python
def build_llm_clients() -> tuple[LLMClient, LLMClient]:
    base_url = os.environ.get("LLM_BASE_URL", "...")
    api_key = os.environ.get("LLM_API_KEY", "")

    fast_model = os.environ.get("LLM_FAST_MODEL", "gemma-3-4b-it")
    smart_model = os.environ.get("LLM_SMART_MODEL", "gemma-4-31b-it-q8_0")

    return (
        LLMClient(base_url, api_key, fast_model),   # Phase 1
        LLMClient(base_url, api_key, smart_model),  # Phases 2–5
    )

# In run_pipeline():
fast_llm, smart_llm = build_llm_clients()

agent1 = TriageAgent(fast_llm, str(output_dir))
agent2 = TaintSpecAgent(smart_llm, str(output_dir))
...
```

---

## Extending the static sanitizer list (Phase 4)

The list of strong sanitizers checked in the static trace is defined in `agents/exploit.py`:

```python
strong_sanitizers = [
    r"\bparameterize\b",
    r"\bsanitize\b",
    r"\bprepare\b",
    r"\bescape_string\b",
    r"\bhtml\.escape\b",
    r"\bmarkupsafe\.escape\b",
    r"\bbleach\.clean\b",
    r"\bDjango.*safe\b",
]
```

Add patterns here for any framework-specific sanitizers relevant to your codebase. Patterns are Python regex and are searched case-insensitively in a ±30 line window around the finding.

For example, to add Django ORM protection:

```python
strong_sanitizers += [
    r"\.filter\(",       # Django ORM parameterised filter
    r"\.exclude\(",
    r"Q\(",              # Django Q objects (parameterised)
    r"django\.db\.models",
]
```

---

## Customising the CVSS fallback defaults

Edit `_DEFAULT_METRICS` in `agents/reporter.py`:

```python
_DEFAULT_METRICS = CVSSMetrics(
    attack_vector="N",        # Network
    attack_complexity="L",    # Low
    privileges_required="N",  # None
    user_interaction="N",     # None
    scope="U",                # Unchanged
    confidentiality="L",      # Low
    integrity="L",            # Low
    availability="N",         # None
)
```

The current defaults produce CVSS 6.5 (Medium). If your environment audits internal services where network access requires VPN, consider setting `attack_vector="A"` (Adjacent) for the default, which produces a lower score and reduces alert fatigue.

---

## Adding a new output format

The reporter currently writes SARIF and Markdown. Adding a new format (e.g. JSON export for Defect Dojo, HTML report, Jira ticket creation) follows the same pattern:

```python
# In agents/reporter.py, add a new method:

def _write_defect_dojo(self, entries: list[ReportEntry], path: str) -> None:
    """Export in Defect Dojo generic findings JSON format."""
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
            "references": e.cvss.vector_string,
            "active": True,
            "verified": True,
            "false_p": False,
            "duplicate": False,
        })
    output = {"findings": findings}
    Path(path).write_text(json.dumps(output, indent=2), encoding="utf-8")

# Then call it from run():
self._write_defect_dojo(entries, str(self.output_dir / "defect_dojo.json"))
```

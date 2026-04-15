"""
Phase 2 — Taint Specification Agent (SemTaint-style)

For every finding from Phase 1, retrieves code context and asks the LLM to
pinpoint the exact source, sink, sanitizers, and unresolved calls.
Then generates a Semgrep taint-mode rule YAML for each finding.
Output: taint_specs.json  +  /tmp/audit_rules/{finding_id}.yaml
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from pydantic import ValidationError

from models.schemas import FileFinding, TaintSpec
from utils.llm import LLMClient, LLMError
from utils.sast import generate_semgrep_rule

logger = logging.getLogger(__name__)

_CONTEXT_LINES: int = 50  # lines above and below the finding

_SYSTEM_PROMPT = """\
You are a taint analysis expert.
Given the code and a suspected vulnerability, perform precise taint analysis.

1. Identify the EXACT SOURCE: the function/parameter/variable where untrusted data enters.
2. Identify the EXACT SINK: the function call where the data becomes dangerous.
3. Identify any SANITIZERS on the path (functions that validate or escape the data).
4. List any UNRESOLVED CALLS on the taint path (dynamic dispatch, callbacks, unknown function pointers).

Respond ONLY in JSON (no markdown, no prose):
{
  "source": "<function or variable name>",
  "sink": "<function call or expression>",
  "sanitizers": ["<sanitizer1>", ...],
  "unresolved_calls": ["<call1>", ...],
  "taint_path_summary": "<one or two sentence description of the complete flow>"
}
"""


class TaintSpecAgent:
    """Phase 2: taint source/sink specification and Semgrep rule generation."""

    def __init__(
        self,
        llm: LLMClient,
        output_dir: str,
        rules_dir: str = "/tmp/audit_rules",
    ) -> None:
        self.llm = llm
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.rules_dir = Path(rules_dir)
        self.rules_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, findings: list[FileFinding]) -> list[TaintSpec]:
        specs: list[TaintSpec] = []

        for finding in findings:
            try:
                spec = self._process_finding(finding)
                specs.append(spec)
                logger.info(
                    "Phase 2 | %s line %d → source=%s  sink=%s",
                    finding.file,
                    finding.line,
                    spec.source,
                    spec.sink,
                )
            except Exception as exc:
                logger.error(
                    "Phase 2 | failed for finding %s: %s", finding.finding_id, exc
                )

        out = self.output_dir / "taint_specs.json"
        out.write_text(json.dumps([s.model_dump() for s in specs], indent=2), encoding="utf-8")
        logger.info("Taint specs written → %s  (%d specs)", out, len(specs))
        return specs

    # ------------------------------------------------------------------
    # Per-finding processing
    # ------------------------------------------------------------------

    def _process_finding(self, finding: FileFinding) -> TaintSpec:
        code_ctx = self._extract_context(finding.file, finding.line)

        messages = [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"File: {finding.file}\n"
                    f"Suspected vulnerability at line {finding.line} ({finding.cwe}):\n"
                    f"{finding.description}\n\n"
                    f"Code context:\n```\n{code_ctx}\n```"
                ),
            },
        ]

        try:
            content, usage = self.llm.chat(messages, max_tokens=2048, temperature=0.05)
        except LLMError as exc:
            raise RuntimeError(f"LLM call failed: {exc}") from exc

        logger.debug("Phase 2 | %s | tokens: %s", finding.finding_id, usage)

        taint_data = self._parse_response(content, finding.finding_id)

        # Generate Semgrep rule
        file_suffix = Path(finding.file).suffix
        rule_yaml = generate_semgrep_rule(
            finding_id=finding.finding_id,
            source=taint_data["source"],
            sink=taint_data["sink"],
            cwe=finding.cwe,
            description=finding.description,
            language=file_suffix,
            sanitizers=taint_data.get("sanitizers", []),
        )
        rule_path = self.rules_dir / f"{finding.finding_id}.yaml"
        rule_path.write_text(rule_yaml, encoding="utf-8")

        return TaintSpec(
            finding_id=finding.finding_id,
            file=finding.file,
            line=finding.line,
            cwe=finding.cwe,
            description=finding.description,
            confidence=finding.confidence,
            source=taint_data["source"],
            sink=taint_data["sink"],
            sanitizers=taint_data.get("sanitizers", []),
            unresolved_calls=taint_data.get("unresolved_calls", []),
            taint_path_summary=taint_data.get("taint_path_summary", ""),
            semgrep_rule_path=str(rule_path),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_context(file_path: str, center_line: int) -> str:
        """Return the file slice centred on *center_line* ± CONTEXT_LINES."""
        try:
            lines = Path(file_path).read_text(errors="replace").splitlines()
        except OSError:
            return ""

        start = max(0, center_line - 1 - _CONTEXT_LINES)
        end = min(len(lines), center_line + _CONTEXT_LINES)
        numbered = [
            f"{i + start + 1:5d}  {line}" for i, line in enumerate(lines[start:end])
        ]
        return "\n".join(numbered)

    def _parse_response(self, content: str, finding_id: str) -> dict:
        """Parse the LLM response and return a dict with required keys."""
        try:
            data = self.llm.extract_json(content)
        except ValueError as exc:
            logger.warning("Phase 2 | JSON parse failed for %s: %s", finding_id, exc)
            # Return minimal fallback structure
            return {
                "source": "unknown_source",
                "sink": "unknown_sink",
                "sanitizers": [],
                "unresolved_calls": [],
                "taint_path_summary": "LLM response could not be parsed.",
            }

        if not isinstance(data, dict):
            return {
                "source": str(data)[:80],
                "sink": "unknown_sink",
                "sanitizers": [],
                "unresolved_calls": [],
                "taint_path_summary": "",
            }

        # Normalise: ensure required keys exist
        data.setdefault("source", "unknown_source")
        data.setdefault("sink", "unknown_sink")
        data.setdefault("sanitizers", [])
        data.setdefault("unresolved_calls", [])
        data.setdefault("taint_path_summary", "")
        return data

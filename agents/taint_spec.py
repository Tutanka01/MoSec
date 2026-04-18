"""
Phase 2 — Taint Specification Agent (SemTaint-style)

For every finding from Phase 1, retrieves code context and asks the LLM to
pinpoint the exact source, sink, sanitizers, and unresolved calls.

Lot C enhancement: AST candidates are extracted first and passed to the LLM
so it selects from a grounded list rather than inventing source/sink names.
Then generates a Semgrep taint-mode rule YAML for each finding.
Output: taint_specs.json  +  /tmp/audit_rules/{finding_id}.yaml
"""

from __future__ import annotations

import json
import logging
import re
import tempfile
from pathlib import Path

from models.schemas import ASTCandidate, FileFinding, TaintSpec
from utils.llm import LLMClient, LLMError
from utils.sast import generate_semgrep_rule

logger = logging.getLogger(__name__)

_CONTEXT_LINES: int = 50  # lines above and below the finding

_SYSTEM_PROMPT = """\
You are a taint analysis expert.
Given the code and AST-extracted candidate sources/sinks, perform precise taint analysis.

Your task:
1. Select the BEST SOURCE from the candidates list: the exact point where untrusted data enters.
2. Select the BEST SINK from the candidates list: where the tainted data becomes dangerous.
3. Identify any SANITIZERS on the path (functions that validate or escape the data).
4. List any UNRESOLVED CALLS on the taint path.
5. State the sink_kind: "call", "method_call", "property_assignment", or "subscript_assignment".

CRITICAL SINK RULE — The sink MUST be a named callable function or named property.
  NEVER use an f-string, template literal, or string expression as the sink.
  If tainted data flows into an interpolated string that is then passed to another function,
  use THAT outer function as the sink (e.g. make_response, render_template_string, send,
  res.send, cursor.execute, os.system, open, echo, etc.).

  WRONG sinks: 'f"<h1>{name}</h1>"'  '`Hello ${user}`'  '"SELECT * FROM " + id'
  CORRECT sinks: 'make_response'  'render_template_string'  'cursor.execute'  'res.send'

If no candidates are provided or none fit, infer from the code — but prefer candidates.

Respond ONLY in JSON (no markdown, no prose):
{
  "source": "<exact source function or variable name from candidates>",
  "sink": "<named callable or property — never an expression>",
  "sink_kind": "call" | "method_call" | "property_assignment" | "subscript_assignment",
  "sanitizers": ["<sanitizer1>", ...],
  "unresolved_calls": ["<call1>", ...],
  "taint_path_summary": "<one or two sentence description of the complete flow>",
  "source_line": <int or null>,
  "sink_line": <int or null>
}
"""


class TaintSpecAgent:
    """Phase 2: taint source/sink specification and Semgrep rule generation."""

    def __init__(
        self,
        llm: LLMClient,
        output_dir: str,
        rules_dir: str = str(Path(tempfile.gettempdir()) / "audit_rules"),
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
        out.write_text(
            json.dumps([s.model_dump() for s in specs], indent=2), encoding="utf-8"
        )
        logger.info("Taint specs written → %s  (%d specs)", out, len(specs))
        return specs

    # ------------------------------------------------------------------
    # Per-finding processing
    # ------------------------------------------------------------------

    def _process_finding(self, finding: FileFinding) -> TaintSpec:
        code_ctx = self._extract_context(finding.file, finding.line)

        # Lot C: extract AST candidates to ground the LLM's source/sink selection
        ast_candidates = self._extract_ast_candidates(finding)
        candidates_block = self._format_candidates(ast_candidates)

        messages = [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"File: {finding.file}\n"
                    f"Suspected vulnerability at line {finding.line} ({finding.cwe}):\n"
                    f"{finding.description}\n\n"
                    f"{candidates_block}"
                    f"Code context:\n```\n{code_ctx}\n```"
                ),
            },
        ]

        try:
            content, usage = self.llm.chat(messages, max_tokens=2048, temperature=0.05)
        except LLMError as exc:
            raise RuntimeError(f"LLM call failed: {exc}") from exc

        logger.debug(  # nosemgrep
            "Phase 2 | %s | tokens: %s", finding.finding_id, usage
        )

        taint_data = self._parse_response(content, finding.finding_id)

        # Generate Semgrep rule — pass sink_kind for AST-aware pattern generation
        file_suffix = Path(finding.file).suffix
        sink_kind = taint_data.get("sink_kind", "call") or "call"
        rule_yaml = generate_semgrep_rule(
            finding_id=finding.finding_id,
            source=taint_data["source"],
            sink=taint_data["sink"],
            cwe=finding.cwe,
            description=finding.description,
            language=file_suffix,
            sanitizers=taint_data.get("sanitizers", []),
            sink_kind=sink_kind,
            validate=True,
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
            sink_kind=sink_kind,
            source_line=taint_data.get("source_line"),
            sink_line=taint_data.get("sink_line"),
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

    def _extract_ast_candidates(self, finding: FileFinding) -> list[ASTCandidate]:
        """Run AST extraction and return source/sink candidates (Lot C)."""
        try:
            from utils.ast_extractor import TaintCandidateExtractor  # noqa: PLC0415

            extractor = TaintCandidateExtractor()
            return extractor.extract(
                file_path=finding.file,
                center_line=finding.line,
                cwe=finding.cwe,
                radius=_CONTEXT_LINES,
            )
        except Exception as exc:
            logger.debug("Phase 2 | AST extraction failed (non-fatal): %s", exc)
            return []

    @staticmethod
    def _format_candidates(candidates: list[ASTCandidate]) -> str:
        """Format AST candidates as a structured block for the LLM prompt."""
        if not candidates:
            return ""

        sources = [c for c in candidates if c.kind == "source"]
        sinks = [c for c in candidates if c.kind == "sink"]

        lines: list[str] = ["AST-extracted candidates (prefer these over guessing):\n"]

        if sources:
            lines.append("  Sources:")
            for c in sources[:5]:
                rv = f" → var {c.returns_var}" if c.returns_var else ""
                lines.append(f"    - {c.name} (line {c.line}{rv})")

        if sinks:
            lines.append("  Sinks:")
            for c in sinks[:5]:
                af = f" ← {c.assigned_from}" if c.assigned_from else ""
                lines.append(f"    - {c.name} [{c.sink_kind}] (line {c.line}{af})")

        lines.append("")
        return "\n".join(lines) + "\n"

    def _parse_response(self, content: str, finding_id: str) -> dict:
        """Parse the LLM response and return a dict with required keys."""
        try:
            data = self.llm.extract_json(content)
        except ValueError as exc:
            logger.warning("Phase 2 | JSON parse failed for %s: %s", finding_id, exc)
            return {
                "source": "unknown_source",
                "sink": "unknown_sink",
                "sink_kind": "call",
                "sanitizers": [],
                "unresolved_calls": [],
                "taint_path_summary": "LLM response could not be parsed.",
                "source_line": None,
                "sink_line": None,
            }

        if not isinstance(data, dict):
            return {
                "source": str(data)[:80],
                "sink": "unknown_sink",
                "sink_kind": "call",
                "sanitizers": [],
                "unresolved_calls": [],
                "taint_path_summary": "",
                "source_line": None,
                "sink_line": None,
            }

        # Normalise: ensure required keys exist
        data.setdefault("source", "unknown_source")
        data.setdefault("sink", "unknown_sink")
        data.setdefault("sink_kind", "call")
        data.setdefault("sanitizers", [])
        data.setdefault("unresolved_calls", [])
        data.setdefault("taint_path_summary", "")
        data.setdefault("source_line", None)
        data.setdefault("sink_line", None)

        # Validate sink_kind
        valid_kinds = {
            "call",
            "method_call",
            "property_assignment",
            "subscript_assignment",
        }
        if data["sink_kind"] not in valid_kinds:
            data["sink_kind"] = "call"

        # Reject expression sinks (f-strings, template literals, concatenations).
        # These crash Semgrep YAML generation and break the static trace.
        # Replace with the best callable we can infer from the context.
        sink = data["sink"]
        if not _is_named_callable(sink):
            logger.debug(
                "Phase 2 | expression sink detected %r — substituting callable", sink
            )
            data["sink"] = _infer_callable_sink(
                sink, data.get("taint_path_summary", "")
            )
            data["sink_kind"] = "call"

        return data


_EXPR_SINK_RE = re.compile(r'["\'{`<>]')


def _is_named_callable(sink: str) -> bool:
    """Return True when sink is a plain dotted identifier (callable or property name)."""
    bare = sink.split("(")[0].strip()
    return bool(re.match(r"^[a-zA-Z_$][\w$.]*$", bare)) and not _EXPR_SINK_RE.search(
        bare
    )


_SINK_KEYWORDS_TO_CALLABLE: list[tuple[str, str]] = [
    # XSS — HTML response functions
    ("make_response", "make_response"),
    ("render_template", "render_template_string"),
    ("Response(", "Response"),
    ("send(", "res.send"),
    ("res.send", "res.send"),
    ("write(", "res.write"),
    ("echo", "echo"),
    ("innerHTML", "innerHTML"),
    # SQLi
    ("execute(", "cursor.execute"),
    ("query(", "cursor.query"),
    # CmdI
    ("system(", "os.system"),
    ("exec(", "exec"),
    ("shell_exec", "shell_exec"),
    # Path traversal
    ("open(", "open"),
    ("file_get_contents", "file_get_contents"),
]


def _infer_callable_sink(expr: str, summary: str) -> str:
    """
    Best-effort inference of a named callable sink from an expression.
    Falls back to 'make_response' for HTML-like expressions (XSS default).
    """
    combined = (expr + " " + summary).lower()
    for keyword, callable_name in _SINK_KEYWORDS_TO_CALLABLE:
        if keyword.lower() in combined:
            return callable_name
    # Default for HTML string interpolation → Flask response function
    if any(tag in expr for tag in ("<", ">", "html", "HTML")):
        return "make_response"
    return "make_response"

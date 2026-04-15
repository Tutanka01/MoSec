"""
Phase 3 — Data Flow Verification Agent (ReAct loop)

For each taint spec, runs a ReAct (Reason → Act → Observe) loop of up to 5
iterations to confirm or deny reachability of the source→sink path.

Available actions:
  - run_semgrep   : run the generated Semgrep rule
  - grep_sanitizers : grep for known sanitizer patterns in the file
  - read_context  : read a larger slice of the file
  - run_codeql    : run an inline CodeQL query (when a DB is available)

Output: confirmed_flows.json
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from models.schemas import ConfirmedFlow, TaintSpec, VerificationEvidence
from utils.llm import LLMClient, LLMError
from utils.sast import CodeQLRunner, SemgrepRunner

logger = logging.getLogger(__name__)

_MAX_ITERATIONS: int = 5

_REASON_PROMPT = """\
You are a data-flow verification engine performing a ReAct loop.

Context:
  File: {file}
  Line: {line}
  CWE: {cwe}
  Source: {source}
  Sink: {sink}
  Sanitizers declared: {sanitizers}
  Taint path summary: {taint_path_summary}

Evidence gathered so far:
{evidence}

Iteration: {iteration}/{max_iter}

Decide what to do next.  You must choose ONE action from this list:
  - run_semgrep      (use the generated Semgrep rule to find matches)
  - grep_sanitizers  (grep the file for any sanitizer-like patterns)
  - read_context     (read a wider slice of code around the finding)
  - run_codeql       (query the CodeQL DB for call/data-flow relationships)
  - conclude         (you have enough evidence to make a final decision)

Respond ONLY in JSON:
{{
  "reasoning": "<one paragraph — what do you know and what do you need>",
  "action": "<one of the five actions above>",
  "action_param": "<optional parameter, e.g. line range '1-200' for read_context or a grep pattern>"
}}
"""

_CONCLUDE_PROMPT = """\
Based on all evidence collected, make a final verdict on this taint flow.

File: {file}  Line: {line}  CWE: {cwe}
Source: {source}  →  Sink: {sink}
Sanitizers declared: {sanitizers}

Evidence:
{evidence}

Respond ONLY in JSON:
{{
  "verdict": "confirmed" | "sanitized" | "unreachable",
  "reasoning": "<explanation>"
}}
"""

_READ_CONTEXT_LINES: int = 80


class DataFlowAgent:
    """Phase 3: ReAct-based data-flow verification."""

    def __init__(
        self,
        llm: LLMClient,
        output_dir: str,
        codeql_db_path: str | None = None,
        codeql_bin: str = "codeql",
    ) -> None:
        self.llm = llm
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.codeql_db_path = codeql_db_path
        self._codeql = CodeQLRunner(codeql_bin)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, specs: list[TaintSpec], repo_path: str) -> list[ConfirmedFlow]:
        confirmed: list[ConfirmedFlow] = []

        for spec in specs:
            try:
                flow = self._verify_flow(spec, repo_path)
                if flow is not None:
                    confirmed.append(flow)
                    logger.info(
                        "Phase 3 | CONFIRMED  %s line %d (%s)",
                        spec.file,
                        spec.line,
                        spec.cwe,
                    )
                else:
                    logger.info(
                        "Phase 3 | DROPPED    %s line %d (%s) — sanitized or unreachable",
                        spec.file,
                        spec.line,
                        spec.cwe,
                    )
            except Exception as exc:
                logger.error(
                    "Phase 3 | error on finding %s: %s", spec.finding_id, exc
                )

        out = self.output_dir / "confirmed_flows.json"
        out.write_text(json.dumps([f.model_dump() for f in confirmed], indent=2), encoding="utf-8")
        logger.info("Confirmed flows written → %s  (%d flows)", out, len(confirmed))
        return confirmed

    # ------------------------------------------------------------------
    # ReAct loop for a single spec
    # ------------------------------------------------------------------

    def _verify_flow(self, spec: TaintSpec, repo_path: str) -> ConfirmedFlow | None:
        semgrep = SemgrepRunner(repo_path)
        evidence: list[VerificationEvidence] = []

        for iteration in range(1, _MAX_ITERATIONS + 1):
            # --- Reason ---
            try:
                action, param, reasoning = self._reason(spec, evidence, iteration)
            except LLMError as exc:
                logger.warning("Phase 3 | LLM reason failed: %s", exc)
                break

            # --- Act ---
            if action == "conclude":
                obs = reasoning
            elif action == "run_semgrep":
                obs = self._act_semgrep(spec, semgrep)
            elif action == "grep_sanitizers":
                pattern = param or "|".join(spec.sanitizers) or r"(validate|sanitize|escape|quote|encode)"
                obs = self._act_grep(spec.file, pattern)
            elif action == "read_context":
                obs = self._act_read_context(spec.file, spec.line, param)
            elif action == "run_codeql":
                obs = self._act_codeql(spec, param)
            else:
                obs = f"Unknown action '{action}' — skipping"

            # --- Observe ---
            ev = VerificationEvidence(
                iteration=iteration,
                action=f"{action}({param or ''})",
                result=obs[:1000],
                conclusion=reasoning[:500],
            )
            evidence.append(ev)
            logger.debug(
                "Phase 3 | iter %d/%d  action=%s", iteration, _MAX_ITERATIONS, action
            )

            if action == "conclude" or iteration == _MAX_ITERATIONS:
                break

        # --- Final verdict ---
        verdict, verdict_reasoning = self._conclude(spec, evidence)

        if verdict != "confirmed":
            return None

        return ConfirmedFlow(
            finding_id=spec.finding_id,
            file=spec.file,
            line=spec.line,
            cwe=spec.cwe,
            description=spec.description,
            confidence=spec.confidence,
            source=spec.source,
            sink=spec.sink,
            sanitizers=spec.sanitizers,
            taint_path_summary=spec.taint_path_summary,
            verification_iterations=len(evidence),
            verification_evidence=evidence,
        )

    # ------------------------------------------------------------------
    # Reasoning step
    # ------------------------------------------------------------------

    def _reason(
        self,
        spec: TaintSpec,
        evidence: list[VerificationEvidence],
        iteration: int,
    ) -> tuple[str, str, str]:
        """Return (action, action_param, reasoning)."""
        evidence_text = (
            "\n".join(
                f"  [{e.iteration}] {e.action}: {e.result[:300]}"
                for e in evidence
            )
            or "  (none yet)"
        )

        prompt = _REASON_PROMPT.format(
            file=spec.file,
            line=spec.line,
            cwe=spec.cwe,
            source=spec.source,
            sink=spec.sink,
            sanitizers=spec.sanitizers or "none",
            taint_path_summary=spec.taint_path_summary,
            evidence=evidence_text,
            iteration=iteration,
            max_iter=_MAX_ITERATIONS,
        )

        content, _ = self.llm.chat(
            [{"role": "user", "content": prompt}],
            max_tokens=512,
            temperature=0.05,
        )

        try:
            data = self.llm.extract_json(content)
        except ValueError:
            return "conclude", "", content[:300]

        action = data.get("action", "conclude")
        param = str(data.get("action_param") or "")
        reasoning = data.get("reasoning", "")
        return action, param, reasoning

    # ------------------------------------------------------------------
    # Verdict step
    # ------------------------------------------------------------------

    def _conclude(
        self,
        spec: TaintSpec,
        evidence: list[VerificationEvidence],
    ) -> tuple[str, str]:
        """Return (verdict, reasoning) where verdict ∈ {confirmed, sanitized, unreachable}."""
        evidence_text = "\n".join(
            f"  [{e.iteration}] {e.action}: {e.result[:400]}" for e in evidence
        ) or "  (no evidence gathered)"

        prompt = _CONCLUDE_PROMPT.format(
            file=spec.file,
            line=spec.line,
            cwe=spec.cwe,
            source=spec.source,
            sink=spec.sink,
            sanitizers=spec.sanitizers or "none",
            evidence=evidence_text,
        )

        try:
            content, _ = self.llm.chat(
                [{"role": "user", "content": prompt}],
                max_tokens=256,
                temperature=0.0,
            )
            data = self.llm.extract_json(content)
            verdict = data.get("verdict", "confirmed")
            reasoning = data.get("reasoning", "")
            return verdict, reasoning
        except Exception as exc:
            logger.warning("Phase 3 | conclude LLM failed: %s — defaulting to confirmed", exc)
            return "confirmed", "Verdict defaulted to confirmed after LLM failure."

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _act_semgrep(self, spec: TaintSpec, runner: SemgrepRunner) -> str:
        if not spec.semgrep_rule_path or not Path(spec.semgrep_rule_path).exists():
            return "No Semgrep rule file available."

        results = runner.run_rule_file(spec.semgrep_rule_path)
        if not results:
            return "Semgrep found no matches for this rule."

        snippets = []
        for r in results[:5]:
            path = r.get("path", "?")
            start = r.get("start", {}).get("line", "?")
            msg = r.get("extra", {}).get("message", "")
            snippets.append(f"  {path}:{start} — {msg}")

        return f"Semgrep matched {len(results)} location(s):\n" + "\n".join(snippets)

    def _act_grep(self, file_path: str, pattern: str) -> str:
        try:
            lines = Path(file_path).read_text(errors="replace").splitlines()
        except OSError:
            return "Could not read file."

        matches = []
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
        except re.error:
            compiled = re.compile(re.escape(pattern), re.IGNORECASE)

        for i, line in enumerate(lines, 1):
            if compiled.search(line):
                matches.append(f"  line {i}: {line.rstrip()[:120]}")

        if not matches:
            return f"No matches for pattern '{pattern}' in {file_path}."
        return f"Found {len(matches)} match(es) for '{pattern}':\n" + "\n".join(matches[:10])

    def _act_read_context(self, file_path: str, center: int, param: str) -> str:
        try:
            lines = Path(file_path).read_text(errors="replace").splitlines()
        except OSError:
            return "Could not read file."

        # param may be "start-end" or empty
        try:
            if "-" in (param or ""):
                parts = param.split("-")
                start = int(parts[0]) - 1
                end = int(parts[1])
            else:
                half = _READ_CONTEXT_LINES // 2
                start = max(0, center - 1 - half)
                end = min(len(lines), center + half)
        except (ValueError, IndexError):
            half = _READ_CONTEXT_LINES // 2
            start = max(0, center - 1 - half)
            end = min(len(lines), center + half)

        numbered = [
            f"{i + start + 1:5d}  {line}" for i, line in enumerate(lines[start:end])
        ]
        return "\n".join(numbered)

    def _act_codeql(self, spec: TaintSpec, param: str) -> str:
        if not self.codeql_db_path:
            return "No CodeQL database available."

        # Generic reachability query: look for call to sink
        sink_name = spec.sink.split("(")[0].strip().split(".")[-1]
        ql = f"""
import python

from Call c, string name
where c.getFunc().(Attribute).getName() = "{sink_name}"
   or c.getFunc().(Name).getId() = "{sink_name}"
select c, "Call to {sink_name} at " + c.getLocation().toString()
"""
        rows = self._codeql.run_inline_query(self.codeql_db_path, ql)
        if not rows:
            return f"CodeQL: no calls to '{sink_name}' found in database."
        snippets = [f"  {str(r)[:120]}" for r in rows[:5]]
        return f"CodeQL found {len(rows)} reference(s) to '{sink_name}':\n" + "\n".join(snippets)

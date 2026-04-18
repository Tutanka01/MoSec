"""
Phase 3 — Data Flow Verification Agent (ReAct loop)

For each taint spec, runs a ReAct (Reason → Act → Observe) loop of up to 5
iterations to confirm or deny reachability of the source→sink path.

Available actions:
  - run_semgrep      : run the generated Semgrep rule
  - grep_sanitizers  : grep the file for sanitizer-like patterns
  - read_context     : read a larger slice of the file
  - run_codeql       : run an inline CodeQL query (when a DB is available)
  - conclude         : end the loop and emit a verdict

Output: confirmed_flows.json
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from pydantic import ValidationError

from models.schemas import (
    CodeLocation,
    ConfirmedFlow,
    ReActStep,
    StructuredEvidence,
    TaintSpec,
    VerificationEvidence,
)
from utils.llm import LLMClient, LLMError
from utils.sast import CodeQLRunner, SemgrepRunner

logger = logging.getLogger(__name__)

_MAX_ITERATIONS: int = 5

_VALID_ACTIONS = frozenset(
    {"run_semgrep", "grep_sanitizers", "read_context", "run_codeql", "conclude"}
)

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

Actions already performed (DO NOT repeat these with the same parameters):
{played}

Iteration: {iteration}/{max_iter}

Decide what to do next.  You MUST choose ONE action from this exact list:
  - run_semgrep      (use the generated Semgrep rule to find matches)
  - grep_sanitizers  (grep the file for any sanitizer-like patterns)
  - read_context     (read a wider slice of code around the finding)
  - run_codeql       (query the CodeQL DB for call/data-flow relationships)
  - conclude         (you have enough evidence to make a final decision)

Rules:
  1. Only conclude when you have definitive evidence, or when no further action
     can produce new information.
  2. Do NOT repeat an action with the same parameters.
  3. Your reasoning must be at least one full sentence.
  4. Your confidence (0.0–1.0) must reflect how sure you are about the current
     state of evidence.

Respond ONLY in valid JSON — no markdown, no prose:
{{
  "reasoning": "<at least one full sentence>",
  "action": "<one of the five actions above>",
  "action_param": "<optional parameter>",
  "confidence": <float 0.0–1.0>
}}
"""

_CONCLUDE_PROMPT = """\
Based on all evidence collected, make a final verdict on this taint flow.

File: {file}  Line: {line}  CWE: {cwe}
Source: {source}  →  Sink: {sink}
Sanitizers declared: {sanitizers}

Evidence:
{evidence}

BURDEN OF PROOF: confirm the flow ONLY if there is affirmative evidence that:
  (a) the source data is not sanitized before reaching the sink, AND
  (b) a concrete exploit payload would trigger the {cwe} behaviour.
If evidence is ambiguous or insufficient, choose "unreachable".

Respond ONLY in valid JSON:
{{
  "verdict": "confirmed",
  "reasoning": "<explanation>"
}}
or
{{
  "verdict": "unreachable",
  "reasoning": "<explanation>"
}}
or
{{
  "verdict": "sanitized",
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
        consistency_n: int = 1,
    ) -> None:
        self.llm = llm
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.codeql_db_path = codeql_db_path
        self._codeql = CodeQLRunner(codeql_bin)
        # consistency_n > 1 enables majority-vote over N conclude calls (Lot D)
        self._consistency_n = consistency_n

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
                logger.error("Phase 3 | error on finding %s: %s", spec.finding_id, exc)

        out = self.output_dir / "confirmed_flows.json"
        out.write_text(
            json.dumps([f.model_dump() for f in confirmed], indent=2), encoding="utf-8"
        )
        logger.info("Confirmed flows written → %s  (%d flows)", out, len(confirmed))
        return confirmed

    # ------------------------------------------------------------------
    # ReAct loop for a single spec
    # ------------------------------------------------------------------

    def _verify_flow(self, spec: TaintSpec, repo_path: str) -> ConfirmedFlow | None:
        semgrep = SemgrepRunner(repo_path)
        evidence: list[VerificationEvidence] = []
        # Track (action, param) pairs to prevent wasteful repetition
        played: set[tuple[str, str]] = set()

        for iteration in range(1, _MAX_ITERATIONS + 1):
            # --- Reason ---
            try:
                step = self._reason(spec, evidence, played, iteration)
            except LLMError as exc:
                logger.warning("Phase 3 | LLM reason failed: %s", exc)
                break

            action = step.action
            param = step.action_param

            # Dedup: if the LLM repeats an already-played action, skip without
            # consuming the iteration budget so we try something new next turn.
            if action != "conclude" and (action, param) in played:
                logger.debug(
                    "Phase 3 | iter %d dedup  action=%s param=%r — skipping",
                    iteration,
                    action,
                    param,
                )
                # Inject a synthetic observation so the LLM sees why it was skipped
                evidence.append(
                    VerificationEvidence(
                        iteration=iteration,
                        action=f"DEDUP:{action}({param})",
                        result="Action already performed — no new information.",
                        conclusion="",
                    )
                )
                continue

            # --- Act ---
            structured: StructuredEvidence | None = None
            if action == "conclude":
                obs, structured = (
                    step.reasoning,
                    StructuredEvidence(kind="conclude", summary=step.reasoning[:400]),
                )
            elif action == "run_semgrep":
                obs, structured = self._act_semgrep(spec, semgrep)
            elif action == "grep_sanitizers":
                pattern = (
                    param
                    or "|".join(spec.sanitizers)
                    or r"(validate|sanitize|escape|quote|encode)"
                )
                obs, structured = self._act_grep(spec.file, pattern)
            elif action == "read_context":
                obs, structured = self._act_read_context(spec.file, spec.line, param)
            elif action == "run_codeql":
                obs, structured = self._act_codeql(spec, param)
            else:
                obs = f"Unknown action '{action}' — skipping"
                structured = StructuredEvidence(kind="unknown", summary=obs)

            played.add((action, param))

            # --- Observe ---
            ev = VerificationEvidence(
                iteration=iteration,
                action=f"{action}({param})",
                result=obs[:1000],
                conclusion=step.reasoning[:500],
                structured=structured,
            )
            evidence.append(ev)
            logger.debug(
                "Phase 3 | iter %d/%d  action=%s  confidence=%.2f",
                iteration,
                _MAX_ITERATIONS,
                action,
                step.confidence,
            )

            if action == "conclude" or iteration == _MAX_ITERATIONS:
                break

        # --- Final verdict via VerifierAgent (imported lazily to avoid circular dep) ---
        from agents.verifier import VerifierAgent  # noqa: PLC0415

        verifier = VerifierAgent(self.llm, consistency_n=self._consistency_n)
        verdict, verdict_reasoning = verifier.verify(spec, evidence)

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
    # Reasoning step — returns a validated ReActStep
    # ------------------------------------------------------------------

    def _reason(
        self,
        spec: TaintSpec,
        evidence: list[VerificationEvidence],
        played: set[tuple[str, str]],
        iteration: int,
    ) -> ReActStep:
        """Ask the LLM what to do next; return a validated ReActStep."""
        evidence_text = (
            "\n".join(
                f"  [{e.iteration}] {e.action}: {e.result[:400]}"
                for e in evidence
                if not e.action.startswith("DEDUP:")
            )
            or "  (none yet)"
        )

        played_text = (
            "\n".join(f"  {a}({p})" for a, p in sorted(played)) or "  (none yet)"
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
            played=played_text,
            iteration=iteration,
            max_iter=_MAX_ITERATIONS,
        )

        last_err: str = ""
        for attempt in range(2):  # 1 retry on validation failure
            content, _ = self.llm.chat(
                [{"role": "user", "content": prompt}],
                max_tokens=512,
                temperature=0.05,
            )

            try:
                data = self.llm.extract_json(content)
            except ValueError:
                # Unrecoverable parse failure → safe default
                return ReActStep(
                    reasoning=content[:300] or "LLM response could not be parsed.",
                    action="conclude",
                    confidence=0.1,
                )

            # Normalise action: map unknown strings to "conclude" so the pipeline
            # never silently burns iterations on hallucinated action names.
            raw_action = str(data.get("action", "conclude")).strip().lower()
            if raw_action not in _VALID_ACTIONS:
                logger.warning(
                    "Phase 3 | unknown action %r from LLM — substituting conclude",
                    raw_action,
                )
                raw_action = "conclude"
            data["action"] = raw_action

            try:
                return ReActStep.model_validate(data)
            except ValidationError as exc:
                last_err = str(exc)
                if attempt == 0:
                    # One retry with the validation error surfaced to the model
                    prompt += (
                        f"\n\nYour previous response failed schema validation: {last_err}\n"
                        "Please fix it and respond with valid JSON only."
                    )

        # Both attempts failed — return safe default
        logger.warning(
            "Phase 3 | ReActStep validation failed after retry: %s", last_err
        )
        return ReActStep(
            reasoning="Schema validation failed after retry.",
            action="conclude",
            confidence=0.1,
        )

    # ------------------------------------------------------------------
    # Actions — each returns (raw_text: str, structured: StructuredEvidence)
    # ------------------------------------------------------------------

    def _act_semgrep(
        self, spec: TaintSpec, runner: SemgrepRunner
    ) -> tuple[str, StructuredEvidence]:
        if not spec.semgrep_rule_path or not Path(spec.semgrep_rule_path).exists():
            msg = "No Semgrep rule file available."
            return msg, StructuredEvidence(kind="no_flow", summary=msg)

        results = runner.run_rule_file(spec.semgrep_rule_path)
        if not results:
            msg = "Semgrep found no matches for this rule."
            return msg, StructuredEvidence(kind="no_flow", summary=msg)

        hits: list[CodeLocation] = []
        snippets: list[str] = []
        for r in results[:10]:
            file_ = r.get("path", "?")
            start_line = r.get("start", {}).get("line", 0)
            end_line = r.get("end", {}).get("line", start_line)
            msg_text = r.get("extra", {}).get("message", "")
            snippet = r.get("extra", {}).get("lines", "")[:200]
            hits.append(
                CodeLocation(
                    file=file_,
                    line_start=start_line,
                    line_end=end_line,
                    snippet=snippet,
                )
            )
            snippets.append(f"  {file_}:{start_line} — {msg_text}")

        summary = f"Semgrep matched {len(results)} location(s):\n" + "\n".join(
            snippets[:5]
        )
        return summary, StructuredEvidence(
            kind="semgrep_matches", hits=hits, summary=summary
        )

    def _act_grep(self, file_path: str, pattern: str) -> tuple[str, StructuredEvidence]:
        try:
            lines = Path(file_path).read_text(errors="replace").splitlines()
        except OSError:
            msg = "Could not read file."
            return msg, StructuredEvidence(kind="no_flow", summary=msg)

        try:
            compiled = re.compile(pattern, re.IGNORECASE)
        except re.error:
            compiled = re.compile(re.escape(pattern), re.IGNORECASE)

        hits: list[CodeLocation] = []
        match_lines: list[str] = []
        for i, line in enumerate(lines, 1):
            if compiled.search(line):
                hits.append(
                    CodeLocation(
                        file=file_path,
                        line_start=i,
                        line_end=i,
                        snippet=line.rstrip()[:200],
                    )
                )
                match_lines.append(f"  line {i}: {line.rstrip()[:120]}")

        if not hits:
            msg = f"No matches for pattern '{pattern}' in {file_path}."
            return msg, StructuredEvidence(kind="no_flow", summary=msg)

        summary = f"Found {len(hits)} match(es) for '{pattern}':\n" + "\n".join(
            match_lines[:10]
        )
        return summary, StructuredEvidence(
            kind="grep_hits", hits=hits[:10], summary=summary
        )

    def _act_read_context(
        self, file_path: str, center: int, param: str
    ) -> tuple[str, StructuredEvidence]:
        try:
            lines = Path(file_path).read_text(errors="replace").splitlines()
        except OSError:
            msg = "Could not read file."
            return msg, StructuredEvidence(kind="no_flow", summary=msg)

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
        text = "\n".join(numbered)
        loc = CodeLocation(
            file=file_path,
            line_start=start + 1,
            line_end=end,
            snippet=text[:500],
        )
        return text, StructuredEvidence(
            kind="code_slice",
            hits=[loc],
            summary=f"Read lines {start + 1}–{end} of {file_path}",
        )

    def _act_codeql(
        self, spec: TaintSpec, param: str
    ) -> tuple[str, StructuredEvidence]:
        if not self.codeql_db_path:
            msg = "No CodeQL database available."
            return msg, StructuredEvidence(kind="no_flow", summary=msg)

        sink_name = spec.sink.split("(")[0].strip().split(".")[-1]
        # Use TaintTracking when the sink kind is a call, otherwise fall back to
        # a basic call-site query.
        sink_kind = getattr(spec, "sink_kind", "call")
        if sink_kind in ("property_assignment", "subscript_assignment"):
            ql = f"""
import python
from AssignStmt a
where a.getATarget().toString().regexpMatch(".*{re.escape(sink_name)}.*")
select a, "Assignment to {sink_name} at " + a.getLocation().toString()
"""
        else:
            ql = f"""
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

from DataFlow::CallCfgNode call
where call.getFunction().getName() = "{sink_name}"
select call, "Call to {sink_name} at " + call.getLocation().toString()
"""
        rows = self._codeql.run_inline_query(self.codeql_db_path, ql)
        if not rows:
            msg = f"CodeQL: no references to '{sink_name}' found (NO_FLOW)."
            return msg, StructuredEvidence(kind="no_flow", summary=msg)

        snippets = [f"  {str(r)[:200]}" for r in rows[:5]]
        summary = (
            f"CodeQL found {len(rows)} reference(s) to '{sink_name}':\n"
            + "\n".join(snippets)
        )
        hits = [
            CodeLocation(file=spec.file, line_start=0, line_end=0, snippet=str(r)[:200])
            for r in rows[:10]
        ]
        return summary, StructuredEvidence(
            kind="codeql_paths", hits=hits, summary=summary
        )

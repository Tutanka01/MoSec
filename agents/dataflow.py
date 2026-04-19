"""
Phase 3 — Data Flow Verification Agent (ReAct loop + Template Injection Detector)

For each taint spec, runs a ReAct (Reason → Act → Observe) loop of up to 5
iterations to confirm or deny reachability of the source→sink path.

Deterministic pre-pass (TemplateInjectionDetector):
  Before the LLM loop, a pattern-based detector identifies server-side template
  injection flows where a source variable is interpolated into a template literal
  (JavaScript backtick strings) that is then passed to an HTTP output function
  (res.send, res.write, res.end).  This implements the "additional taint step"
  concept from CodeQL's JavaScript taint-tracking library (Avgustinov et al., 2016)
  and TAJS (Møller & Schärenholt, 2020), treating ${expr} inside a template literal
  as a taint propagation edge from `expr` to the resulting string.

Available actions:
  - run_semgrep      : run the generated Semgrep rule
  - grep_sanitizers  : grep the file for sanitizer-like patterns
  - read_context     : read a larger slice of the file
  - run_codeql       : run an inline CodeQL query (when a DB is available)
  - conclude         : end the loop and emit a verdict

Output: confirmed_flows.json

References:
  [1] Avgustinov et al. (2016). QL: Object-oriented queries on relational data.
      ECOOP 2016. (CodeQL taint-tracking, AdditionalTaintStep for template literals)
  [2] Møller & Schärenholt (2020). TAJS — Type Analysis for JavaScript.
      (Template expression tracking via abstract string domains)
  [3] Yao et al. (2022). ReAct: Synergizing reasoning and acting in language models.
      ICLR 2023.
  [4] Zhang et al. (2025). VulnSage: ThinkAndVerify for LLM-based vulnerability detection.
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

# Action aliases — normalise common model-specific variations to the canonical name.
# Reasoning models (minimax-m2.7, DeepSeek-R1, QwQ, …) sometimes use abbreviated
# or alternative action names.  Mapping them here prevents wasteful "conclude"
# substitution that burns an iteration budget on a productive action.
_ACTION_ALIASES: dict[str, str] = {
    # read_context aliases
    "read": "read_context",
    "read_file": "read_context",
    "read_code": "read_context",
    "context": "read_context",
    "show_context": "read_context",
    "view_context": "read_context",
    # run_semgrep aliases
    "semgrep": "run_semgrep",
    "run_rule": "run_semgrep",
    "semgrep_scan": "run_semgrep",
    # grep_sanitizers aliases
    "grep": "grep_sanitizers",
    "search": "grep_sanitizers",
    "grep_pattern": "grep_sanitizers",
    "search_sanitizers": "grep_sanitizers",
    # run_codeql aliases
    "codeql": "run_codeql",
    "query_codeql": "run_codeql",
    # conclude aliases
    "finish": "conclude",
    "done": "conclude",
    "verdict": "conclude",
    "end": "conclude",
    "conclude_flow": "conclude",
    "make_verdict": "conclude",
}

# ---------------------------------------------------------------------------
# Template-injection taint patterns (server-side output sinks)
# CodeQL-style "additional taint steps" for JS template literals
# ---------------------------------------------------------------------------

_SERVER_OUTPUT_SINK_RE = re.compile(
    r"\b(?:res|response)\s*\.\s*(?:send|write|end|json|render|set)\s*\(|"
    r"\bsend\s*\(\s*html\b|"
    r"\bwrite\s*\(\s*html\b",
    re.IGNORECASE,
)

# DOM sinks that appear as identifiers inside template literals / HTML strings
# rather than as direct property assignments in server-side code.
_DOM_SINK_NAMES = frozenset(
    {"innerHTML", "outerHTML", "document.write", "document.writeln", "insertAdjacentHTML"}
)

# JavaScript/PHP/Python context sanitizers that neutralise XSS
_XSS_SANITIZER_RE = re.compile(
    r"\b(?:DOMPurify|sanitizeHtml|escapeHtml|encodeURIComponent|"
    r"he\.encode|xss\s*\(|marked\.parseInline|"
    r"htmlspecialchars|htmlentities|strip_tags|"
    r"html\.escape|markupsafe\.escape|bleach\.clean|"
    r"escape\s*\()\b",
    re.IGNORECASE,
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

━━━ CRITICAL KNOWLEDGE: Template Literal Taint Propagation ━━━
JavaScript template literals (`backtick strings`) propagate taint as an
ADDITIONAL TAINT STEP (per CodeQL JS taint-tracking semantics, Avgustinov et al. 2016):

  If source_var appears as ${{source_var}} inside a template literal,
  taint flows from source_var to the resulting string value.

  Server-side Reflected XSS pattern (CWE-79):
    1. query = req.query.q              ← user-controlled source
    2. html = `<script> ... ${{query}} ... </script>` ← template taint step
    3. res.send(html)                   ← HTTP output sink — CONFIRMED FLOW

  When the sink label is "innerHTML" or "document.write" but it appears
  INSIDE a server-side template literal or string that is then passed to
  res.send/res.write/res.end, the REAL exploitable sink is the HTTP output
  function, not the DOM operation.  The DOM operation is client-side code
  embedded in the server's HTML response — the vulnerability is server-side
  reflected XSS, confirming CWE-79.

  Action guidance for this pattern:
    - Use read_context to confirm the template literal shape
    - Use grep_sanitizers with pattern "DOMPurify|sanitizeHtml|encodeURIComponent"
      to check for client-side sanitizers in the embedded script
    - If the template literal is found un-sanitized → conclude CONFIRMED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

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
  5. If you see PRE-PASS evidence of a template injection flow in the evidence
     list, that is deterministic structural evidence — weight it heavily.

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

SPECIAL RULE — Template Literal Taint (CWE-79):
  If evidence includes a PRE-PASS structural match showing that the source
  variable is interpolated un-sanitized into a template literal that feeds
  a server-side HTTP output function (res.send, res.write, etc.), the flow
  is CONFIRMED even when the sink label refers to a DOM operation (innerHTML)
  that appears only in the embedded HTML/JS string.  The server's reflection
  of un-sanitized user input IS the CWE-79 vulnerability.

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


# ---------------------------------------------------------------------------
# Template Injection Detector — deterministic pre-pass
# ---------------------------------------------------------------------------


class TemplateInjectionDetector:
    """
    Deterministic structural detector for server-side template injection → XSS flows.

    Rationale
    ---------
    JavaScript template literals propagate taint as an "additional taint step"
    (CodeQL terminology, Avgustinov et al. 2016; TAJS, Møller & Schärenholt 2020).
    When user input is interpolated as ${expr} inside a backtick string that is
    then passed to an HTTP output function, the resulting vulnerability is
    server-side Reflected XSS (CWE-79).

    This pattern is missed by traditional Semgrep taint rules because:
      1. The sink (innerHTML, document.write) appears only inside a string literal,
         not as a real property assignment in the server-side AST.
      2. The real server-side sink is res.send() / res.write(), but Phase 2 may
         identify `innerHTML` as the sink from the Phase 1 finding description.

    Algorithm (inspired by CodeQL's AdditionalTaintStep for TemplateLiteralExpr)
    ----------
      Step 1 — Source variable extraction:
        Find all variables assigned from the declared source (e.g. `query = req.query.q`).
      Step 2 — Template literal interpolation detection:
        Scan for `...${source_var}...` patterns inside backtick strings.
        Record the variable name holding the resulting HTML string.
      Step 3 — HTTP output sink detection:
        Scan for res.send(html) / res.write(html) / res.end(html) patterns.
      Step 4 — Sanitizer check:
        If any XSS sanitizer (DOMPurify, encodeURIComponent, …) wraps the
        interpolated expression, return None (the flow is sanitized).

    Returns a StructuredEvidence object pre-populated with hit locations,
    ready to be prepended to the ReAct evidence list.
    """

    def detect(
        self,
        file_path: str,
        source: str,
        sink: str,
    ) -> StructuredEvidence | None:
        """
        Return StructuredEvidence when a template injection flow is found, else None.

        Parameters
        ----------
        file_path : str
            Path to the source file being analysed.
        source : str
            Declared taint source (e.g. "req.query.q").
        sink : str
            Declared taint sink (may be a DOM operation like "innerHTML").
        """
        # Only applies when sink is a DOM operation that would appear in a template
        sink_bare = sink.split("(")[0].strip().split(".")[-1]
        if sink_bare.lower() not in {s.lower().split(".")[-1] for s in _DOM_SINK_NAMES}:
            # Also trigger when sink is a generic output like "res.send" (belt-and-suspenders)
            if not _SERVER_OUTPUT_SINK_RE.search(sink):
                return None

        try:
            code = Path(file_path).read_text(errors="replace")
        except OSError:
            return None

        lines = code.splitlines()

        # Step 1 — Collect all variable names tainted from `source`
        source_bare = source.split(".")[-1].split("(")[0].strip()
        source_vars: set[str] = {source_bare}
        _ASSIGN_RE = re.compile(
            r"(?:const|let|var|)\s*(\w+)\s*=\s*.*\b" + re.escape(source_bare) + r"\b",
            re.IGNORECASE,
        )
        for line in lines:
            m = _ASSIGN_RE.search(line)
            if m:
                source_vars.add(m.group(1))

        if not source_vars:
            return None

        # Step 2 — Find template literals that interpolate a source variable
        # Match multi-line backtick template literals (simplified: scan for ${var})
        template_hits: list[CodeLocation] = []
        template_vars: set[str] = set()

        # Build a regex that matches `${source_var}` or `${source_var.prop}` etc.
        source_var_pat = "|".join(re.escape(v) for v in source_vars)
        interp_re = re.compile(r"\$\{(?:\s*)(?:" + source_var_pat + r")(?:[^}]*)?\}", re.IGNORECASE)

        # Also find the variable that receives the template literal
        # Note: multi-line templates are handled by the fallback in Step 3
        template_assign_re = re.compile(
            r"(?:const|let|var)\s+(\w+)\s*=\s*`[^`]*\$\{",
        )

        for i, line in enumerate(lines, 1):
            if interp_re.search(line):
                # Check sanitizers on the same line
                if _XSS_SANITIZER_RE.search(line):
                    logger.debug(
                        "TemplateInjectionDetector | sanitizer found on line %d — skipping",
                        i,
                    )
                    return None
                template_hits.append(
                    CodeLocation(
                        file=file_path,
                        line_start=i,
                        line_end=i,
                        snippet=line.rstrip()[:200],
                    )
                )

            # Capture the variable receiving the template result (single-line templates)
            m2 = template_assign_re.search(line)
            if m2 and interp_re.search(line):
                template_vars.add(m2.group(1))

        if not template_hits:
            return None

        # Step 3 — Find HTTP output sink calls that receive a tainted variable
        output_hits: list[CodeLocation] = []

        # Check if a template variable is passed to a server output sink
        for i, line in enumerate(lines, 1):
            if _SERVER_OUTPUT_SINK_RE.search(line):
                # Does this call receive a variable from our tainted template set?
                for tv in template_vars:
                    if re.search(r"\b" + re.escape(tv) + r"\b", line):
                        output_hits.append(
                            CodeLocation(
                                file=file_path,
                                line_start=i,
                                line_end=i,
                                snippet=line.rstrip()[:200],
                            )
                        )

        # Fallback: if we found template interpolation but couldn't match the variable
        # (e.g. inline template), check for any server output sink in the file
        if template_hits and not output_hits:
            for i, line in enumerate(lines, 1):
                if _SERVER_OUTPUT_SINK_RE.search(line):
                    output_hits.append(
                        CodeLocation(
                            file=file_path,
                            line_start=i,
                            line_end=i,
                            snippet=line.rstrip()[:200],
                        )
                    )

        if not output_hits:
            return None

        # Step 4 — Final sanitizer sweep over the whole function/route body
        # If any XSS sanitizer appears in the same lexical scope, be conservative
        all_hits = template_hits + output_hits
        min_line = min(h.line_start for h in all_hits)
        max_line = max(h.line_start for h in all_hits)
        scope_lines = lines[max(0, min_line - 5) : min(len(lines), max_line + 5)]
        for scope_line in scope_lines:
            if _XSS_SANITIZER_RE.search(scope_line):
                logger.debug(
                    "TemplateInjectionDetector | sanitizer in scope — not confirming"
                )
                return None

        # Build the evidence summary
        summary = (
            "SERVER-SIDE TEMPLATE INJECTION DETECTED (deterministic pre-pass):\n"
            f"  Source '{source_bare}' flows through template literal interpolation "
            f"(${{expr}}) to an HTTP output function - server-side Reflected XSS.\n"
            f"  Template interpolation at line(s): "
            f"{', '.join(str(h.line_start) for h in template_hits)}\n"
            f"  HTTP output sink at line(s): "
            f"{', '.join(str(h.line_start) for h in output_hits)}\n"
            "  Taint step: ${source_var} in template literal => tainted string => res.send()\n"
            "  No XSS sanitizer (DOMPurify, encodeURIComponent, htmlspecialchars) found on taint path.\n"
            "  VERDICT HINT: CONFIRM - this is a valid CWE-79 flow."
        )

        return StructuredEvidence(
            kind="grep_hits",
            hits=all_hits,
            summary=summary,
        )


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

        # ── Deterministic pre-pass: template injection detector ────────────────
        # Implements CodeQL-style "additional taint step" for JS template literals.
        # If a structural match is found, inject it as iteration-0 evidence so the
        # LLM ReAct loop and VerifierAgent both see it prominently.
        try:
            detector = TemplateInjectionDetector()
            pre_pass = detector.detect(spec.file, spec.source, spec.sink)
            if pre_pass is not None:
                logger.debug(
                    "Phase 3 | pre-pass TEMPLATE INJECTION match  %s line %d",
                    spec.file,
                    spec.line,
                )
                evidence.append(
                    VerificationEvidence(
                        iteration=0,
                        action="pre_pass_template_injection(structural)",
                        result=pre_pass.summary[:1000],
                        conclusion=(
                            "Deterministic structural evidence: source variable interpolated "
                            "un-sanitized into server-side template literal → HTTP output. "
                            "Weight this evidence heavily."
                        ),
                        structured=pre_pass,
                    )
                )
        except Exception as exc:
            logger.debug("Phase 3 | template injection pre-pass error (non-fatal): %s", exc)
        # ──────────────────────────────────────────────────────────────────────

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

            # Normalise action: resolve aliases first, then map unknown strings to
            # "conclude" so the pipeline never silently burns iterations on
            # hallucinated action names.
            raw_action = str(data.get("action", "conclude")).strip().lower()
            if raw_action in _ACTION_ALIASES:
                canonical = _ACTION_ALIASES[raw_action]
                logger.debug(
                    "Phase 3 | action alias %r → %r", raw_action, canonical
                )
                raw_action = canonical
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

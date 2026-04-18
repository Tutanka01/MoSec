"""
VerifierAgent — Lot D

Replaces the single-prompt `_conclude()` in DataFlowAgent with a three-stage
Propose → Falsify → Decide pipeline inspired by VulnSage's ThinkAndVerify
strategy (Zhang et al., 2025).

Design principles:
  - FAIL CLOSED: default verdict is "unreachable" when evidence is insufficient.
  - BURDEN OF PROOF: confirmation requires affirmative evidence of exploitability.
  - SELF-CONSISTENCY: optional N-way majority vote via *consistency_n*.
  - ADVERSARIAL: the Falsify stage forces the model to find flaws in its own reasoning.
"""

from __future__ import annotations

import logging
from collections import Counter

from models.schemas import TaintSpec, VerificationEvidence
from utils.llm import LLMClient

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

_PROPOSE_PROMPT = """\
You are a security analyst making an initial verdict on a taint flow.

Finding:
  File: {file}  Line: {line}  CWE: {cwe}
  Source: {source}  →  Sink: {sink}
  Sanitizers declared: {sanitizers}
  Taint summary: {taint_path_summary}

Evidence collected during verification:
{evidence}

State your INITIAL verdict and reasoning.  Be concrete — cite specific
evidence items by their iteration numbers.

Respond ONLY in JSON:
{{
  "verdict": "confirmed" | "sanitized" | "unreachable",
  "reasoning": "<cite evidence, be specific>"
}}
"""

_FALSIFY_PROMPT = """\
You are a skeptical red-team reviewer.  Your colleague has proposed the
following verdict on a taint flow.  Your job is to find weaknesses in the
reasoning and evidence that might make the verdict WRONG.

Proposed verdict: {verdict}
Reasoning: {reasoning}

Original finding:
  File: {file}  Line: {line}  CWE: {cwe}
  Source: {source}  →  Sink: {sink}
  Sanitizers: {sanitizers}

Evidence:
{evidence}

List AT LEAST 2 concrete reasons the proposed verdict could be incorrect.
If you genuinely cannot find any weakness, respond with: "NONE — verdict appears solid."

Respond ONLY in JSON:
{{
  "rebuttals": ["<reason 1>", "<reason 2>", ...]
}}
"""

_DECIDE_PROMPT = """\
You are the final arbiter of a taint-flow verdict.  You have both the initial
assessment and a skeptical rebuttal.  Weigh them carefully.

Initial verdict: {verdict}
Initial reasoning: {reasoning}

Skeptical rebuttals:
{rebuttals}

Finding:
  File: {file}  Line: {line}  CWE: {cwe}
  Source: {source}  →  Sink: {sink}
  Sanitizers: {sanitizers}

Evidence summary:
{evidence}

RULES:
  1. "confirmed"   — only if there is AFFIRMATIVE evidence that untrusted data
                     flows to the sink AND no effective sanitizer is on the path.
  2. "sanitized"   — only if you have positive evidence that a real sanitizer
                     interrupts the taint path.
  3. "unreachable" — default when evidence is ambiguous, sparse, or contradicted
                     by the rebuttals.

Respond ONLY in JSON:
{{
  "verdict": "confirmed" | "sanitized" | "unreachable",
  "reasoning": "<final explanation accounting for rebuttals>"
}}
"""


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------


class VerifierAgent:
    """
    Implements the Propose → Falsify → Decide verification pipeline.
    Can optionally run N times and take the majority vote (*consistency_n*).
    """

    def __init__(self, llm: LLMClient, consistency_n: int = 1) -> None:
        self.llm = llm
        self._n = max(1, consistency_n)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def verify(
        self,
        spec: TaintSpec,
        evidence: list[VerificationEvidence],
    ) -> tuple[str, str]:
        """
        Return (verdict, reasoning).
        verdict ∈ {"confirmed", "sanitized", "unreachable"}.
        Defaults to "unreachable" on any LLM / parse failure (fail-closed).
        """
        if self._n == 1:
            return self._single_verify(spec, evidence)

        # Self-consistency: run N independent verifications, majority vote
        verdicts: list[str] = []
        reasonings: list[str] = []
        for i in range(self._n):
            v, r = self._single_verify(spec, evidence)
            verdicts.append(v)
            reasonings.append(r)
            logger.debug("Phase 3 | verifier run %d/%d → %s", i + 1, self._n, v)

        winner, count = Counter(verdicts).most_common(1)[0]
        # Pick the reasoning from the first run that produced the winner
        winning_reasoning = next(
            r for v, r in zip(verdicts, reasonings) if v == winner
        )
        logger.info(
            "Phase 3 | verifier majority vote: %s (%d/%d)", winner, count, self._n
        )
        return winner, winning_reasoning

    # ------------------------------------------------------------------
    # Single Propose → Falsify → Decide pass
    # ------------------------------------------------------------------

    def _single_verify(
        self,
        spec: TaintSpec,
        evidence: list[VerificationEvidence],
    ) -> tuple[str, str]:
        evidence_text = self._format_evidence(evidence)

        # Stage 1 — Propose
        initial_verdict, initial_reasoning = self._propose(spec, evidence_text)

        # Stage 2 — Falsify (adversarial critique)
        rebuttals = self._falsify(spec, evidence_text, initial_verdict, initial_reasoning)

        # Stage 3 — Decide (weigh both sides, default to unreachable)
        final_verdict, final_reasoning = self._decide(
            spec, evidence_text, initial_verdict, initial_reasoning, rebuttals
        )

        return final_verdict, final_reasoning

    # ------------------------------------------------------------------
    # Stage implementations
    # ------------------------------------------------------------------

    def _propose(
        self, spec: TaintSpec, evidence_text: str
    ) -> tuple[str, str]:
        prompt = _PROPOSE_PROMPT.format(
            file=spec.file,
            line=spec.line,
            cwe=spec.cwe,
            source=spec.source,
            sink=spec.sink,
            sanitizers=spec.sanitizers or "none",
            taint_path_summary=spec.taint_path_summary,
            evidence=evidence_text,
        )
        try:
            content, _ = self.llm.chat(
                [{"role": "user", "content": prompt}],
                max_tokens=512,
                temperature=0.1,
            )
            data = self.llm.extract_json(content)
            verdict = self._safe_verdict(data.get("verdict", "unreachable"))
            reasoning = str(data.get("reasoning", ""))
            return verdict, reasoning
        except Exception as exc:
            logger.warning("Verifier propose failed: %s — defaulting to unreachable", exc)
            return "unreachable", f"Propose stage failed: {exc}"

    def _falsify(
        self,
        spec: TaintSpec,
        evidence_text: str,
        verdict: str,
        reasoning: str,
    ) -> list[str]:
        prompt = _FALSIFY_PROMPT.format(
            verdict=verdict,
            reasoning=reasoning,
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
                max_tokens=512,
                temperature=0.2,
            )
            data = self.llm.extract_json(content)
            rebuttals = data.get("rebuttals", [])
            if not isinstance(rebuttals, list):
                rebuttals = [str(rebuttals)]
            return [str(r) for r in rebuttals[:5]]
        except Exception as exc:
            logger.debug("Verifier falsify failed (non-critical): %s", exc)
            return []

    def _decide(
        self,
        spec: TaintSpec,
        evidence_text: str,
        initial_verdict: str,
        initial_reasoning: str,
        rebuttals: list[str],
    ) -> tuple[str, str]:
        rebuttal_text = (
            "\n".join(f"  - {r}" for r in rebuttals)
            if rebuttals
            else "  (no rebuttals — reviewer found the evidence solid)"
        )

        prompt = _DECIDE_PROMPT.format(
            verdict=initial_verdict,
            reasoning=initial_reasoning,
            rebuttals=rebuttal_text,
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
            verdict = self._safe_verdict(data.get("verdict", "unreachable"))
            reasoning = str(data.get("reasoning", ""))
            return verdict, reasoning
        except Exception as exc:
            # FAIL CLOSED: any LLM failure in the decide stage → unreachable
            logger.warning(
                "Verifier decide failed: %s — fail-closed to unreachable", exc
            )
            return "unreachable", f"Decide stage failed (fail-closed): {exc}"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_verdict(raw: object) -> str:
        """Normalise and validate a verdict string; default to 'unreachable'."""
        v = str(raw).strip().lower()
        if v in ("confirmed", "sanitized", "unreachable"):
            return v
        logger.warning("Verifier: unexpected verdict value %r — defaulting to unreachable", raw)
        return "unreachable"

    @staticmethod
    def _format_evidence(evidence: list[VerificationEvidence]) -> str:
        if not evidence:
            return "  (no evidence gathered)"
        parts: list[str] = []
        for e in evidence:
            if e.action.startswith("DEDUP:"):
                continue
            # Use structured summary when available (richer, no arbitrary truncation)
            if e.structured and e.structured.summary:
                obs = e.structured.summary[:600]
            else:
                obs = e.result[:600]
            parts.append(f"  [{e.iteration}] {e.action}:\n    {obs}")
        return "\n".join(parts) if parts else "  (no evidence gathered)"

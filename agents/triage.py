"""
Phase 1 — Triage Agent (Carlini Sweep)

Iterates over every source file independently and asks the LLM to find
real, exploitable vulnerabilities.  Findings below confidence 0.6 are dropped.
Output: findings.json
"""

from __future__ import annotations

import json
import logging
import uuid
from pathlib import Path
from pydantic import ValidationError

from models.schemas import FileFinding, RawFinding, RepositoryManifest
from utils.llm import EmptyResponseError, LLMClient, LLMError

logger = logging.getLogger(__name__)

MIN_CONFIDENCE: float = 0.6

_SYSTEM_PROMPT = """\
You are a world-class offensive security researcher competing in a CTF.
Your goal is to find REAL, EXPLOITABLE vulnerabilities in this code.
Do NOT say the code is safe. Do NOT hallucinate. Only report what you can PROVE exists in THIS file.
For each finding: specify the exact line number, the CWE category, a one-sentence attack description,
and a confidence score (0.0–1.0).
Respond ONLY in JSON array format: [{"line": N, "cwe": "CWE-XX", "description": "...", "confidence": 0.X}]
If you find nothing exploitable with confidence > 0.6, return an empty array [].
"""

# Files larger than this limit are truncated so we don't overflow the context.
_MAX_FILE_CHARS: int = 60_000


class TriageAgent:
    """Phase 1: per-file LLM vulnerability triage."""

    def __init__(self, llm: LLMClient, output_dir: str) -> None:
        self.llm = llm
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, manifest: RepositoryManifest) -> list[FileFinding]:
        all_findings: list[FileFinding] = []

        for file_path in manifest.files:
            try:
                findings = self._analyse_file(file_path, manifest.repo_path)
                all_findings.extend(findings)
                logger.info(
                    "Phase 1 | %s → %d finding(s)", file_path, len(findings)
                )
            except Exception as exc:
                logger.error("Phase 1 | error on %s: %s", file_path, exc)

        logger.info("Phase 1 complete | total findings: %d", len(all_findings))

        out = self.output_dir / "findings.json"
        out.write_text(
            json.dumps([f.model_dump() for f in all_findings], indent=2),
            encoding="utf-8",
        )
        logger.info("Findings written → %s", out)
        return all_findings

    # ------------------------------------------------------------------
    # Per-file analysis
    # ------------------------------------------------------------------

    def _analyse_file(self, file_path: str, repo_path: str) -> list[FileFinding]:
        path = Path(file_path)

        try:
            raw_code = path.read_text(errors="replace")
        except OSError as exc:
            logger.warning("Cannot read %s: %s", file_path, exc)
            return []

        if not raw_code.strip():
            return []

        # Truncate very large files, keeping the beginning and end
        if len(raw_code) > _MAX_FILE_CHARS:
            half = _MAX_FILE_CHARS // 2
            raw_code = (
                raw_code[:half]
                + "\n\n... [TRUNCATED — file is large] ...\n\n"
                + raw_code[-half:]
            )

        numbered = self._number_lines(raw_code)

        try:
            rel_path = str(path.relative_to(repo_path))
        except ValueError:
            rel_path = file_path

        messages = [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"File: {rel_path}\n\n"
                    f"```\n{numbered}\n```\n\n"
                    f"Respond with a JSON array only."
                ),
            },
        ]

        try:
            content, usage = self.llm.chat(messages, max_tokens=2048, temperature=0.1)
        except LLMError as exc:
            logger.error("LLM call failed for %s: %s", file_path, exc)
            return []

        logger.debug("Phase 1 | %s | tokens: %s", file_path, usage)
        return self._parse_llm_response(content, file_path)

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    def _parse_llm_response(
        self, content: str, file_path: str
    ) -> list[FileFinding]:
        try:
            raw = self.llm.extract_json(content)
        except EmptyResponseError:
            # Model returned nothing — context overflow, refusal, or server hiccup.
            # Already retried in LLMClient.chat(); log clearly and move on.
            logger.warning(
                "Phase 1 | %s: LLM empty response (possible context overflow or model refusal)",
                file_path,
            )
            return []
        except ValueError as exc:
            logger.warning("Phase 1 | %s: JSON parse failed — %s", file_path, exc)
            return []

        if not isinstance(raw, list):
            # Some models wrap findings: {"findings": [...]} or {"vulnerabilities": [...]}
            if isinstance(raw, dict):
                for v in raw.values():
                    if isinstance(v, list):
                        raw = v
                        logger.debug("Phase 1 | %s: unwrapped dict → list", file_path)
                        break
                else:
                    # Single finding returned as a bare dict → one-element list
                    raw = [raw]
            if not isinstance(raw, list):
                logger.warning(
                    "Phase 1 | expected JSON array for %s, got %s", file_path, type(raw)
                )
                return []

        findings: list[FileFinding] = []
        for item in raw:
            try:
                raw_finding = RawFinding.model_validate(item)
            except ValidationError as exc:
                logger.debug("Phase 1 | invalid finding schema: %s — %s", item, exc)
                continue

            if raw_finding.confidence < MIN_CONFIDENCE:
                continue

            findings.append(
                FileFinding(
                    finding_id=str(uuid.uuid4()),
                    file=file_path,
                    line=raw_finding.line,
                    cwe=raw_finding.cwe,
                    description=raw_finding.description,
                    confidence=raw_finding.confidence,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _number_lines(code: str) -> str:
        return "\n".join(
            f"{i + 1:5d}  {line}"
            for i, line in enumerate(code.splitlines())
        )

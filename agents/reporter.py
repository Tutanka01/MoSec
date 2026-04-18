"""
Phase 5 — Report Agent

For every validated vulnerability:
  - Asks the LLM to compute CVSS 3.1 metric values (AV/AC/PR/UI/S/C/I/A)
  - Calculates the actual CVSS 3.1 base score using the analytic formula
  - Generates a human-readable title, impact statement, and remediation advice
  - Writes results.sarif (SARIF 2.1.0) and report.md
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from models.schemas import (
    CVSSMetrics,
    CVSSScore,
    ConfirmedFlow,
    PipelineReport,
    ReportEntry,
    ValidatedVuln,
    VerificationEvidence,
    calculate_cvss31,
)
from utils.llm import LLMClient, LLMError

logger = logging.getLogger(__name__)

_TOOL_NAME = "MoSec-SAST"
_TOOL_VERSION = "1.0.0"
_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)

_SEVERITY_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "NONE": "none",
}

_CVSS_SYSTEM_PROMPT = """\
You are a CVSS 3.1 scoring expert.  Given a vulnerability description and
proof-of-concept, select the correct metric values.

Metric value options:
  AV (Attack Vector):          N=Network, A=Adjacent, L=Local, P=Physical
  AC (Attack Complexity):      L=Low, H=High
  PR (Privileges Required):    N=None, L=Low, H=High
  UI (User Interaction):       N=None, R=Required
  S  (Scope):                  U=Unchanged, C=Changed
  C  (Confidentiality Impact): N=None, L=Low, H=High
  I  (Integrity Impact):       N=None, L=Low, H=High
  A  (Availability Impact):    N=None, L=Low, H=High

Respond ONLY in JSON:
{
  "attack_vector": "N|A|L|P",
  "attack_complexity": "L|H",
  "privileges_required": "N|L|H",
  "user_interaction": "N|R",
  "scope": "U|C",
  "confidentiality": "N|L|H",
  "integrity": "N|L|H",
  "availability": "N|L|H",
  "title": "<short vulnerability title, ≤ 60 chars>",
  "impact": "<one sentence describing the real-world impact>",
  "remediation": "<specific code-level fix, not generic advice>"
}
"""

# Fallback metric defaults when the LLM fails
_DEFAULT_METRICS = CVSSMetrics(
    attack_vector="N",
    attack_complexity="L",
    privileges_required="N",
    user_interaction="N",
    scope="U",
    confidentiality="L",
    integrity="L",
    availability="N",
)


class ReporterAgent:
    """Phase 5: CVSS scoring, SARIF output, markdown report."""

    def __init__(
        self,
        llm: LLMClient,
        output_dir: str,
        pipeline_stats: dict | None = None,
    ) -> None:
        self.llm = llm
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.pipeline_stats: dict = pipeline_stats or {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(
        self,
        vulns: list[ValidatedVuln],
        confirmed_flows: list[ConfirmedFlow] | None = None,
    ) -> PipelineReport:
        entries: list[ReportEntry] = []

        for vuln in vulns:
            try:
                entry = self._build_report_entry(vuln)
                entries.append(entry)
                logger.info(
                    "Phase 5 | %s  CVSS %.1f (%s)  %s",
                    vuln.cwe,
                    entry.cvss.base_score,
                    entry.cvss.severity,
                    entry.title,
                )
            except Exception as exc:
                logger.error(
                    "Phase 5 | error on finding %s: %s", vuln.finding_id, exc
                )

        # Sort by CVSS descending
        entries.sort(key=lambda e: e.cvss.base_score, reverse=True)

        sarif_path = str(self.output_dir / "results.sarif")
        md_path = str(self.output_dir / "report.md")

        self._write_sarif(entries, sarif_path, confirmed_flows=confirmed_flows)
        self._write_markdown(entries, md_path)

        report = PipelineReport(
            total_files_scanned=self.pipeline_stats.get("files_scanned", 0),
            total_findings_phase1=self.pipeline_stats.get("findings_phase1", 0),
            total_taint_specs=self.pipeline_stats.get("taint_specs", 0),
            total_confirmed_flows=self.pipeline_stats.get("confirmed_flows", 0),
            total_validated_vulns=len(entries),
            vulnerabilities=entries,
            sarif_path=sarif_path,
            markdown_path=md_path,
        )

        out = self.output_dir / "pipeline_report.json"
        out.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        logger.info(
            "Phase 5 complete | %d vulnerabilities | SARIF → %s | MD → %s",
            len(entries),
            sarif_path,
            md_path,
        )
        return report

    # ------------------------------------------------------------------
    # Per-vulnerability processing
    # ------------------------------------------------------------------

    def _build_report_entry(self, vuln: ValidatedVuln) -> ReportEntry:
        cvss_data = self._score_vulnerability(vuln)
        metrics = cvss_data["metrics"]
        extra = cvss_data["extra"]

        cvss_score = calculate_cvss31(metrics)

        return ReportEntry(
            finding_id=vuln.finding_id,
            file=vuln.file,
            line=vuln.line,
            cwe=vuln.cwe,
            title=extra.get("title", f"{vuln.cwe} in {Path(vuln.file).name}"),
            cvss=cvss_score,
            description=vuln.description,
            attack_scenario=vuln.attack_scenario,
            impact=extra.get("impact", ""),
            remediation=extra.get("remediation", ""),
            poc=vuln.poc,
            exploitability=vuln.exploitability,
        )

    def _score_vulnerability(self, vuln: ValidatedVuln) -> dict:
        """Return {'metrics': CVSSMetrics, 'extra': {title, impact, remediation}}."""
        prompt = (
            f"Vulnerability:\n"
            f"  CWE: {vuln.cwe}\n"
            f"  Description: {vuln.description}\n"
            f"  Source: {vuln.source}\n"
            f"  Sink: {vuln.sink}\n"
            f"  Attack scenario: {vuln.attack_scenario}\n"
            f"  PoC: {vuln.poc}\n"
            f"  File: {vuln.file}  Line: {vuln.line}\n"
        )

        try:
            content, _ = self.llm.chat(
                [
                    {"role": "system", "content": _CVSS_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=512,
                temperature=0.0,
            )
            data = self.llm.extract_json(content)
        except (LLMError, ValueError) as exc:
            logger.warning("Phase 5 | CVSS scoring failed for %s: %s", vuln.finding_id, exc)
            return {
                "metrics": _DEFAULT_METRICS,
                "extra": {
                    "title": f"{vuln.cwe} in {Path(vuln.file).name}",
                    "impact": vuln.attack_scenario,
                    "remediation": "Review and sanitise all user-controlled inputs before use.",
                },
            }

        _VALID_AV = {"N", "A", "L", "P"}
        _VALID_AC = {"L", "H"}
        _VALID_PR = {"N", "L", "H"}
        _VALID_UI = {"N", "R"}
        _VALID_S = {"U", "C"}
        _VALID_CIA = {"N", "L", "H"}

        def _pick(key: str, valid: set, default: str) -> str:
            v = str(data.get(key, default)).upper()
            return v if v in valid else default

        metrics = CVSSMetrics(
            attack_vector=_pick("attack_vector", _VALID_AV, "N"),
            attack_complexity=_pick("attack_complexity", _VALID_AC, "L"),
            privileges_required=_pick("privileges_required", _VALID_PR, "N"),
            user_interaction=_pick("user_interaction", _VALID_UI, "N"),
            scope=_pick("scope", _VALID_S, "U"),
            confidentiality=_pick("confidentiality", _VALID_CIA, "L"),
            integrity=_pick("integrity", _VALID_CIA, "L"),
            availability=_pick("availability", _VALID_CIA, "N"),
        )

        extra = {
            "title": str(data.get("title", f"{vuln.cwe} in {Path(vuln.file).name}"))[:80],
            "impact": str(data.get("impact", "")),
            "remediation": str(data.get("remediation", "")),
        }

        return {"metrics": metrics, "extra": extra}

    # ------------------------------------------------------------------
    # SARIF 2.1.0 output
    # ------------------------------------------------------------------

    def _write_sarif(
        self,
        entries: list[ReportEntry],
        path: str,
        confirmed_flows: list[ConfirmedFlow] | None = None,
    ) -> None:
        # Build a lookup {finding_id → ConfirmedFlow} for codeFlows enrichment (Lot D)
        flow_map: dict[str, ConfirmedFlow] = {}
        if confirmed_flows:
            for cf in confirmed_flows:
                flow_map[cf.finding_id] = cf

        rules = []
        seen_rules: set[str] = set()
        results = []

        for e in entries:
            rule_id = e.cwe.replace(" ", "-")
            if rule_id not in seen_rules:
                seen_rules.add(rule_id)
                rules.append({
                    "id": rule_id,
                    "name": e.title,
                    "shortDescription": {"text": e.title},
                    "fullDescription": {"text": e.description},
                    "defaultConfiguration": {
                        "level": _SEVERITY_LEVEL.get(e.cvss.severity, "warning"),
                    },
                    "properties": {
                        "tags": ["security", e.cwe],
                        "problem.severity": _SEVERITY_LEVEL.get(e.cvss.severity, "warning"),
                        "security-severity": str(e.cvss.base_score),
                    },
                })

            # Normalise path for SARIF URIs (forward slashes, no leading /)
            uri = e.file.replace("\\", "/").lstrip("/")

            # Build codeFlows from StructuredEvidence when available (Lot D)
            code_flows = _build_code_flows(flow_map.get(e.finding_id), uri)

            sarif_result: dict = {
                "ruleId": rule_id,
                "level": _SEVERITY_LEVEL.get(e.cvss.severity, "warning"),
                "message": {
                    "text": (
                        f"{e.title}\n\n"
                        f"**Attack scenario:** {e.attack_scenario}\n\n"
                        f"**PoC:** `{e.poc}`\n\n"
                        f"**Remediation:** {e.remediation}"
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": uri,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {"startLine": max(1, e.line)},
                        }
                    }
                ],
                "fingerprints": {"finding_id/v1": e.finding_id},
                "properties": {
                    "cwe": e.cwe,
                    "cvss_vector": e.cvss.vector_string,
                    "cvss_score": e.cvss.base_score,
                    "exploitability": e.exploitability,
                    "poc": e.poc,
                },
            }
            if code_flows:
                sarif_result["codeFlows"] = code_flows

            results.append(sarif_result)

        sarif_doc = {
            "$schema": _SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": _TOOL_NAME,
                            "version": _TOOL_VERSION,
                            "informationUri": "https://github.com/mosec/sast-agent",
                            "rules": rules,
                        }
                    },
                    "results": results,
                    "automationDetails": {
                        "description": {
                            "text": f"MoSec SAST pipeline run — {datetime.now(timezone.utc).isoformat()}"
                        }
                    },
                }
            ],
        }

        Path(path).write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")
        logger.info("SARIF written → %s", path)

    # ------------------------------------------------------------------
    # Markdown report
    # ------------------------------------------------------------------

    def _write_markdown(self, entries: list[ReportEntry], path: str) -> None:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        lines: list[str] = [
            f"# MoSec SAST Security Report",
            f"",
            f"Generated: {ts}",
            f"",
            f"## Summary",
            f"",
            f"| # | Severity | CVSS | CWE | File | Title |",
            f"|---|----------|------|-----|------|-------|",
        ]

        for idx, e in enumerate(entries, 1):
            lines.append(
                f"| {idx} | **{e.cvss.severity}** | {e.cvss.base_score} "
                f"| {e.cwe} | `{Path(e.file).name}:{e.line}` | {e.title} |"
            )

        lines += ["", "---", ""]

        for idx, e in enumerate(entries, 1):
            badge = _severity_badge(e.cvss.severity)
            lines += [
                f"## {idx}. {e.title}  {badge}",
                f"",
                f"| Field | Value |",
                f"|-------|-------|",
                f"| **File** | `{e.file}:{e.line}` |",
                f"| **CWE** | {e.cwe} |",
                f"| **CVSS 3.1** | `{e.cvss.vector_string}` → **{e.cvss.base_score}** ({e.cvss.severity}) |",
                f"| **Exploitability** | {e.exploitability} |",
                f"| **Finding ID** | `{e.finding_id}` |",
                f"",
                f"### Description",
                f"",
                f"{e.description}",
                f"",
                f"### Attack Scenario",
                f"",
                f"{e.attack_scenario}",
                f"",
                f"### Impact",
                f"",
                f"{e.impact}",
                f"",
                f"### Proof of Concept",
                f"",
                f"```",
                f"{e.poc}",
                f"```",
                f"",
                f"### Taint Flow",
                f"",
                f"*See `confirmed_flows.json` → finding `{e.finding_id}` for the full ReAct trace.*",
                f"",
                f"### Remediation",
                f"",
                f"{e.remediation}",
                f"",
                f"---",
                f"",
            ]

        Path(path).write_text("\n".join(lines), encoding="utf-8")
        logger.info("Markdown report written -> %s", path)


def _severity_badge(severity: str) -> str:
    badges = {
        "CRITICAL": "🔴 CRITICAL",
        "HIGH": "🟠 HIGH",
        "MEDIUM": "🟡 MEDIUM",
        "LOW": "🟢 LOW",
        "NONE": "⚪ NONE",
    }
    return badges.get(severity, severity)


def _build_code_flows(
    flow: ConfirmedFlow | None, default_uri: str
) -> list[dict] | None:
    """
    Build a SARIF 2.1.0 `codeFlows` array from the VerificationEvidence (Lot D).

    Uses StructuredEvidence.hits (CodeLocation) when available — these carry
    precise file/line ranges produced by Semgrep, grep, or CodeQL actions.
    Falls back to the raw `result` text when no structured evidence exists.
    """
    if flow is None or not flow.verification_evidence:
        return None

    thread_flow_locations: list[dict] = []

    for ev in flow.verification_evidence:
        if ev.action.startswith("DEDUP:"):
            continue

        # Prefer structured evidence hits (accurate line numbers)
        if ev.structured and ev.structured.hits:
            for hit in ev.structured.hits[:3]:
                hit_uri = hit.file.replace("\\", "/").lstrip("/") if hit.file else default_uri
                loc: dict = {
                    "location": {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": hit_uri,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": max(1, hit.line_start),
                                "endLine": max(1, hit.line_end),
                            },
                        },
                        "message": {"text": f"[{ev.action}] {hit.snippet[:200]}"},
                    }
                }
                thread_flow_locations.append(loc)
        else:
            # Fallback: record the action as a logical location (no line number)
            thread_flow_locations.append({
                "location": {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": default_uri,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {"startLine": max(1, flow.line)},
                    },
                    "message": {
                        "text": f"[iter {ev.iteration}] {ev.action}: {ev.result[:200]}"
                    },
                }
            })

    if not thread_flow_locations:
        return None

    return [
        {
            "message": {"text": f"Taint flow verified in {flow.verification_iterations} ReAct iteration(s)"},
            "threadFlows": [
                {
                    "locations": thread_flow_locations,
                }
            ],
        }
    ]

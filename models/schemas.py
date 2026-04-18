"""
Pydantic schemas for all inter-agent data structures in the SAST pipeline.
"""

from __future__ import annotations

import math
from typing import Literal, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# ReAct / Verifier shared types (Lots A & D)
# ---------------------------------------------------------------------------


class ReActStep(BaseModel):
    """Validated shape of the LLM's reasoning step in the ReAct loop (Lot A)."""

    reasoning: str = ""
    action: Literal[
        "run_semgrep", "grep_sanitizers", "read_context", "run_codeql", "conclude"
    ]
    action_param: str = ""
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)


class CodeLocation(BaseModel):
    """Precise code location used inside StructuredEvidence (Lot D)."""

    file: str
    line_start: int
    line_end: int
    snippet: str = ""


class StructuredEvidence(BaseModel):
    """Rich evidence record replacing the raw-string result field (Lot D)."""

    kind: Literal[
        "semgrep_matches", "grep_hits", "code_slice",
        "codeql_paths", "no_flow", "conclude", "unknown",
    ]
    hits: list[CodeLocation] = Field(default_factory=list)
    summary: str


class TraceResult(BaseModel):
    """Return type of the AST-based static trace (Lot C)."""

    reachable: bool
    reason: str = ""
    path: list[str] = Field(default_factory=list)
    function_scope: str = ""


class ASTCandidate(BaseModel):
    """Source or sink candidate extracted from the AST (Lot C)."""

    kind: Literal["source", "sink"]
    name: str
    line: int
    col: int = 0
    # How the sink is used: call, method_call, property_assignment, subscript_assignment
    sink_kind: str = "call"
    assigned_from: Optional[str] = None
    returns_var: Optional[str] = None
    args: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Phase 0 — Ingestion
# ---------------------------------------------------------------------------


class EntryPoint(BaseModel):
    file: str
    line: int
    type: str  # http_route | file_read | subprocess | eval | deserialization
    name: str


class Dependency(BaseModel):
    name: str
    version: Optional[str] = None
    ecosystem: str  # pip | npm


class ASTSummary(BaseModel):
    file: str
    functions: list[str] = Field(default_factory=list)
    classes: list[str] = Field(default_factory=list)
    imports: list[str] = Field(default_factory=list)


class RepositoryManifest(BaseModel):
    repo_path: str
    files: list[str]
    entry_points: list[EntryPoint] = Field(default_factory=list)
    dependencies: list[Dependency] = Field(default_factory=list)
    ast_summary: list[ASTSummary] = Field(default_factory=list)
    codeql_db_path: Optional[str] = None


# ---------------------------------------------------------------------------
# Phase 1 — Triage
# ---------------------------------------------------------------------------


class RawFinding(BaseModel):
    """Shape expected directly from the LLM JSON array."""

    line: int
    cwe: str
    description: str
    confidence: float


class FileFinding(BaseModel):
    """Enriched finding with a stable UUID, persisted to findings.json."""

    finding_id: str
    file: str
    line: int
    cwe: str
    description: str
    confidence: float


# ---------------------------------------------------------------------------
# Phase 2 — Taint Specification
# ---------------------------------------------------------------------------


class TaintSpec(BaseModel):
    finding_id: str
    file: str
    line: int
    cwe: str
    description: str
    confidence: float
    # LLM-extracted taint fields
    source: str
    sink: str
    sanitizers: list[str] = Field(default_factory=list)
    unresolved_calls: list[str] = Field(default_factory=list)
    taint_path_summary: str
    # Path to the generated Semgrep rule YAML
    semgrep_rule_path: Optional[str] = None
    # AST metadata populated when TaintSpecAgent uses AST grounding (Lot C)
    sink_kind: str = "call"
    source_line: Optional[int] = None
    source_col: Optional[int] = None
    sink_line: Optional[int] = None
    sink_col: Optional[int] = None


# ---------------------------------------------------------------------------
# Phase 3 — Data Flow Verification (ReAct)
# ---------------------------------------------------------------------------


class VerificationEvidence(BaseModel):
    iteration: int
    action: str
    result: str
    conclusion: str
    structured: Optional[StructuredEvidence] = None  # Lot D rich evidence


class ConfirmedFlow(BaseModel):
    finding_id: str
    file: str
    line: int
    cwe: str
    description: str
    confidence: float
    source: str
    sink: str
    sanitizers: list[str] = Field(default_factory=list)
    taint_path_summary: str
    verification_iterations: int
    verification_evidence: list[VerificationEvidence] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Phase 4 — Exploit Hypothesis
# ---------------------------------------------------------------------------


class ValidatedVuln(BaseModel):
    finding_id: str
    file: str
    line: int
    cwe: str
    description: str
    confidence: float
    source: str
    sink: str
    taint_path_summary: str
    poc: str
    attack_scenario: str
    exploitability: str  # high | medium | low


# ---------------------------------------------------------------------------
# Phase 5 — Report
# ---------------------------------------------------------------------------


class CVSSMetrics(BaseModel):
    attack_vector: str       # N | A | L | P
    attack_complexity: str   # L | H
    privileges_required: str # N | L | H
    user_interaction: str    # N | R
    scope: str               # U | C
    confidentiality: str     # N | L | H
    integrity: str           # N | L | H
    availability: str        # N | L | H


class CVSSScore(BaseModel):
    base_score: float
    severity: str        # NONE | LOW | MEDIUM | HIGH | CRITICAL
    vector_string: str
    metrics: CVSSMetrics


class ReportEntry(BaseModel):
    finding_id: str
    file: str
    line: int
    cwe: str
    title: str
    cvss: CVSSScore
    description: str
    attack_scenario: str
    impact: str
    remediation: str
    poc: str
    exploitability: str


class PipelineReport(BaseModel):
    total_files_scanned: int
    total_findings_phase1: int
    total_taint_specs: int
    total_confirmed_flows: int
    total_validated_vulns: int
    vulnerabilities: list[ReportEntry]
    sarif_path: str
    markdown_path: str


# ---------------------------------------------------------------------------
# CVSS 3.1 calculator (no external deps)
# ---------------------------------------------------------------------------

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}   # Scope Unchanged
_PR_C = {"N": 0.85, "L": 0.50, "H": 0.50}   # Scope Changed
_UI = {"N": 0.85, "R": 0.62}
_IMP = {"N": 0.00, "L": 0.22, "H": 0.56}

_SEVERITY_THRESHOLDS = [
    (0.0, "NONE"),
    (0.1, "LOW"),
    (4.0, "MEDIUM"),
    (7.0, "HIGH"),
    (9.0, "CRITICAL"),
]


def _roundup(value: float) -> float:
    """CVSS 3.1 Roundup: smallest 1-decimal value >= input."""
    return math.ceil(value * 10) / 10


def calculate_cvss31(m: CVSSMetrics) -> CVSSScore:
    av = _AV[m.attack_vector]
    ac = _AC[m.attack_complexity]
    pr = _PR_C[m.privileges_required] if m.scope == "C" else _PR_U[m.privileges_required]
    ui = _UI[m.user_interaction]
    c = _IMP[m.confidentiality]
    i = _IMP[m.integrity]
    a = _IMP[m.availability]

    isc_base = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)

    if m.scope == "U":
        impact = 6.42 * isc_base
    else:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        base_score = 0.0
    elif m.scope == "U":
        base_score = _roundup(min(impact + exploitability, 10.0))
    else:
        base_score = _roundup(min(1.08 * (impact + exploitability), 10.0))

    severity = "NONE"
    for threshold, label in _SEVERITY_THRESHOLDS:
        if base_score >= threshold:
            severity = label

    vector = (
        f"CVSS:3.1/AV:{m.attack_vector}/AC:{m.attack_complexity}"
        f"/PR:{m.privileges_required}/UI:{m.user_interaction}"
        f"/S:{m.scope}/C:{m.confidentiality}/I:{m.integrity}/A:{m.availability}"
    )

    return CVSSScore(
        base_score=base_score,
        severity=severity,
        vector_string=vector,
        metrics=m,
    )

#!/usr/bin/env python3
"""
MoSec SAST Pipeline — main orchestrator.

Usage:
  python pipeline.py --repo-path /path/to/repo [--phase 0] [--keep-rules]
                     [--output-dir ./output] [--clone-url https://github.com/...]
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import sys
from pathlib import Path

from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Bootstrap: load .env before importing agents (they may read env at import)
# ---------------------------------------------------------------------------
load_dotenv()

from agents.ingestion import IngestionAgent
from agents.triage import TriageAgent
from agents.taint_spec import TaintSpecAgent
from agents.dataflow import DataFlowAgent
from agents.exploit import ExploitAgent
from agents.reporter import ReporterAgent

from models.schemas import (
    ConfirmedFlow,
    FileFinding,
    PipelineReport,
    RepositoryManifest,
    TaintSpec,
    ValidatedVuln,
)
from utils.llm import LLMClient

# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------


def _configure_logging(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    log_path = output_dir / "pipeline.log"

    fmt = "%(asctime)s  %(levelname)-8s  %(name)-30s  %(message)s"
    handlers: list[logging.Handler] = [
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_path, encoding="utf-8"),
    ]
    logging.basicConfig(level=logging.INFO, format=fmt, handlers=handlers)

    # Reduce noise from openai HTTP client
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.WARNING)


logger = logging.getLogger("pipeline")


# ---------------------------------------------------------------------------
# Intermediate state helpers
# ---------------------------------------------------------------------------


def _load_json(path: Path) -> list | dict | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except Exception as exc:
        logger.error("Failed to load %s: %s", path, exc)
        return None


def _load_manifest(output_dir: Path) -> RepositoryManifest | None:
    data = _load_json(output_dir / "manifest.json")
    if data is None:
        return None
    try:
        return RepositoryManifest.model_validate(data)
    except Exception as exc:
        logger.error("manifest.json parse error: %s", exc)
        return None


def _load_findings(output_dir: Path) -> list[FileFinding] | None:
    data = _load_json(output_dir / "findings.json")
    if data is None or not isinstance(data, list):
        return None
    try:
        return [FileFinding.model_validate(d) for d in data]
    except Exception as exc:
        logger.error("findings.json parse error: %s", exc)
        return None


def _load_taint_specs(output_dir: Path) -> list[TaintSpec] | None:
    data = _load_json(output_dir / "taint_specs.json")
    if data is None or not isinstance(data, list):
        return None
    try:
        return [TaintSpec.model_validate(d) for d in data]
    except Exception as exc:
        logger.error("taint_specs.json parse error: %s", exc)
        return None


def _load_confirmed_flows(output_dir: Path) -> list[ConfirmedFlow] | None:
    data = _load_json(output_dir / "confirmed_flows.json")
    if data is None or not isinstance(data, list):
        return None
    try:
        return [ConfirmedFlow.model_validate(d) for d in data]
    except Exception as exc:
        logger.error("confirmed_flows.json parse error: %s", exc)
        return None


def _load_validated_vulns(output_dir: Path) -> list[ValidatedVuln] | None:
    data = _load_json(output_dir / "validated_vulns.json")
    if data is None or not isinstance(data, list):
        return None
    try:
        return [ValidatedVuln.model_validate(d) for d in data]
    except Exception as exc:
        logger.error("validated_vulns.json parse error: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


def build_llm_client() -> LLMClient:
    base_url = os.environ.get("LLM_BASE_URL", "https://llm.eva.univ-pau.fr/v1")
    api_key = os.environ.get("LLM_API_KEY", "")
    model = os.environ.get("LLM_MODEL", "gemma-4-31b-it-q8_0")
    logger.info("LLM endpoint: %s  model: %s", base_url, model)
    return LLMClient(base_url=base_url, api_key=api_key, model=model)


def run_pipeline(
    repo_path: str,
    output_dir: Path,
    start_phase: int,
    keep_rules: bool,
    clone_url: str | None,
    codeql_bin: str,
    rules_dir: str,
) -> PipelineReport | None:
    llm = build_llm_client()

    # ── Phase 0 — Ingestion ──────────────────────────────────────────────
    manifest: RepositoryManifest | None = None

    if start_phase <= 0:
        logger.info("═══ Phase 0: Ingestion ═══")
        agent0 = IngestionAgent(str(output_dir), codeql_bin=codeql_bin)
        manifest = agent0.run(repo_path, clone_url=clone_url)
    else:
        manifest = _load_manifest(output_dir)
        if manifest is None:
            logger.error("Cannot resume from phase %d: manifest.json missing", start_phase)
            return None
        logger.info("Phase 0 skipped — loaded manifest.json")

    # ── Phase 1 — Triage ────────────────────────────────────────────────
    findings: list[FileFinding] | None = None

    if start_phase <= 1:
        logger.info("═══ Phase 1: Triage (Carlini Sweep) ═══")
        agent1 = TriageAgent(llm, str(output_dir))
        findings = agent1.run(manifest)
    else:
        findings = _load_findings(output_dir)
        if findings is None:
            logger.error("Cannot resume from phase %d: findings.json missing", start_phase)
            return None
        logger.info("Phase 1 skipped — loaded %d findings", len(findings))

    if not findings:
        logger.info("No findings above confidence threshold — pipeline complete (clean repo).")
        _write_clean_report(output_dir, manifest)
        return None

    # ── Phase 2 — Taint Specification ───────────────────────────────────
    taint_specs: list[TaintSpec] | None = None

    if start_phase <= 2:
        logger.info("═══ Phase 2: Taint Specification ═══")
        agent2 = TaintSpecAgent(llm, str(output_dir), rules_dir=rules_dir)
        taint_specs = agent2.run(findings)
    else:
        taint_specs = _load_taint_specs(output_dir)
        if taint_specs is None:
            logger.error("Cannot resume from phase %d: taint_specs.json missing", start_phase)
            return None
        logger.info("Phase 2 skipped — loaded %d taint specs", len(taint_specs))

    if not taint_specs:
        logger.info("No taint specs produced — pipeline complete.")
        return None

    # ── Phase 3 — Data Flow Verification ────────────────────────────────
    confirmed_flows: list[ConfirmedFlow] | None = None

    if start_phase <= 3:
        logger.info("═══ Phase 3: Data Flow Verification (ReAct) ═══")
        agent3 = DataFlowAgent(
            llm,
            str(output_dir),
            codeql_db_path=manifest.codeql_db_path,
            codeql_bin=codeql_bin,
        )
        confirmed_flows = agent3.run(taint_specs, manifest.repo_path)
    else:
        confirmed_flows = _load_confirmed_flows(output_dir)
        if confirmed_flows is None:
            logger.error("Cannot resume from phase %d: confirmed_flows.json missing", start_phase)
            return None
        logger.info("Phase 3 skipped — loaded %d confirmed flows", len(confirmed_flows))

    if not confirmed_flows:
        logger.info("No flows survived verification — pipeline complete (all sanitized/unreachable).")
        return None

    # ── Phase 4 — Exploit Hypothesis ────────────────────────────────────
    validated_vulns: list[ValidatedVuln] | None = None

    if start_phase <= 4:
        logger.info("═══ Phase 4: Exploit Hypothesis ═══")
        agent4 = ExploitAgent(llm, str(output_dir))
        validated_vulns = agent4.run(confirmed_flows)
    else:
        validated_vulns = _load_validated_vulns(output_dir)
        if validated_vulns is None:
            logger.error("Cannot resume from phase %d: validated_vulns.json missing", start_phase)
            return None
        logger.info("Phase 4 skipped — loaded %d validated vulns", len(validated_vulns))

    if not validated_vulns:
        logger.info("No exploitable vulnerabilities validated — pipeline complete.")
        return None

    # ── Phase 5 — Report ────────────────────────────────────────────────
    if start_phase <= 5:
        logger.info("═══ Phase 5: Report Generation ═══")
        pipeline_stats = {
            "files_scanned": len(manifest.files),
            "findings_phase1": len(findings),
            "taint_specs": len(taint_specs),
            "confirmed_flows": len(confirmed_flows),
        }
        agent5 = ReporterAgent(llm, str(output_dir), pipeline_stats=pipeline_stats)
        report = agent5.run(validated_vulns)
    else:
        logger.info("Phase 5 skipped — nothing to do")
        return None

    # ── Token summary ───────────────────────────────────────────────────
    tok = llm.token_summary()
    logger.info(
        "Token usage: prompt=%d  completion=%d  total=%d",
        tok["total_prompt_tokens"],
        tok["total_completion_tokens"],
        tok["total_tokens"],
    )
    (output_dir / "token_usage.json").write_text(json.dumps(tok, indent=2), encoding="utf-8")

    # ── Clean up Semgrep rules unless --keep-rules ───────────────────────
    if not keep_rules:
        rules_path = Path(rules_dir)
        if rules_path.exists():
            shutil.rmtree(rules_path, ignore_errors=True)
            logger.info("Semgrep rules cleaned up (%s)", rules_dir)

    logger.info(
        "Pipeline complete | %d validated vulnerabilities | SARIF → %s | MD → %s",
        report.total_validated_vulns,
        report.sarif_path,
        report.markdown_path,
    )
    return report


def _write_clean_report(output_dir: Path, manifest: RepositoryManifest) -> None:
    """Write a minimal SARIF + markdown when no issues are found."""
    sarif = {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
            "Schemata/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "MoSec-SAST",
                        "version": "1.0.0",
                        "rules": [],
                    }
                },
                "results": [],
            }
        ],
    }
    (output_dir / "results.sarif").write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    (output_dir / "report.md").write_text(
        "# MoSec SAST Security Report\n\nNo exploitable vulnerabilities found.\n",
        encoding="utf-8",
    )
    logger.info("Clean report written.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="MoSec SAST Pipeline — LLM-centred security analysis",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--repo-path",
        required=True,
        help="Path to the repository to audit (local directory).",
    )
    parser.add_argument(
        "--clone-url",
        default=None,
        help="If set, clone this URL into --repo-path before analysing.",
    )
    parser.add_argument(
        "--output-dir",
        default="./output",
        help="Directory where all intermediate and final outputs are written.",
    )
    parser.add_argument(
        "--phase",
        type=int,
        default=0,
        choices=range(6),
        metavar="0-5",
        help=(
            "Start (or resume) the pipeline from this phase.  "
            "Previous phase outputs must already exist in --output-dir."
        ),
    )
    parser.add_argument(
        "--keep-rules",
        action="store_true",
        default=False,
        help="Do not delete the generated Semgrep rule files after the run.",
    )
    parser.add_argument(
        "--rules-dir",
        default="/tmp/audit_rules",
        help="Directory where generated Semgrep rule YAMLs are written.",
    )
    parser.add_argument(
        "--codeql-bin",
        default="codeql",
        help="Path to the CodeQL CLI binary.",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    output_dir = Path(args.output_dir).resolve()
    _configure_logging(output_dir)

    logger.info("MoSec SAST Pipeline starting")
    logger.info("  repo-path  : %s", args.repo_path)
    logger.info("  output-dir : %s", output_dir)
    logger.info("  start-phase: %d", args.phase)
    logger.info("  keep-rules : %s", args.keep_rules)

    report = run_pipeline(
        repo_path=args.repo_path,
        output_dir=output_dir,
        start_phase=args.phase,
        keep_rules=args.keep_rules,
        clone_url=args.clone_url,
        codeql_bin=args.codeql_bin,
        rules_dir=args.rules_dir,
    )

    if report is not None:
        sys.exit(0 if report.total_validated_vulns == 0 else 1)
    sys.exit(0)


if __name__ == "__main__":
    main()

"""
MoSec Benchmark Runner — Lot B

Measures pipeline quality (Precision / Recall / F1) against a ground-truth
suite of vulnerable and safe code snippets.

Usage:
    python -m benchmarks.runner [--suite benchmarks/cases] [--phase 4] [--output bench_report.json]

Each case consists of:
    <name>.py (or .js)            — the source code to analyse
    <name>.expected.json          — ground-truth: {label, should_validate, cwe, ...}

Metrics emitted:
    - Precision   = TP / (TP + FP)
    - Recall      = TP / (TP + FN)
    - F1          = 2 * P * R / (P + R)
    - Per-CWE breakdown
    - Per-difficulty breakdown (if "difficulty" field present)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class BenchmarkCase:
    name: str
    code_path: Path
    expected_path: Path
    label: str             # TP | FP | TN
    should_validate: bool
    cwe: str
    description: str
    source_hint: str = ""
    sink_hint: str = ""
    difficulty: str = "normal"


@dataclass
class CaseResult:
    case: BenchmarkCase
    predicted: bool        # did the pipeline produce a validated vuln?
    elapsed_s: float
    error: Optional[str] = None

    @property
    def tp(self) -> bool:
        return self.case.should_validate and self.predicted

    @property
    def fp(self) -> bool:
        return (not self.case.should_validate) and self.predicted

    @property
    def tn(self) -> bool:
        return (not self.case.should_validate) and (not self.predicted)

    @property
    def fn(self) -> bool:
        return self.case.should_validate and (not self.predicted)

    @property
    def correct(self) -> bool:
        return self.predicted == self.case.should_validate


@dataclass
class BenchmarkReport:
    total: int = 0
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    accuracy: float = 0.0
    per_cwe: dict[str, dict[str, int]] = field(default_factory=dict)
    per_difficulty: dict[str, dict[str, int]] = field(default_factory=dict)
    results: list[dict] = field(default_factory=list)
    elapsed_s: float = 0.0


# ---------------------------------------------------------------------------
# Case loading
# ---------------------------------------------------------------------------


def load_cases(suite_dir: str) -> list[BenchmarkCase]:
    """Load all benchmark cases from *suite_dir*."""
    cases: list[BenchmarkCase] = []
    base = Path(suite_dir)

    for code_path in sorted(base.glob("*.py")) + sorted(base.glob("*.js")):
        expected_path = code_path.with_suffix("").with_suffix(
            code_path.suffix + ".expected.json"
        )
        if not expected_path.exists():
            logger.warning("No expected file for %s — skipping", code_path.name)
            continue

        with expected_path.open() as fh:
            exp = json.load(fh)

        cases.append(BenchmarkCase(
            name=code_path.stem,
            code_path=code_path,
            expected_path=expected_path,
            label=exp.get("label", "TP"),
            should_validate=exp.get("should_validate", True),
            cwe=exp.get("cwe", "CWE-UNKNOWN"),
            description=exp.get("description", ""),
            source_hint=exp.get("source_hint", ""),
            sink_hint=exp.get("sink_hint", ""),
            difficulty=exp.get("difficulty", "normal"),
        ))

    logger.info("Loaded %d benchmark cases from %s", len(cases), suite_dir)
    return cases


# ---------------------------------------------------------------------------
# Pipeline runner helpers
# ---------------------------------------------------------------------------


def _run_pipeline_on_case(case: BenchmarkCase, llm_client, output_base: Path) -> bool:
    """
    Run Phase 1–4 on a single benchmark case.
    Returns True if the pipeline produces at least one validated vulnerability.
    """
    import uuid
    from agents.ingestion import IngestionAgent
    from agents.triage import TriageAgent
    from agents.taint_spec import TaintSpecAgent
    from agents.dataflow import DataFlowAgent
    from agents.exploit import ExploitAgent

    run_id = uuid.uuid4().hex[:8]
    out_dir = output_base / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    rules_dir = out_dir / "rules"
    rules_dir.mkdir(exist_ok=True)

    # Create a minimal manifest pointing to the single test file
    from models.schemas import RepositoryManifest, FileFinding
    manifest = RepositoryManifest(
        repo_path=str(case.code_path.parent),
        files=[str(case.code_path)],
    )

    repo_path = str(case.code_path.parent)

    # Phase 1 — Triage
    triage = TriageAgent(llm=llm_client, output_dir=str(out_dir))
    findings = triage.run(manifest)

    if not findings:
        return False

    # Phase 2 — TaintSpec
    taint = TaintSpecAgent(llm=llm_client, output_dir=str(out_dir), rules_dir=str(rules_dir))
    specs = taint.run(findings)

    if not specs:
        return False

    # Phase 3 — DataFlow
    dataflow = DataFlowAgent(llm=llm_client, output_dir=str(out_dir))
    confirmed = dataflow.run(specs, repo_path)

    if not confirmed:
        return False

    # Phase 4 — Exploit
    exploit = ExploitAgent(llm=llm_client, output_dir=str(out_dir))
    validated = exploit.run(confirmed)

    return len(validated) > 0


# ---------------------------------------------------------------------------
# Main benchmark runner
# ---------------------------------------------------------------------------


class BenchmarkRunner:

    def __init__(self, llm_client, output_dir: str = "bench_output") -> None:
        self.llm = llm_client
        self.output_dir = Path(output_dir)

    def run(self, suite_dir: str) -> BenchmarkReport:
        cases = load_cases(suite_dir)
        if not cases:
            logger.error("No benchmark cases found in %s", suite_dir)
            return BenchmarkReport()

        report = BenchmarkReport()
        start = time.monotonic()

        with tempfile.TemporaryDirectory(prefix="mosec_bench_") as tmp:
            tmp_path = Path(tmp)
            for case in cases:
                logger.info("Running case: %s", case.name)
                t0 = time.monotonic()
                error: Optional[str] = None
                predicted = False
                try:
                    predicted = _run_pipeline_on_case(case, self.llm, tmp_path)
                except Exception as exc:
                    error = str(exc)
                    logger.error("Case %s error: %s", case.name, exc)

                elapsed = time.monotonic() - t0
                result = CaseResult(case=case, predicted=predicted, elapsed_s=elapsed, error=error)

                # Accumulate metrics
                report.total += 1
                if result.tp: report.tp += 1
                if result.fp: report.fp += 1
                if result.tn: report.tn += 1
                if result.fn: report.fn += 1

                # Per-CWE
                cwe = case.cwe
                if cwe not in report.per_cwe:
                    report.per_cwe[cwe] = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
                for metric in ("tp", "fp", "tn", "fn"):
                    if getattr(result, metric):
                        report.per_cwe[cwe][metric] += 1

                # Per-difficulty
                diff = case.difficulty
                if diff not in report.per_difficulty:
                    report.per_difficulty[diff] = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
                for metric in ("tp", "fp", "tn", "fn"):
                    if getattr(result, metric):
                        report.per_difficulty[diff][metric] += 1

                status = "✓" if result.correct else "✗"
                logger.info(
                    "%s  %s  predicted=%s  expected=%s  elapsed=%.1fs",
                    status, case.name, predicted, case.should_validate, elapsed,
                )
                report.results.append({
                    "case": case.name,
                    "label": case.label,
                    "cwe": case.cwe,
                    "difficulty": case.difficulty,
                    "expected": case.should_validate,
                    "predicted": predicted,
                    "correct": result.correct,
                    "tp": result.tp,
                    "fp": result.fp,
                    "tn": result.tn,
                    "fn": result.fn,
                    "elapsed_s": round(elapsed, 2),
                    "error": error,
                })

        report.elapsed_s = time.monotonic() - start

        # Compute aggregate metrics
        p_denom = report.tp + report.fp
        r_denom = report.tp + report.fn
        report.precision = report.tp / p_denom if p_denom else 0.0
        report.recall = report.tp / r_denom if r_denom else 0.0
        pr_sum = report.precision + report.recall
        report.f1 = 2 * report.precision * report.recall / pr_sum if pr_sum else 0.0
        report.accuracy = (report.tp + report.tn) / report.total if report.total else 0.0

        return report

    def write_report(self, report: BenchmarkReport, output_path: str) -> None:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "summary": {
                "total": report.total,
                "tp": report.tp,
                "fp": report.fp,
                "tn": report.tn,
                "fn": report.fn,
                "precision": round(report.precision, 4),
                "recall": round(report.recall, 4),
                "f1": round(report.f1, 4),
                "accuracy": round(report.accuracy, 4),
                "elapsed_s": round(report.elapsed_s, 1),
            },
            "per_cwe": report.per_cwe,
            "per_difficulty": report.per_difficulty,
            "cases": report.results,
        }
        out.write_text(json.dumps(data, indent=2), encoding="utf-8")
        logger.info("Benchmark report written → %s", output_path)

        # Human-readable summary to stdout
        print("\n" + "=" * 60)
        print("  MoSec Benchmark Results")
        print("=" * 60)
        print(f"  Total cases : {report.total}")
        print(f"  TP={report.tp}  FP={report.fp}  TN={report.tn}  FN={report.fn}")
        print(f"  Precision   : {report.precision:.1%}")
        print(f"  Recall      : {report.recall:.1%}")
        print(f"  F1          : {report.f1:.1%}")
        print(f"  Accuracy    : {report.accuracy:.1%}")
        print(f"  Elapsed     : {report.elapsed_s:.1f}s")
        print("=" * 60)
        if report.per_cwe:
            print("\n  Per-CWE breakdown:")
            for cwe, m in sorted(report.per_cwe.items()):
                tp, fp = m["tp"], m["fp"]
                fn = m["fn"]
                p_d = tp + fp
                r_d = tp + fn
                p = tp / p_d if p_d else 0.0
                r = tp / r_d if r_d else 0.0
                f = 2 * p * r / (p + r) if (p + r) else 0.0
                print(f"    {cwe:20s}  P={p:.0%}  R={r:.0%}  F1={f:.0%}  (TP={tp} FP={fp} FN={fn})")
        print()


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    parser = argparse.ArgumentParser(description="MoSec benchmark runner")
    parser.add_argument("--suite", default="benchmarks/cases", help="Path to benchmark cases directory")
    parser.add_argument("--output", default="output/bench_report.json", help="Output JSON path")
    args = parser.parse_args()

    # Build LLM client from environment (same as pipeline.py)
    from utils.llm import LLMClient
    base_url = os.environ.get("LLM_BASE_URL", "http://localhost:8080/v1")
    api_key = os.environ.get("LLM_API_KEY", "")
    model = os.environ.get("LLM_MODEL", "qwen2.5-coder")
    llm = LLMClient(base_url=base_url, api_key=api_key, model=model)

    runner = BenchmarkRunner(llm_client=llm, output_dir="output/bench_tmp")
    report = runner.run(args.suite)
    runner.write_report(report, args.output)

    # Exit 1 if F1 < 0.5 (CI gate)
    sys.exit(0 if report.f1 >= 0.5 else 1)


if __name__ == "__main__":
    main()

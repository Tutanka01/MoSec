"""
Wrappers for Semgrep and CodeQL CLI tools.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Semgrep
# ---------------------------------------------------------------------------


class SemgrepRunner:
    """Run Semgrep rules against a repository and return parsed JSON results."""

    def __init__(self, repo_path: str, timeout: int = 120) -> None:
        self.repo_path = repo_path
        self.timeout = timeout

    def run_rule_file(self, rule_path: str) -> list[dict]:
        """Run a single rule file; returns the list of Semgrep result dicts."""
        cmd = [
            "semgrep",
            "scan",
            "--config", rule_path,
            "--json",
            "--no-git-ignore",
            "--quiet",
            self.repo_path,
        ]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            # Semgrep exits 0 (no findings) or 1 (findings found); anything else
            # is an error.
            if result.returncode not in (0, 1):
                logger.error("Semgrep error (rc=%d): %s", result.returncode, result.stderr[:500])
                return []
            data = json.loads(result.stdout)
            return data.get("results", [])
        except subprocess.TimeoutExpired:
            logger.error("Semgrep timed out on rule %s", rule_path)
            return []
        except json.JSONDecodeError as exc:
            logger.error("Semgrep JSON parse error: %s", exc)
            return []
        except FileNotFoundError:
            logger.error("semgrep not found in PATH — skipping rule run")
            return []

    def grep_pattern(self, pattern: str, file_path: str) -> list[tuple[int, str]]:
        """
        Lightweight grep fallback: find *pattern* (Python regex) in *file_path*.
        Returns list of (line_number, line_text).
        """
        results: list[tuple[int, str]] = []
        try:
            content = Path(file_path).read_text(errors="replace")
            for i, line in enumerate(content.splitlines(), 1):
                if re.search(pattern, line):
                    results.append((i, line.rstrip()))
        except OSError as exc:
            logger.warning("grep_pattern read error for %s: %s", file_path, exc)
        return results

    def grep_pattern_repo(self, pattern: str) -> list[tuple[str, int, str]]:
        """
        Grep *pattern* across the whole repo.
        Returns list of (relative_file, line_number, line_text).
        """
        results: list[tuple[str, int, str]] = []
        try:
            proc = subprocess.run(
                ["grep", "-rn", "--include=*.py", "--include=*.js",
                 "--include=*.ts", pattern, self.repo_path],
                capture_output=True, text=True, timeout=30,
            )
            for line in proc.stdout.splitlines():
                # format: path:lineno:content
                parts = line.split(":", 2)
                if len(parts) == 3:
                    fpath, lineno, content = parts
                    try:
                        results.append((fpath, int(lineno), content))
                    except ValueError:
                        pass
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return results


def generate_semgrep_rule(
    finding_id: str,
    source: str,
    sink: str,
    cwe: str,
    description: str,
    language: str,
    sanitizers: list[str],
) -> str:
    """
    Build a Semgrep taint-mode rule YAML from the LLM-extracted source/sink.

    The source and sink strings are converted to Semgrep ellipsis patterns by
    replacing concrete argument lists with `(...)`.
    """

    def to_semgrep_pattern(func_ref: str) -> str:
        """'request.args.get("id")' → 'request.args.get(...)'"""
        p = re.sub(r"\([^)]*\)", "(...)", func_ref.strip())
        # Ensure it ends with (...)
        if not p.endswith("(...)"):
            p = p.rstrip("()") + "(...)"
        return p

    src_pattern = to_semgrep_pattern(source)
    sink_pattern = to_semgrep_pattern(sink)

    sanitizer_block = ""
    if sanitizers:
        san_lines = "\n".join(
            f"      - pattern: {to_semgrep_pattern(s)}" for s in sanitizers
        )
        sanitizer_block = f"    pattern-sanitizers:\n{san_lines}\n"

    # Semgrep language identifier normalisation
    lang_map = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".jsx": "javascript",
        ".tsx": "typescript",
    }
    sem_lang = lang_map.get(language, language)

    rule = f"""rules:
  - id: sast-{finding_id}
    mode: taint
    pattern-sources:
      - pattern: {src_pattern}
    pattern-sinks:
      - pattern: {sink_pattern}
{sanitizer_block}    message: >
      {cwe}: {description}
      Source: {source}
      Sink: {sink}
    languages: [{sem_lang}]
    severity: ERROR
    metadata:
      cwe: "{cwe}"
      source: "{source}"
      sink: "{sink}"
      finding_id: "{finding_id}"
"""
    return rule


# ---------------------------------------------------------------------------
# CodeQL
# ---------------------------------------------------------------------------


class CodeQLRunner:
    """Wrapper for the CodeQL CLI binary."""

    def __init__(self, codeql_bin: str = "codeql") -> None:
        self.codeql_bin = codeql_bin

    def _available(self) -> bool:
        try:
            subprocess.run(
                [self.codeql_bin, "version"],
                capture_output=True,
                timeout=10,
            )
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def create_database(
        self,
        repo_path: str,
        db_path: str,
        language: str,
    ) -> bool:
        """
        Create a CodeQL database.  Returns True on success.
        Silently degrades when CodeQL is not installed.
        """
        if not self._available():
            logger.warning("CodeQL binary not found — skipping database creation")
            return False

        cmd = [
            self.codeql_bin,
            "database", "create",
            db_path,
            f"--language={language}",
            f"--source-root={repo_path}",
            "--overwrite",
        ]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=600,
            )
            if result.returncode != 0:
                logger.error("CodeQL create failed: %s", result.stderr[:500])
                return False
            logger.info("CodeQL database created at %s", db_path)
            return True
        except subprocess.TimeoutExpired:
            logger.error("CodeQL database creation timed out")
            return False

    def run_inline_query(
        self,
        db_path: str,
        ql_source: str,
    ) -> list[list]:
        """
        Write *ql_source* to a temp file, run it, decode and return tuples.
        Returns [] on any failure.
        """
        if not self._available() or not Path(db_path).exists():
            return []

        with tempfile.NamedTemporaryFile(
            suffix=".ql", mode="w", delete=False, dir=tempfile.gettempdir()
        ) as fh:
            fh.write(ql_source)
            ql_path = fh.name

        bqrs_path = ql_path.replace(".ql", ".bqrs")

        try:
            run_cmd = [
                self.codeql_bin, "query", "run",
                "--database", db_path,
                "--output", bqrs_path,
                ql_path,
            ]
            result = subprocess.run(run_cmd, capture_output=True, text=True, timeout=120)
            if result.returncode != 0:
                logger.debug("CodeQL query failed: %s", result.stderr[:300])
                return []

            decode_cmd = [
                self.codeql_bin, "bqrs", "decode",
                "--format=json",
                bqrs_path,
            ]
            decode = subprocess.run(decode_cmd, capture_output=True, text=True, timeout=30)
            if decode.returncode != 0:
                return []

            data = json.loads(decode.stdout)
            return data.get("#select", {}).get("tuples", [])

        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as exc:
            logger.debug("CodeQL inline query error: %s", exc)
            return []
        finally:
            for p in (ql_path, bqrs_path):
                try:
                    Path(p).unlink(missing_ok=True)
                except OSError:
                    pass

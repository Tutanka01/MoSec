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


# Semgrep patterns per sink kind — $TAINT is the metavariable for taint tracking
_SINK_KIND_PATTERNS: dict[str, str] = {
    "call":                 "{base}(...)",
    "method_call":          "$X.{base}(...)",
    "property_assignment":  "$X.{base} = $TAINT",
    "subscript_assignment": "$X[...] = $TAINT",
    "template_interp":      "`...${{...}}...`",
    "identifier":           "{base}",
}

_LANG_MAP: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
}


def _semgrep_base_name(ref: str) -> str:
    """
    Extract the bare callable/property name from an LLM-produced reference.

    Uses depth-counting to handle nested parentheses correctly — the previous
    regex `r"\\([^)]*\\)"` was non-recursive and silently mangled expressions
    like `method(arg, func(inner))`.
    """
    ref = ref.strip()
    paren_depth = 0
    base_chars: list[str] = []
    for ch in ref:
        if ch == "(":
            if paren_depth == 0:
                break           # stop at first open paren — everything before is the base
            paren_depth += 1
            base_chars.append(ch)
        elif ch == ")":
            paren_depth -= 1
            base_chars.append(ch)
        else:
            base_chars.append(ch)
    base = "".join(base_chars).strip()
    return base if base else ref.split("(")[0].strip()


def _classify_ref(ref: str) -> str:
    """
    Infer the sink_kind from a raw LLM reference when no AST metadata is available.

    Heuristic rules (ordered by specificity):
      - subscript ([) without call (() → subscript_assignment
      - no parentheses + looks like an attribute → property_assignment for sinks
      - has parentheses → call / method_call
    """
    ref = ref.strip()
    has_paren = "(" in ref
    has_bracket = "[" in ref and not has_paren
    has_dot = "." in ref.split("(")[0]

    if has_bracket:
        return "subscript_assignment"
    if not has_paren:
        # bare name or dotted attribute — treat as property_assignment for sink patterns
        return "property_assignment"
    if has_dot:
        return "method_call"
    return "call"


def to_semgrep_pattern(ref: str, kind: str | None = None) -> str:
    """
    Convert a function/property reference to a valid Semgrep pattern.

    When *kind* is provided (from AST metadata) it is used directly.
    Otherwise the kind is inferred heuristically.
    """
    if kind is None:
        kind = _classify_ref(ref)

    base = _semgrep_base_name(ref)
    # For dotted names use only the last segment (e.g. 'cursor.execute' → 'execute')
    # but keep the qualifier for method_call to avoid over-matching
    if kind == "call":
        bare = base.split(".")[-1] if "." not in base else base
    else:
        bare = base.split(".")[-1]

    template = _SINK_KIND_PATTERNS.get(kind, "{base}(...)")
    return template.format(base=bare if kind != "method_call" else base)


def _validate_semgrep_rule(yaml_text: str, rule_id: str) -> bool:
    """
    Run `semgrep --validate` on a generated rule.
    Returns True when valid, logs a warning and returns False when invalid.
    This is a best-effort check — missing semgrep binary is treated as valid.
    """
    with tempfile.NamedTemporaryFile(
        suffix=".yaml", mode="w", delete=False, dir=tempfile.gettempdir()
    ) as fh:
        fh.write(yaml_text)
        tmp_path = fh.name

    try:
        result = subprocess.run(
            ["semgrep", "--validate", "--config", tmp_path],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode != 0:
            logger.warning(
                "Semgrep rule %s failed validation:\n%s",
                rule_id,
                (result.stderr or result.stdout)[:400],
            )
            return False
        return True
    except FileNotFoundError:
        return True   # semgrep not in PATH — skip validation, don't block the pipeline
    except subprocess.TimeoutExpired:
        return True   # validation timed out — optimistically pass
    finally:
        try:
            Path(tmp_path).unlink(missing_ok=True)
        except OSError:
            pass


def generate_semgrep_rule(
    finding_id: str,
    source: str,
    sink: str,
    cwe: str,
    description: str,
    language: str,
    sanitizers: list[str],
    sink_kind: str | None = None,
    source_kind: str | None = None,
    validate: bool = True,
) -> str:
    """
    Build a Semgrep taint-mode rule YAML from the LLM-extracted source/sink.

    *sink_kind* and *source_kind* are AST-derived kinds (Lot C).  When absent
    the kind is inferred heuristically (Lot A fix), avoiding the old broken
    regex that turned `user['id']` into the invalid `user['id'](...)`.

    The rule is validated with `semgrep --validate` before being returned.
    If validation fails, a simpler pattern-regex fallback rule is emitted.
    """
    src_pattern = to_semgrep_pattern(source, kind=source_kind or "call")
    sink_pattern = to_semgrep_pattern(sink, kind=sink_kind)

    sanitizer_block = ""
    if sanitizers:
        san_lines = "\n".join(
            f"      - pattern: {to_semgrep_pattern(s)}" for s in sanitizers
        )
        sanitizer_block = f"    pattern-sanitizers:\n{san_lines}\n"

    sem_lang = _LANG_MAP.get(language, language.lstrip("."))

    rule = (
        f"rules:\n"
        f"  - id: sast-{finding_id}\n"
        f"    mode: taint\n"
        f"    pattern-sources:\n"
        f"      - pattern: {src_pattern}\n"
        f"    pattern-sinks:\n"
        f"      - pattern: {sink_pattern}\n"
        f"{sanitizer_block}"
        f"    message: >\n"
        f"      {cwe}: {description}\n"
        f"      Source: {source}\n"
        f"      Sink: {sink}\n"
        f"    languages: [{sem_lang}]\n"
        f"    severity: ERROR\n"
        f"    metadata:\n"
        f'      cwe: "{cwe}"\n'
        f'      source: "{source}"\n'
        f'      sink: "{sink}"\n'
        f'      finding_id: "{finding_id}"\n'
    )

    if validate and not _validate_semgrep_rule(rule, finding_id):
        # Fallback: emit a simpler grep-style rule that is always valid
        source_bare = _semgrep_base_name(source).split(".")[-1]
        sink_bare = _semgrep_base_name(sink).split(".")[-1]
        rule = (
            f"rules:\n"
            f"  - id: sast-{finding_id}-fallback\n"
            f"    pattern-either:\n"
            f"      - pattern-regex: '{re.escape(source_bare)}'\n"
            f"      - pattern-regex: '{re.escape(sink_bare)}'\n"
            f"    message: >\n"
            f"      {cwe} (fallback pattern): {description}\n"
            f"    languages: [{sem_lang}]\n"
            f"    severity: WARNING\n"
            f"    metadata:\n"
            f'      cwe: "{cwe}"\n'
            f'      finding_id: "{finding_id}"\n'
            f"      fallback: true\n"
        )

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

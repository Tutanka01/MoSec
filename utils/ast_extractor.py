"""
AST-based taint candidate extraction and intra-procedural CFG/def-use analysis.

Strategy:
  - Python files  : stdlib `ast` (always available, Pythonic, accurate)
  - JS / TS files : tree-sitter-javascript (optional; regex fallback otherwise)

Provides:
  TaintCandidateExtractor.extract()   → list[ASTCandidate]
  TaintCandidateExtractor.get_cfg()   → SimpleCFG
  SimpleCFG.taint_bfs()               → (reachable: bool, path: list[str])
"""

from __future__ import annotations

import ast
import logging
import re
from pathlib import Path
from typing import Optional

from models.schemas import ASTCandidate

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional tree-sitter import
# ---------------------------------------------------------------------------

_TS_AVAILABLE = False
_js_parser = None

try:
    import tree_sitter_javascript as _tsjs
    from tree_sitter import Language as _TSLanguage, Parser as _TSParser

    _JS_LANGUAGE = _TSLanguage(_tsjs.language())
    _js_parser = _TSParser(_JS_LANGUAGE)
    _TS_AVAILABLE = True
except Exception as _ts_err:
    logger.debug("tree-sitter-javascript not available (%s) — JS will use regex fallback", _ts_err)


# ---------------------------------------------------------------------------
# Known taint sources and sinks
# ---------------------------------------------------------------------------

_PYTHON_SOURCES: dict[str, set[str]] = {
    "flask":   {
        "request.args.get", "request.form.get", "request.json",
        "request.cookies.get", "request.data", "request.values.get",
        "request.files.get", "request.args", "request.form", "request.values",
        "request.get_json",
    },
    "django":  {
        "request.GET.get", "request.POST.get", "request.body",
        "request.META.get", "request.GET", "request.POST",
    },
    "stdlib":  {"input", "sys.argv", "os.environ.get", "os.environ"},
    "fastapi": {"Query", "Body", "Form", "Cookie", "Header", "Path"},
}

# Source bare names (leaf identifier) for quick matching
_PYTHON_SOURCE_BARE: set[str] = {
    s.split(".")[-1]
    for group in _PYTHON_SOURCES.values()
    for s in group
}

_PYTHON_SINKS_BY_CWE: dict[str, list[tuple[str, str]]] = {
    "CWE-79":  [
        ("innerHTML", "property_assignment"),
        ("outerHTML", "property_assignment"),
        ("document.write", "call"),
        ("eval", "call"),
        ("write", "method_call"),
    ],
    "CWE-89":  [
        ("execute", "method_call"),
        ("executemany", "method_call"),
        ("raw", "method_call"),
        ("query", "method_call"),
        ("filter", "method_call"),
        ("extra", "method_call"),
        ("raw_query", "method_call"),
    ],
    "CWE-78":  [
        ("subprocess.Popen", "call"),
        ("subprocess.run", "call"),
        ("subprocess.call", "call"),
        ("os.system", "call"),
        ("os.popen", "call"),
        ("exec", "call"),
        ("eval", "call"),
    ],
    "CWE-22":  [
        ("open", "call"),
        ("pathlib.Path", "call"),
        ("send_file", "call"),
        ("send_from_directory", "call"),
        ("FileResponse", "call"),
    ],
    "CWE-502": [
        ("pickle.loads", "call"),
        ("yaml.load", "call"),
        ("marshal.loads", "call"),
        ("jsonpickle.decode", "call"),
    ],
    "CWE-94":  [
        ("eval", "call"),
        ("exec", "call"),
        ("compile", "call"),
        ("__import__", "call"),
    ],
}

_JS_SOURCES: set[str] = {
    "req.query", "req.body", "req.params",
    "document.location.search", "window.location.hash",
    "URLSearchParams", "localStorage.getItem", "sessionStorage.getItem",
    "document.cookie",
}

_JS_SOURCE_BARE: set[str] = {s.split(".")[-1] for s in _JS_SOURCES}

_JS_SINKS_BY_CWE: dict[str, list[tuple[str, str]]] = {
    "CWE-79":  [
        ("innerHTML", "property_assignment"),
        ("outerHTML", "property_assignment"),
        ("document.write", "call"),
        ("eval", "call"),
        ("dangerouslySetInnerHTML", "property_assignment"),
        ("insertAdjacentHTML", "method_call"),
    ],
    "CWE-89":  [
        ("query", "method_call"),
        ("execute", "method_call"),
        ("run", "method_call"),
    ],
    "CWE-78":  [
        ("exec", "call"),
        ("execSync", "call"),
        ("spawn", "call"),
        ("spawnSync", "call"),
    ],
}


# ---------------------------------------------------------------------------
# SimpleCFG — intra-procedural def-use graph
# ---------------------------------------------------------------------------


class SimpleCFG:
    """
    Lightweight intra-procedural data-flow graph built from a function body.

    Nodes: variable names (strings).
    Edges: `_def_use[target] = {src1, src2, ...}` means target was derived from srcs.
    Sink index: `_sink_args[sink_bare_name] = {arg_var1, arg_var2, ...}`.
    """

    def __init__(self) -> None:
        self._def_use: dict[str, set[str]] = {}
        self._sink_args: dict[str, set[str]] = {}
        self._prop_assigns: dict[str, set[str]] = {}  # prop → {rhs_var, ...}

    def add_assignment(self, target: str, sources: set[str]) -> None:
        if not target or not sources:
            return
        self._def_use.setdefault(target, set()).update(sources)

    def add_sink_use(self, sink_name: str, args: set[str]) -> None:
        if not sink_name:
            return
        self._sink_args.setdefault(sink_name, set()).update(args)

    def add_property_assign(self, prop_name: str, rhs_vars: set[str]) -> None:
        self._prop_assigns.setdefault(prop_name, set()).update(rhs_vars)

    def taint_bfs(
        self,
        source_vars: set[str],
        sink_name: str,
        barriers: set[str],
    ) -> tuple[bool, list[str]]:
        """
        BFS over the def-use graph from *source_vars* to *sink_name*.
        Returns (reachable, path_description).
        *barriers* are variable/function names that break the taint chain.
        """
        # Direct check: any source var is directly consumed by the sink
        sink_consumers = (
            self._sink_args.get(sink_name, set()) |
            self._prop_assigns.get(sink_name, set())
        )
        direct_hit = source_vars & sink_consumers
        if direct_hit:
            return True, [f"{list(direct_hit)[0]} → {sink_name}"]

        # BFS
        frontier: set[str] = set(source_vars) - barriers
        visited: set[str] = set(source_vars)
        path: list[str] = []

        while frontier:
            next_frontier: set[str] = set()
            for var in frontier:
                # Forward propagation: var is used to define other vars
                for target, deps in self._def_use.items():
                    if var in deps and target not in visited and target not in barriers:
                        next_frontier.add(target)
                        visited.add(target)
                        path.append(f"{var} → {target}")
                        # Check if this derived var reaches the sink
                        all_sink_args = sink_consumers | self._sink_args.get(sink_name, set())
                        if target in all_sink_args or target == sink_name:
                            return True, path
            frontier = next_frontier - barriers

        return False, []


# ---------------------------------------------------------------------------
# TaintCandidateExtractor
# ---------------------------------------------------------------------------


class TaintCandidateExtractor:
    """
    Extracts taint source/sink candidates and builds an intra-procedural CFG.

    Python: uses stdlib `ast` for accurate parsing.
    JS/TS:  uses tree-sitter when available, regex fallback otherwise.
    Other:  regex fallback.
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract(
        self,
        file_path: str,
        center_line: int,
        cwe: str,
        radius: int = 80,
    ) -> list[ASTCandidate]:
        """Return source/sink candidates near *center_line* in *file_path*."""
        path = Path(file_path)
        suffix = path.suffix.lower()
        try:
            code = path.read_text(errors="replace")
        except OSError:
            return []

        if suffix == ".py":
            return self._extract_python(code, center_line, cwe, radius)
        elif suffix in (".js", ".jsx", ".ts", ".tsx"):
            return self._extract_js(code, center_line, cwe, radius)
        else:
            return self._extract_regex_fallback(code, center_line, cwe, radius)

    def get_cfg(self, file_path: str, center_line: int) -> SimpleCFG:
        """Build and return a SimpleCFG for the function containing *center_line*."""
        path = Path(file_path)
        suffix = path.suffix.lower()
        try:
            code = path.read_text(errors="replace")
        except OSError:
            return SimpleCFG()

        if suffix == ".py":
            return self._build_python_cfg(code, center_line)
        else:
            return self._build_generic_cfg(code, center_line)

    # ------------------------------------------------------------------
    # Python extraction (stdlib ast — always available)
    # ------------------------------------------------------------------

    def _extract_python(
        self, code: str, center_line: int, cwe: str, radius: int
    ) -> list[ASTCandidate]:
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return []

        line_min = max(1, center_line - radius)
        line_max = center_line + radius
        sinks_for_cwe = self._sinks_for_cwe_python(cwe)
        candidates: list[ASTCandidate] = []

        for node in ast.walk(tree):
            lineno = getattr(node, "lineno", 0)
            if not (line_min <= lineno <= line_max):
                continue
            col = getattr(node, "col_offset", 0)

            # Source detection: calls to known source functions
            if isinstance(node, ast.Call):
                call_str = _call_to_str(node)
                bare = call_str.split(".")[-1].split("(")[0]
                if bare in _PYTHON_SOURCE_BARE or call_str in {
                    s for group in _PYTHON_SOURCES.values() for s in group
                }:
                    returns_var = _find_assignment_target(tree, lineno)
                    candidates.append(ASTCandidate(
                        kind="source",
                        name=call_str,
                        line=lineno,
                        col=col,
                        sink_kind="call",
                        returns_var=returns_var,
                    ))

            # Sink detection: function/method calls
            if isinstance(node, ast.Call):
                call_str = _call_to_str(node)
                for sink_name, sink_kind in sinks_for_cwe:
                    bare_sink = sink_name.split(".")[-1]
                    if bare_sink and bare_sink in call_str:
                        candidates.append(ASTCandidate(
                            kind="sink",
                            name=call_str,
                            line=lineno,
                            col=col,
                            sink_kind=sink_kind,
                            args=[_expr_to_str(a) for a in node.args],
                        ))
                        break

            # Sink detection: property assignments (e.g., elem.innerHTML = x)
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Attribute):
                        attr = target.attr
                        for sink_name, _ in sinks_for_cwe:
                            if attr == sink_name.split(".")[-1]:
                                candidates.append(ASTCandidate(
                                    kind="sink",
                                    name=f"{_expr_to_str(target.value)}.{attr}",
                                    line=lineno,
                                    col=col,
                                    sink_kind="property_assignment",
                                    assigned_from=_expr_to_str(node.value),
                                ))
                                break

        return candidates

    def _build_python_cfg(self, code: str, center_line: int) -> SimpleCFG:
        """Build an intra-procedural def-use CFG for the function containing center_line."""
        cfg = SimpleCFG()
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return cfg

        # Find the tightest enclosing function
        scope = _find_containing_function(tree, center_line) or tree

        for node in ast.walk(scope):
            # Variable assignments: target = expr
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                value = node.value
                if value is None:
                    continue
                src_vars = _collect_names(value)
                for target in targets:
                    for t_name in _collect_names(target):
                        cfg.add_assignment(t_name, src_vars)

            # Augmented assignment: target += expr
            if isinstance(node, ast.AugAssign):
                src_vars = _collect_names(node.value) | _collect_names(node.target)
                for t_name in _collect_names(node.target):
                    cfg.add_assignment(t_name, src_vars)

            # Function call arguments → sink use
            if isinstance(node, ast.Call):
                call_str = _call_to_str(node)
                bare_func = call_str.split("(")[0].split(".")[-1]
                args_vars: set[str] = set()
                for arg in node.args:
                    args_vars.update(_collect_names(arg))
                for kw in node.keywords:
                    if kw.value:
                        args_vars.update(_collect_names(kw.value))
                cfg.add_sink_use(bare_func, args_vars)
                cfg.add_sink_use(call_str.split("(")[0], args_vars)  # full dotted name

            # Property assignment: obj.attr = value
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Attribute):
                        rhs_vars = _collect_names(node.value)
                        cfg.add_property_assign(target.attr, rhs_vars)

        return cfg

    # ------------------------------------------------------------------
    # JavaScript extraction (tree-sitter when available)
    # ------------------------------------------------------------------

    def _extract_js(
        self, code: str, center_line: int, cwe: str, radius: int
    ) -> list[ASTCandidate]:
        if not _TS_AVAILABLE or _js_parser is None:
            return self._extract_regex_fallback(code, center_line, cwe, radius)

        sinks_for_cwe = _JS_SINKS_BY_CWE.get(cwe, [])
        try:
            tree = _js_parser.parse(code.encode())
        except Exception as exc:
            logger.debug("tree-sitter parse error: %s", exc)
            return self._extract_regex_fallback(code, center_line, cwe, radius)

        line_min = max(0, center_line - radius)
        line_max = center_line + radius
        candidates: list[ASTCandidate] = []

        def visit(node) -> None:
            row = node.start_point[0] + 1   # 1-indexed
            if row < line_min or row > line_max:
                for child in node.children:
                    visit(child)
                return

            # Source: call expressions matching known JS sources
            if node.type == "call_expression":
                func_node = node.child_by_field_name("function")
                if func_node and func_node.text:
                    fname = func_node.text.decode(errors="replace")
                    if any(src in fname for src in _JS_SOURCES) or \
                            fname.split(".")[-1] in _JS_SOURCE_BARE:
                        candidates.append(ASTCandidate(
                            kind="source",
                            name=fname,
                            line=row,
                            col=node.start_point[1],
                            sink_kind="call",
                        ))

            # Sink: assignment to dangerous property (elem.innerHTML = x)
            if node.type == "assignment_expression":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left and right and left.text:
                    left_text = left.text.decode(errors="replace")
                    for sink_name, _ in sinks_for_cwe:
                        if sink_name.split(".")[-1] in left_text:
                            candidates.append(ASTCandidate(
                                kind="sink",
                                name=left_text,
                                line=row,
                                col=node.start_point[1],
                                sink_kind="property_assignment",
                                assigned_from=right.text.decode(errors="replace") if right.text else "",
                            ))
                            break

            # Sink: call expressions to dangerous functions
            if node.type == "call_expression":
                func_node = node.child_by_field_name("function")
                if func_node and func_node.text:
                    fname = func_node.text.decode(errors="replace")
                    for sink_name, sink_kind in sinks_for_cwe:
                        if sink_name.split(".")[-1] in fname:
                            candidates.append(ASTCandidate(
                                kind="sink",
                                name=fname,
                                line=row,
                                col=node.start_point[1],
                                sink_kind=sink_kind,
                            ))
                            break

            for child in node.children:
                visit(child)

        visit(tree.root_node)
        return candidates

    # ------------------------------------------------------------------
    # Generic CFG builder (Python regex — for JS and other languages)
    # ------------------------------------------------------------------

    def _build_generic_cfg(self, code: str, center_line: int) -> SimpleCFG:
        """
        Regex-based def-use extraction.  Weaker than AST but always available.
        Scoped to a heuristic function boundary around *center_line*.
        """
        cfg = SimpleCFG()
        lines = code.splitlines()
        func_start, func_end = _find_function_body_heuristic(lines, center_line - 1)
        scope_lines = lines[func_start:func_end]

        # Patterns for variable assignment
        assign_re = re.compile(
            r"^\s*(?:const|let|var)?\s+(\w+)\s*=\s*(.+)$"
        )
        call_re = re.compile(r"([\w.]+)\s*\(([^)]*)\)")

        for line in scope_lines:
            m = assign_re.match(line)
            if m:
                target = m.group(1)
                expr = m.group(2) or ""
                src_vars = set(re.findall(r"\b(\w+)\b", expr)) - {target}
                cfg.add_assignment(target, src_vars)

            for call_m in call_re.finditer(line):
                func_full = call_m.group(1)
                func_bare = func_full.split(".")[-1]
                args_vars = set(re.findall(r"\b(\w+)\b", call_m.group(2) or ""))
                cfg.add_sink_use(func_bare, args_vars)
                if "." in func_full:
                    cfg.add_sink_use(func_full, args_vars)

            # Property assignment: obj.prop = value
            prop_assign_re = re.compile(r"(\w+)\.([\w]+)\s*=\s*(.+)")
            for pm in prop_assign_re.finditer(line):
                prop = pm.group(2)
                rhs_vars = set(re.findall(r"\b(\w+)\b", pm.group(3) or ""))
                cfg.add_property_assign(prop, rhs_vars)

        return cfg

    # ------------------------------------------------------------------
    # Regex fallback extraction
    # ------------------------------------------------------------------

    def _extract_regex_fallback(
        self, code: str, center_line: int, cwe: str, radius: int
    ) -> list[ASTCandidate]:
        """Regex scan when AST/tree-sitter parsing is unavailable."""
        lines = code.splitlines()
        candidates: list[ASTCandidate] = []
        sinks_py = _PYTHON_SINKS_BY_CWE.get(cwe, [])
        sinks_js = _JS_SINKS_BY_CWE.get(cwe, [])
        all_sinks = sinks_py + sinks_js

        for i, line in enumerate(lines):
            lineno = i + 1
            if abs(lineno - center_line) > radius:
                continue

            # Sources
            for bare in _PYTHON_SOURCE_BARE | _JS_SOURCE_BARE:
                if re.search(r"\b" + re.escape(bare) + r"\b", line):
                    candidates.append(ASTCandidate(
                        kind="source", name=bare, line=lineno, col=0, sink_kind="call"
                    ))

            # Sinks
            for sink_name, sink_kind in all_sinks:
                bare = sink_name.split(".")[-1]
                if re.search(r"\b" + re.escape(bare) + r"\b", line):
                    candidates.append(ASTCandidate(
                        kind="sink", name=sink_name, line=lineno, col=0, sink_kind=sink_kind
                    ))

        return candidates

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _sinks_for_cwe_python(cwe: str) -> list[tuple[str, str]]:
        sinks = _PYTHON_SINKS_BY_CWE.get(cwe, [])
        if not sinks:
            # Generic — all known sinks
            sinks = [item for lst in _PYTHON_SINKS_BY_CWE.values() for item in lst]
        return sinks


# ---------------------------------------------------------------------------
# stdlib ast helpers (module-level for reuse)
# ---------------------------------------------------------------------------


def _call_to_str(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Attribute):
        return f"{_expr_to_str(func.value)}.{func.attr}"
    if isinstance(func, ast.Name):
        return func.id
    return ""


def _expr_to_str(node: ast.expr | None) -> str:
    if node is None:
        return ""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_expr_to_str(node.value)}.{node.attr}"
    if isinstance(node, ast.Constant):
        return repr(node.value)
    if isinstance(node, ast.Subscript):
        return f"{_expr_to_str(node.value)}[...]"
    if isinstance(node, ast.Call):
        return _call_to_str(node)
    return "?"


def _find_assignment_target(tree: ast.AST, lineno: int) -> Optional[str]:
    """Return the variable name that receives the value at *lineno*, or None."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and node.lineno == lineno:
            if node.targets and isinstance(node.targets[0], ast.Name):
                return node.targets[0].id
    return None


def _collect_names(node: ast.AST) -> set[str]:
    """Collect all Name identifiers used in *node* (deep walk)."""
    return {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}


def _find_containing_function(
    tree: ast.AST, line: int
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """Return the innermost function definition containing *line*."""
    best: ast.FunctionDef | ast.AsyncFunctionDef | None = None
    best_start = -1
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = node.lineno
            end = getattr(node, "end_lineno", start + 500)
            if start <= line <= end and start > best_start:
                best = node
                best_start = start
    return best


def _find_function_body_heuristic(lines: list[str], center_idx: int) -> tuple[int, int]:
    """
    Heuristically determine the start and end (exclusive) of the function body
    that contains *center_idx* (0-based line index).
    """
    func_start = max(0, center_idx - 80)
    func_end = min(len(lines), center_idx + 80)

    # Scan backwards for a function definition
    for i in range(center_idx, max(0, center_idx - 120), -1):
        stripped = lines[i].lstrip()
        if stripped.startswith(("def ", "async def ", "function ", "const ", "class ")):
            func_start = i
            def_indent = len(lines[i]) - len(stripped)
            # Scan forwards to end of this function
            for j in range(i + 1, min(len(lines), i + 300)):
                s2 = lines[j].lstrip()
                cur_indent = len(lines[j]) - len(s2)
                if s2.startswith(("def ", "async def ", "function ", "class ")) and \
                        cur_indent <= def_indent:
                    func_end = j
                    break
            break

    return func_start, func_end

"""
Phase 0 — Ingestion Agent

Responsibilities:
- Clone or accept a local repository path
- Parse ASTs with tree-sitter for all .py / .js / .ts files
- Build a CodeQL database
- Detect entry points (HTTP routes, file reads, subprocess calls, eval, deserialization)
- Extract dependency graphs (requirements.txt, pyproject.toml, package.json)
- Emit manifest.json
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from pathlib import Path
from typing import Optional

from models.schemas import ASTSummary, Dependency, EntryPoint, RepositoryManifest
from utils.sast import CodeQLRunner

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Entry-point regex patterns
# ---------------------------------------------------------------------------

_PY_PATTERNS: dict[str, list[str]] = {
    "http_route": [
        r"@\w+\.route\(",
        r"@\w+\.(get|post|put|delete|patch|head|options)\(",
        r"url_patterns\s*=",
        r"\bpath\s*\(",
        r"\bre_path\s*\(",
        r"@bp\.route\(",
    ],
    "file_read": [
        r"\bopen\s*\(",
        r"\.read_text\s*\(",
        r"\.read_bytes\s*\(",
        r"os\.path\.join\s*\(",
    ],
    "subprocess": [
        r"\bsubprocess\.",
        r"\bos\.system\s*\(",
        r"\bos\.popen\s*\(",
        r"\bPopen\s*\(",
    ],
    "eval": [
        r"\beval\s*\(",
        r"\bexec\s*\(",
        r"\bcompile\s*\(",
    ],
    "deserialization": [
        r"\bpickle\.loads?\s*\(",
        r"\byaml\.load\s*\(",
        r"\bjson\.loads\s*\(",
        r"\bmarshal\.loads\s*\(",
        r"\bshelve\.open\s*\(",
    ],
}

_JS_PATTERNS: dict[str, list[str]] = {
    "http_route": [
        r"\bapp\.(get|post|put|delete|patch|head|options)\s*\(",
        r"\brouter\.(get|post|put|delete|patch|head|options)\s*\(",
        r"express\.Router\s*\(",
        r"new Router\s*\(",
    ],
    "file_read": [
        r"\bfs\.readFile\b",
        r"\bfs\.readFileSync\b",
        r"\brequire\s*\(",
        r"\bimport\s*\(",
    ],
    "subprocess": [
        r"\bchild_process\b",
        r"\bexec\s*\(",
        r"\bspawn\s*\(",
        r"\bexecSync\s*\(",
        r"\bspawnSync\s*\(",
    ],
    "eval": [
        r"\beval\s*\(",
        r"\bnew Function\s*\(",
        r"\bsetTimeout\s*\(\s*['\"]",
    ],
    "deserialization": [
        r"\bJSON\.parse\s*\(",
        r"\bdeserialize\s*\(",
        r"\bunserialize\s*\(",
        r"\bserialization\b",
    ],
}

_PHP_PATTERNS: dict[str, list[str]] = {
    "http_route": [
        r"\$_GET\b",
        r"\$_POST\b",
        r"\$_REQUEST\b",
        r"->route\s*\(",
        r"Route::",
        r"->get\s*\(",
        r"->post\s*\(",
        r"\bRoute::get\b",
        r"\bRoute::post\b",
    ],
    "file_read": [
        r"\bfile_get_contents\s*\(",
        r"\bfopen\s*\(",
        r"\binclude\s*[('\"]",
        r"\brequire\s*[('\"]",
        r"\binclude_once\s*[('\"]",
        r"\brequire_once\s*[('\"]",
        r"\breadfile\s*\(",
    ],
    "subprocess": [
        r"\bexec\s*\(",
        r"\bsystem\s*\(",
        r"\bshell_exec\s*\(",
        r"\bpassthru\s*\(",
        r"\bpopen\s*\(",
        r"\bproc_open\s*\(",
        r"\bpcntl_exec\s*\(",
    ],
    "eval": [
        r"\beval\s*\(",
        r"\bassert\s*\(",
        r"\bcreate_function\s*\(",
        r"\bpreg_replace\s*\(.*[/\|]e[/\|]",
    ],
    "deserialization": [
        r"\bunserialize\s*\(",
    ],
}


class IngestionAgent:
    """Phase 0 — clone/read a repository and produce a RepositoryManifest."""

    def __init__(self, output_dir: str, codeql_bin: str = "codeql") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._codeql = CodeQLRunner(codeql_bin)

        # Lazy-import tree-sitter so that missing optional deps don't crash import
        self._py_parser = None
        self._js_parser = None
        self._init_parsers()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(
        self,
        repo_path: str,
        clone_url: Optional[str] = None,
    ) -> RepositoryManifest:
        if clone_url:
            repo_path = self._clone_repo(clone_url, repo_path)

        repo = Path(repo_path).resolve()
        logger.info("Ingesting repository: %s", repo)

        files = self._collect_files(repo)
        logger.info("Source files found: %d", len(files))

        ast_summaries = self._build_ast_summaries(files, repo)
        entry_points = self._extract_entry_points(files, repo)
        dependencies = self._extract_dependencies(repo)

        logger.info(
            "Entry points: %d  Dependencies: %d",
            len(entry_points),
            len(dependencies),
        )

        codeql_db_path = self._build_codeql_database(repo)

        manifest = RepositoryManifest(
            repo_path=str(repo),
            files=[str(f) for f in files],
            entry_points=entry_points,
            dependencies=dependencies,
            ast_summary=ast_summaries,
            codeql_db_path=codeql_db_path,
        )

        out = self.output_dir / "manifest.json"
        out.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")
        logger.info("Manifest written → %s", out)
        return manifest

    # ------------------------------------------------------------------
    # Tree-sitter initialisation
    # ------------------------------------------------------------------

    def _init_parsers(self) -> None:
        self._php_parser = None
        try:
            from tree_sitter import Language, Parser  # type: ignore
            import tree_sitter_python as tspython  # type: ignore
            import tree_sitter_javascript as tsjavascript  # type: ignore

            self._py_parser = Parser(Language(tspython.language()))
            self._js_parser = Parser(Language(tsjavascript.language()))
            logger.debug("tree-sitter parsers initialised (py, js)")
        except Exception as exc:
            logger.warning(
                "tree-sitter (py/js) unavailable (%s) — AST summaries will be empty", exc
            )

        try:
            from tree_sitter import Language, Parser  # type: ignore
            import tree_sitter_php as tsphp  # type: ignore

            self._php_parser = Parser(Language(tsphp.language_php()))
            logger.debug("tree-sitter PHP parser initialised")
        except Exception as exc:
            logger.warning("tree-sitter-php unavailable (%s) — PHP AST summaries skipped", exc)

    # ------------------------------------------------------------------
    # File collection
    # ------------------------------------------------------------------

    def _collect_files(self, repo: Path) -> list[Path]:
        _EXT = {".py", ".js", ".ts", ".jsx", ".tsx", ".php"}
        _SKIP = {
            "node_modules", ".git", "__pycache__", ".venv", "venv",
            "dist", "build", ".tox", ".eggs", "site-packages",
            "vendor",  # PHP Composer vendor dir
        }
        files: list[Path] = []
        for p in repo.rglob("*"):
            if not p.is_file():
                continue
            if p.suffix not in _EXT:
                continue
            if any(skip in p.parts for skip in _SKIP):
                continue
            files.append(p)
        return sorted(files)

    # ------------------------------------------------------------------
    # AST summaries
    # ------------------------------------------------------------------

    def _build_ast_summaries(
        self, files: list[Path], repo: Path
    ) -> list[ASTSummary]:
        summaries: list[ASTSummary] = []
        for f in files:
            try:
                summary = self._analyse_file_ast(f, repo)
                if summary:
                    summaries.append(summary)
            except Exception as exc:
                logger.debug("AST analysis skipped for %s: %s", f, exc)
        return summaries

    def _analyse_file_ast(self, path: Path, repo: Path) -> Optional[ASTSummary]:
        if self._py_parser is None and self._js_parser is None and self._php_parser is None:
            return None

        rel = str(path.relative_to(repo))
        code = path.read_bytes()

        if path.suffix == ".py" and self._py_parser:
            tree = self._py_parser.parse(code)
            return self._summarise_tree(tree, rel, is_python=True)
        elif path.suffix in {".js", ".ts", ".jsx", ".tsx"} and self._js_parser:
            tree = self._js_parser.parse(code)
            return self._summarise_tree(tree, rel, is_python=False)
        elif path.suffix == ".php" and self._php_parser:
            tree = self._php_parser.parse(code)
            return self._summarise_php_tree(tree, rel)
        return None

    @staticmethod
    def _summarise_tree(tree, rel: str, is_python: bool) -> ASTSummary:
        functions: list[str] = []
        classes: list[str] = []
        imports: list[str] = []

        if is_python:
            fn_types = {"function_definition", "async_function_definition"}
            cls_types = {"class_definition"}
            imp_types = {"import_statement", "import_from_statement"}
        else:
            fn_types = {"function_declaration", "method_definition", "arrow_function"}
            cls_types = {"class_declaration", "class_expression"}
            imp_types = {"import_statement", "import_declaration"}

        def walk(node) -> None:
            if node.type in fn_types:
                name = node.child_by_field_name("name")
                if name:
                    functions.append(name.text.decode(errors="replace"))
            elif node.type in cls_types:
                name = node.child_by_field_name("name")
                if name:
                    classes.append(name.text.decode(errors="replace"))
            elif node.type in imp_types:
                imports.append(node.text.decode(errors="replace")[:120])
            for child in node.children:
                walk(child)

        walk(tree.root_node)
        return ASTSummary(file=rel, functions=functions, classes=classes, imports=imports)

    @staticmethod
    def _summarise_php_tree(tree, rel: str) -> ASTSummary:
        """Extract functions, classes, and use-statements from a PHP tree-sitter tree."""
        functions: list[str] = []
        classes: list[str] = []
        imports: list[str] = []

        def walk(node) -> None:
            if node.type in ("function_definition", "method_declaration"):
                name_node = node.child_by_field_name("name")
                if name_node and name_node.text:
                    functions.append(name_node.text.decode(errors="replace"))
            elif node.type == "class_declaration":
                name_node = node.child_by_field_name("name")
                if name_node and name_node.text:
                    classes.append(name_node.text.decode(errors="replace"))
            elif node.type == "namespace_use_declaration":
                imports.append(node.text.decode(errors="replace")[:120])
            for child in node.children:
                walk(child)

        walk(tree.root_node)
        return ASTSummary(file=rel, functions=functions, classes=classes, imports=imports)

    # ------------------------------------------------------------------
    # Entry point extraction (regex-based, per-line)
    # ------------------------------------------------------------------

    def _extract_entry_points(
        self, files: list[Path], repo: Path
    ) -> list[EntryPoint]:
        entry_points: list[EntryPoint] = []
        for f in files:
            if f.suffix == ".py":
                patterns = _PY_PATTERNS
            elif f.suffix == ".php":
                patterns = _PHP_PATTERNS
            else:
                patterns = _JS_PATTERNS
            rel = str(f.relative_to(repo))
            try:
                lines = f.read_text(errors="replace").splitlines()
            except OSError as exc:
                logger.debug("Cannot read %s: %s", f, exc)
                continue
            for ep_type, pats in patterns.items():
                for pattern in pats:
                    compiled = re.compile(pattern)
                    for i, line in enumerate(lines, 1):
                        if compiled.search(line):
                            entry_points.append(
                                EntryPoint(
                                    file=rel,
                                    line=i,
                                    type=ep_type,
                                    name=line.strip()[:100],
                                )
                            )
        return entry_points

    # ------------------------------------------------------------------
    # Dependency extraction
    # ------------------------------------------------------------------

    def _extract_dependencies(self, repo: Path) -> list[Dependency]:
        deps: list[Dependency] = []
        for fname in [
            "requirements.txt",
            "requirements-dev.txt",
            "requirements-prod.txt",
            "requirements-test.txt",
        ]:
            p = repo / fname
            if p.exists():
                deps.extend(self._parse_requirements_txt(p))

        if (repo / "pyproject.toml").exists():
            deps.extend(self._parse_pyproject_toml(repo / "pyproject.toml"))

        if (repo / "package.json").exists():
            deps.extend(self._parse_package_json(repo / "package.json"))

        return deps

    @staticmethod
    def _parse_requirements_txt(path: Path) -> list[Dependency]:
        deps: list[Dependency] = []
        _LINE = re.compile(r"^([A-Za-z0-9_\-\.]+)\s*([>=<!~^,\s\d\.]+)?")
        for raw_line in path.read_text(errors="replace").splitlines():
            line = raw_line.strip()
            if not line or line.startswith(("#", "-", "git+", "http")):
                continue
            m = _LINE.match(line)
            if m:
                deps.append(
                    Dependency(
                        name=m.group(1),
                        version=(m.group(2) or "").strip() or None,
                        ecosystem="pip",
                    )
                )
        return deps

    @staticmethod
    def _parse_pyproject_toml(path: Path) -> list[Dependency]:
        deps: list[Dependency] = []
        _LINE = re.compile(r"^([A-Za-z0-9_\-\.]+)\s*([>=<!~^,\s\d\.]+)?")
        try:
            try:
                import tomllib  # Python 3.11+
            except ImportError:
                import tomli as tomllib  # type: ignore

            data = tomllib.loads(path.read_text(encoding="utf-8"))
            dep_list: list[str] = data.get("project", {}).get("dependencies", [])
            # Also check tool.poetry
            dep_list += list(
                data.get("tool", {}).get("poetry", {}).get("dependencies", {}).keys()
            )
            for dep in dep_list:
                m = _LINE.match(dep.strip())
                if m:
                    deps.append(
                        Dependency(
                            name=m.group(1),
                            version=(m.group(2) or "").strip() or None,
                            ecosystem="pip",
                        )
                    )
        except Exception as exc:
            logger.debug("pyproject.toml parse skipped: %s", exc)
        return deps

    @staticmethod
    def _parse_package_json(path: Path) -> list[Dependency]:
        deps: list[Dependency] = []
        try:
            data: dict = json.loads(path.read_text(encoding="utf-8"))
            for section in ("dependencies", "devDependencies", "peerDependencies"):
                for name, version in data.get(section, {}).items():
                    deps.append(Dependency(name=name, version=str(version), ecosystem="npm"))
        except Exception as exc:
            logger.debug("package.json parse skipped: %s", exc)
        return deps

    # ------------------------------------------------------------------
    # CodeQL database
    # ------------------------------------------------------------------

    def _build_codeql_database(self, repo: Path) -> Optional[str]:
        has_py = any(repo.rglob("*.py"))
        has_js = any(p for p in repo.rglob("*")
                     if p.suffix in {".js", ".ts", ".jsx", ".tsx"})
        has_php = any(repo.rglob("*.php"))

        if has_py:
            lang = "python"
        elif has_js:
            lang = "javascript"
        elif has_php:
            lang = "php"
        else:
            lang = None

        if lang is None:
            return None

        db_path = str(self.output_dir / "codeql_db")
        ok = self._codeql.create_database(str(repo), db_path, lang)
        return db_path if ok else None

    # ------------------------------------------------------------------
    # Git clone helper
    # ------------------------------------------------------------------

    @staticmethod
    def _clone_repo(clone_url: str, target_path: str) -> str:
        logger.info("Cloning %s → %s", clone_url, target_path)
        subprocess.run(
            ["git", "clone", "--depth=1", clone_url, target_path],
            check=True,
        )
        return target_path

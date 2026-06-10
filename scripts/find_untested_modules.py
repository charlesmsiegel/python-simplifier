#!/usr/bin/env python3
"""
Identify source modules that have no tests referencing them.

Provides deterministic support for establishing a test safety net by flagging
modules that define logic but are not imported by any test file.

Finds:
  - no_tests_in_repo  : project has source files but zero test files (HIGH)
  - untested_module   : a source module defining functions/classes that no
                        test file imports (MEDIUM)
"""

import ast
import sys
import json
import argparse
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Iterator, Set, List, Tuple, Optional
from collections import defaultdict


@dataclass
class CodeSmell:
    file: str
    line: int
    smell_type: str
    description: str
    suggestion: str
    severity: str
    code_snippet: str = ""


# ---------------------------------------------------------------------------
# Shared helpers (verbatim contract from find_global_state.py)
# ---------------------------------------------------------------------------

def find_python_files(path: Path) -> Iterator[Path]:
    if path.is_file() and path.suffix == ".py":
        yield path
    elif path.is_dir():
        for p in path.rglob("*.py"):
            if ".venv" not in p.parts and "node_modules" not in p.parts and "__pycache__" not in p.parts:
                yield p


def _get_line(lines: List[str], lineno: int) -> str:
    if 0 < lineno <= len(lines):
        return lines[lineno - 1].strip()[:80]
    return ""


# ---------------------------------------------------------------------------
# File classification helpers
# ---------------------------------------------------------------------------

_EXCLUDE_SEGMENTS: Set[str] = {".venv", "build", "dist", "docs", "migrations"}
_ENTRYPOINT_SEGMENTS: Set[str] = {"scripts", "bin"}


def _is_test_file(p: Path) -> bool:
    """Return True if the file is a test or test-infrastructure file."""
    name = p.name
    if name == "conftest.py":
        return True
    if name.startswith("test_") or name.endswith("_test.py"):
        return True
    # Any path segment named "tests" or "test"
    for part in p.parts[:-1]:  # exclude the filename itself (already checked)
        if part in ("tests", "test"):
            return True
    return False


def _is_excluded(p: Path, root: Optional[Path] = None) -> bool:
    """Return True if the file lives under an excluded directory segment.

    Checks are performed on the path relative to *root* so that files inside
    (e.g.) a root that happens to be named '.venv' are not incorrectly excluded.
    Falls back to absolute parts when root is not supplied.
    """
    if root is not None:
        try:
            parts = p.relative_to(root).parts[:-1]  # directory parts only
        except ValueError:
            parts = p.parts
    else:
        parts = p.parts
    for part in parts:
        if part in _EXCLUDE_SEGMENTS:
            return True
    return False


def _is_source_file(p: Path, root: Optional[Path] = None) -> bool:
    """Return True if the file should be treated as a source module."""
    name = p.name
    # Explicit exclusions
    if name in ("__init__.py", "setup.py", "conftest.py"):
        return False
    if _is_excluded(p, root):
        return False
    if _is_test_file(p):
        return False
    # Entrypoint scripts (in scripts/ or bin/) are excluded only when those
    # directories appear *below* the package root — i.e., they are not the
    # sole directory level between the analyzed root and the file.  This lets
    # a project whose entire code lives directly inside scripts/ (where scripts/
    # IS the library) still be analyzed, while still excluding helpers tucked
    # into a scripts/ subdirectory of a larger package tree.
    if root is not None:
        try:
            rel_parts = p.relative_to(root).parts[:-1]  # directory parts only
        except ValueError:
            rel_parts = ()
    else:
        rel_parts = p.parts
    # Only apply entrypoint exclusion when there is more than one directory
    # level in the relative path (e.g. "src/scripts/helper.py" is excluded,
    # but "scripts/tool.py" directly under root is kept as a source file).
    if len(rel_parts) > 1:
        for part in rel_parts:
            if part in _ENTRYPOINT_SEGMENTS:
                return False
    return True


# ---------------------------------------------------------------------------
# Module name helpers
# ---------------------------------------------------------------------------

def _module_names_for_file(p: Path, root: Path) -> Tuple[str, str]:
    """Return (dotted_name, bare_stem) for a source file relative to root."""
    try:
        rel = p.relative_to(root)
    except ValueError:
        return (p.stem, p.stem)
    parts = list(rel.parts)
    parts[-1] = parts[-1][:-3]  # strip .py
    dotted = ".".join(parts)
    stem = parts[-1]
    return (dotted, stem)


# ---------------------------------------------------------------------------
# Import name extraction
# ---------------------------------------------------------------------------

def _collect_imported_names(tree: ast.AST) -> Set[str]:
    """
    Collect all module/name base names referenced in import statements.
    Returns both dotted names and their leaf/base components.
    """
    names: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                dotted = alias.name
                names.add(dotted)
                names.add(dotted.split(".")[0])   # top-level package
                names.add(dotted.split(".")[-1])  # leaf name
        elif isinstance(node, ast.ImportFrom):
            module = node.module
            if module:
                names.add(module)
                names.add(module.split(".")[0])
                names.add(module.split(".")[-1])
            # Also add imported names themselves (e.g. `from pkg import MyClass`)
            for alias in node.names:
                if alias.name != "*":
                    names.add(alias.name)
            # Relative: `from .x import y` — base name is "x"
            if node.level and node.level > 0 and module:
                names.add(module.split(".")[-1])
    return names


def _has_definitions(tree: ast.AST) -> bool:
    """Return True if the module defines at least one function or class."""
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return True
    return False


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def analyze(root: Path, ignore: Set[str]) -> List[CodeSmell]:
    py_files = list(find_python_files(root))
    if not py_files:
        return []

    test_files: List[Path] = []
    source_files: List[Path] = []

    for p in py_files:
        if _is_test_file(p):
            test_files.append(p)
        elif _is_source_file(p, root):
            source_files.append(p)

    issues: List[CodeSmell] = []

    # no_tests_in_repo
    if source_files and not test_files:
        if "no_tests_in_repo" not in ignore:
            issues.append(CodeSmell(
                file=str(root),
                line=1,
                smell_type="no_tests_in_repo",
                description="Project has source modules but no test files were found",
                suggestion=(
                    "Establish a safety net before refactoring — add pytest and "
                    "characterization tests for the highest-churn modules first."
                ),
                severity="high",
            ))
        # Still report untested_module findings even when no tests exist,
        # so callers can see what needs coverage.

    # Collect all names referenced by test files
    referenced_by_tests: Set[str] = set()
    for tp in test_files:
        try:
            source = tp.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(tp))
            referenced_by_tests.update(_collect_imported_names(tree))
        except (SyntaxError, Exception):
            pass

    # Check each source file
    if "untested_module" not in ignore:
        for sp in sorted(source_files, key=str):
            try:
                source = sp.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(source, filename=str(sp))
            except (SyntaxError, Exception):
                continue

            if not _has_definitions(tree):
                continue

            dotted, stem = _module_names_for_file(sp, root)
            # Conservative: if ANY of the names appear in what tests import, skip
            if dotted in referenced_by_tests or stem in referenced_by_tests:
                continue

            lines = source.splitlines()
            issues.append(CodeSmell(
                file=str(sp),
                line=1,
                smell_type="untested_module",
                description=f"Module '{dotted}' defines functions/classes but is not imported by any test file",
                suggestion="Add at least a characterization test pinning current behavior before refactoring this module.",
                severity="medium",
                code_snippet=_get_line(lines, 1),
            ))

    return issues


def main():
    parser = argparse.ArgumentParser(
        description="Identify source modules with no test coverage references"
    )
    parser.add_argument("path", nargs="?", default=".", help="File or directory to analyze")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--ignore", type=str, default="", help="Comma-separated smell types to ignore")
    args = parser.parse_args()
    ignore = set(args.ignore.split(",")) if args.ignore else set()

    root = Path(args.path)
    if root.is_file():
        root = root.parent
    root = root.resolve()

    all_issues = analyze(root, ignore)
    all_issues.sort(key=lambda x: (x.severity != "high", x.severity != "medium", x.file, x.line))

    if args.format == "json":
        print(json.dumps([asdict(i) for i in all_issues], indent=2))
    else:
        if not all_issues:
            print("✅ No test-coverage issues found!")
            return
        by_type = defaultdict(int)
        for i in all_issues:
            by_type[i.smell_type] += 1
        print(f"Found {len(all_issues)} test-coverage issue(s):\n\nSummary:")
        for s, c in sorted(by_type.items(), key=lambda x: -x[1]):
            print(f"  {s}: {c}")
        print()
        icons = {"high": "🔴", "medium": "🟡", "low": "🟢"}
        for i in all_issues:
            print(f"{icons[i.severity]} [{i.severity.upper()}] {i.file}:{i.line}")
            print(f"   {i.smell_type}: {i.description}")
            if i.code_snippet:
                print(f"   Code: {i.code_snippet}")
            print(f"   → {i.suggestion}\n")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Detect test-quality smells in Python test files via AST analysis.

Only analyses files whose name starts with "test_", ends with "_test.py",
or whose path contains a "tests" or "test" directory segment.

Finds:
  - test_without_assertion : test function with no assertion of any kind
  - overmocking            : test function with more than 4 mock/patch constructs
  - skipped_without_reason : @skip / @pytest.mark.skip with no reason/message arg
  - logic_in_test          : test function body contains for/while/if control flow
"""

import ast
import sys
import json
import argparse
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Iterator
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


def find_python_files(path: Path) -> Iterator[Path]:
    if path.is_file() and path.suffix == ".py":
        yield path
    elif path.is_dir():
        for p in path.rglob("*.py"):
            if ".venv" not in p.parts and "node_modules" not in p.parts and "__pycache__" not in p.parts:
                yield p


def _is_test_file(filepath: Path) -> bool:
    """Return True if this file should be analysed as a test file."""
    name = filepath.name
    if name.startswith("test_") or name.endswith("_test.py"):
        return True
    parts = filepath.parts
    return "tests" in parts or "test" in parts


def _get_line(lines: list[str], lineno: int) -> str:
    if 0 < lineno <= len(lines):
        return lines[lineno - 1].strip()[:80]
    return ""


# ---------------------------------------------------------------------------
# Assertion detection helpers
# ---------------------------------------------------------------------------

def _is_assert_call(node: ast.expr) -> bool:
    """Return True if node is a call to an assert-style method/function."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    # self.assertXxx(...) / self.assert_xxx(...)
    if isinstance(func, ast.Attribute):
        attr = func.attr
        if attr.startswith("assert") or attr.startswith("Assert"):
            return True
        # mock assertions: .assert_called, .assert_called_once_with, etc.
        if attr.startswith("assert_"):
            return True
        # assert_has_calls, assert_any_call, assert_called_with …
        if attr in {"assert_called", "assert_called_once", "assert_called_with",
                    "assert_called_once_with", "assert_any_call", "assert_has_calls",
                    "assert_not_called"}:
            return True
        # np.testing.assert_* or similar: obj.assert_array_equal etc.
        if attr.startswith("assert"):
            return True
    # pytest.raises / pytest.warns used as plain call (not `with`)
    if isinstance(func, ast.Attribute):
        if isinstance(func.value, ast.Name) and func.value.id == "pytest":
            if func.attr in ("raises", "warns", "approx"):
                return True
    if isinstance(func, ast.Name):
        name = func.id
        # bare assert_* helper functions
        if name.startswith("assert_") or name.startswith("Assert"):
            return True
    return False


def _is_pytest_raises_with(node: ast.stmt) -> bool:
    """Return True if `node` is `with pytest.raises(...):` or `with pytest.warns(...)`."""
    if not isinstance(node, ast.With):
        return False
    for item in node.items:
        ctx = item.context_expr
        if isinstance(ctx, ast.Call):
            func = ctx.func
            if isinstance(func, ast.Attribute):
                if isinstance(func.value, ast.Name) and func.value.id == "pytest":
                    if func.attr in ("raises", "warns"):
                        return True
    return False


def _has_assertion(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True if the function body contains ANY assertion."""
    for node in ast.walk(func_node):
        if isinstance(node, ast.Assert):
            return True
        if isinstance(node, ast.Expr) and _is_assert_call(node.value):
            return True
        if _is_pytest_raises_with(node):
            return True
    return False


# ---------------------------------------------------------------------------
# Mock/patch counting
# ---------------------------------------------------------------------------

_MOCK_CALL_NAMES = {"patch", "MagicMock", "Mock", "AsyncMock", "MagicMock", "patch_object"}
_MOCK_ATTRS = {"patch", "patch_object"}  # mock.patch / patch.object


def _count_mock_constructs(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    """
    Count total mock/patch constructs in function body + its decorators.

    Counts:
    - @patch decorators on the function itself
    - Calls to mock.patch / patch / patch.object / MagicMock / Mock / AsyncMock
      anywhere in the body
    """
    count = 0

    # Decorators
    for dec in func_node.decorator_list:
        # @patch(...)  /  @mock.patch(...)  /  @patch.object(...)
        call = dec
        if isinstance(dec, ast.Call):
            call = dec.func
        if isinstance(call, ast.Attribute):
            if call.attr == "patch" or (hasattr(call, 'attr') and call.attr in ("patch", "object")):
                count += 1
                continue
            # mock.patch.object etc.
            if isinstance(call.value, ast.Attribute) and call.value.attr == "patch":
                count += 1
                continue
        if isinstance(call, ast.Name) and call.id == "patch":
            count += 1
            continue

    # Body: walk body statements explicitly to avoid double-counting
    # decorator nodes that ast.walk(func_node) would also visit.
    body_nodes = []
    for stmt in func_node.body:
        for node in ast.walk(stmt):
            body_nodes.append(node)

    for node in body_nodes:
        if isinstance(node, ast.Call):
            func = node.func
            # patch(...)  ->  Name("patch")
            if isinstance(func, ast.Name) and func.id in {"patch", "MagicMock", "Mock", "AsyncMock"}:
                count += 1
            # mock.patch(...)  ->  Attribute(Name("mock"), "patch")
            elif isinstance(func, ast.Attribute):
                if func.attr in {"patch", "MagicMock", "Mock", "AsyncMock"}:
                    count += 1
                # patch.object(...)
                elif func.attr == "object" and isinstance(func.value, ast.Attribute) and func.value.attr == "patch":
                    count += 1
                elif func.attr == "object" and isinstance(func.value, ast.Name) and func.value.id == "patch":
                    count += 1

    return count


# ---------------------------------------------------------------------------
# Skip-decorator detection
# ---------------------------------------------------------------------------

def _decorator_has_reason(dec: ast.expr) -> bool:
    """Return True if the decorator call has at least one argument (reason/message)."""
    if isinstance(dec, ast.Call):
        return bool(dec.args or dec.keywords)
    return False


def _is_skip_decorator(dec: ast.expr) -> tuple[bool, bool]:
    """
    Return (is_skip, has_reason).
    Handles:
      @skip  @skip("reason")
      @unittest.skip  @unittest.skip("reason")
      @pytest.mark.skip  @pytest.mark.skip(reason="...")
      @pytest.mark.xfail  @pytest.mark.xfail(reason="...")
    """
    # Unwrap call to get the base name/attribute
    base = dec.func if isinstance(dec, ast.Call) else dec

    # @skip  or  @skip("msg")
    if isinstance(base, ast.Name) and base.id == "skip":
        return True, _decorator_has_reason(dec)

    if isinstance(base, ast.Attribute):
        attr = base.attr
        obj = base.value

        # @unittest.skip
        if isinstance(obj, ast.Name) and obj.id == "unittest" and attr == "skip":
            return True, _decorator_has_reason(dec)

        # @pytest.mark.skip  /  @pytest.mark.xfail
        if attr in ("skip", "xfail") and isinstance(obj, ast.Attribute):
            if obj.attr == "mark" and isinstance(obj.value, ast.Name) and obj.value.id == "pytest":
                return True, _decorator_has_reason(dec)

        # @mark.skip  /  @mark.xfail
        if attr in ("skip", "xfail") and isinstance(obj, ast.Name) and obj.id == "mark":
            return True, _decorator_has_reason(dec)

    return False, False


# ---------------------------------------------------------------------------
# Logic-in-test detection
# ---------------------------------------------------------------------------

def _has_logic(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[bool, int]:
    """
    Return (has_logic, first_line) where logic = For / While / If node
    directly within the test function body (recursively, but skipping
    nested function/class definitions and comprehension scopes).
    """
    def walk_body(stmts):
        for stmt in stmts:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue  # don't descend into nested scopes
            if isinstance(stmt, (ast.For, ast.While)):
                yield stmt
            elif isinstance(stmt, ast.If):
                yield stmt
            # Recurse into statement bodies (try/except, with, etc.)
            for child in ast.iter_child_nodes(stmt):
                if isinstance(child, ast.stmt):
                    yield from walk_body([child])

    for node in walk_body(func_node.body):
        return True, node.lineno
    return False, 0


# ---------------------------------------------------------------------------
# Per-file analysis
# ---------------------------------------------------------------------------

def analyze_file(filepath: Path, ignore: set) -> list[CodeSmell]:
    if not _is_test_file(filepath):
        return []
    try:
        source = filepath.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(filepath))
        lines = source.splitlines()
    except Exception:
        return []

    issues: list[CodeSmell] = []

    def add(line, st, desc, sug, sev, snippet=""):
        if st in ignore:
            return
        issues.append(CodeSmell(
            file=str(filepath),
            line=line,
            smell_type=st,
            description=desc,
            suggestion=sug,
            severity=sev,
            code_snippet=snippet,
        ))

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not node.name.startswith("test"):
            continue

        fn = node
        fn_snippet = _get_line(lines, fn.lineno)

        # ---- test_without_assertion ----------------------------------------
        if not _has_assertion(fn):
            add(
                fn.lineno,
                "test_without_assertion",
                f"Test function '{fn.name}' contains no assertion",
                "Add assertions to verify behaviour, or delete the test if it is a placeholder.",
                "high",
                fn_snippet,
            )

        # ---- overmocking ---------------------------------------------------
        mock_count = _count_mock_constructs(fn)
        if mock_count > 4:
            add(
                fn.lineno,
                "overmocking",
                f"Test function '{fn.name}' uses {mock_count} mock/patch constructs",
                (
                    "Heavy mocking tests the mocks, not real behaviour. "
                    "Prefer real objects or restructure to use fewer seams."
                ),
                "medium",
                fn_snippet,
            )

        # ---- skipped_without_reason ----------------------------------------
        for dec in fn.decorator_list:
            is_skip, has_reason = _is_skip_decorator(dec)
            if is_skip and not has_reason:
                dec_line = dec.lineno
                add(
                    dec_line,
                    "skipped_without_reason",
                    f"Test '{fn.name}' is skipped without a reason/message",
                    "Add a reason= argument explaining why the test is skipped, or remove the skip.",
                    "low",
                    _get_line(lines, dec_line),
                )

        # ---- logic_in_test -------------------------------------------------
        has_logic, logic_line = _has_logic(fn)
        if has_logic:
            add(
                logic_line,
                "logic_in_test",
                f"Test function '{fn.name}' contains control-flow (for/while/if) in its body",
                (
                    "Tests with logic can hide bugs. Make tests linear; "
                    "use parametrize for multiple cases."
                ),
                "low",
                _get_line(lines, logic_line),
            )

    return issues


def main():
    parser = argparse.ArgumentParser(description="Detect test-quality smells in Python test files")
    parser.add_argument("path", nargs="?", default=".", help="File or directory")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--ignore", type=str, default="", help="Comma-separated smell types to ignore")
    args = parser.parse_args()
    ignore = set(args.ignore.split(",")) if args.ignore else set()

    all_issues: list[CodeSmell] = []
    for filepath in find_python_files(Path(args.path)):
        all_issues.extend(analyze_file(filepath, ignore))
    all_issues.sort(key=lambda x: (x.severity != "high", x.severity != "medium", x.file, x.line))

    if args.format == "json":
        print(json.dumps([asdict(i) for i in all_issues], indent=2))
    else:
        if not all_issues:
            print("✅ No test smells found!")
            return
        by_type: dict[str, int] = defaultdict(int)
        for i in all_issues:
            by_type[i.smell_type] += 1
        print(f"Found {len(all_issues)} test smell(s):\n\nSummary:")
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

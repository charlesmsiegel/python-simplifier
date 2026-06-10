#!/usr/bin/env python3
"""
Detect coroutines created but never awaited in Python code via AST analysis.

A common AI-generated bug: calling an async function without 'await' silently
creates a coroutine object that is immediately discarded — the code does nothing.

Finds:
  - unawaited_coroutine : a call to an async-def function whose result is
                          discarded (bare expression statement) or used as an
                          if/while condition, and is not wrapped in await or
                          asyncio task-creation helpers.
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


def _get_line(lines, lineno):
    if 0 < lineno <= len(lines):
        return lines[lineno - 1].strip()[:80]
    return ""


# Wrappers that legitimately consume a coroutine without a direct await
_ASYNCIO_WRAPPERS = {
    "gather", "create_task", "ensure_future", "run", "wait", "shield",
}

# Full qualified forms: asyncio.gather, loop.create_task, etc.
def _is_wrapper_call(node):
    """Return True if node is a Call whose function is an asyncio/loop wrapper."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Attribute):
        # asyncio.gather(...), asyncio.create_task(...), loop.create_task(...)
        if func.attr in _ASYNCIO_WRAPPERS:
            return True
    elif isinstance(func, ast.Name):
        if func.id in _ASYNCIO_WRAPPERS:
            return True
    return False


def _collect_async_names(tree):
    """Collect all names defined as async def anywhere in the module."""
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef):
            names.add(node.name)
    return names


def _call_target_name(call_node):
    """
    Return the bare function name for a Call node, or None if not applicable.
    Handles: name(...) and obj.name(...).
    """
    func = call_node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def detect(tree, filename, lines, ignore):
    issues = []
    st = "unawaited_coroutine"
    if st in ignore:
        return issues

    async_names = _collect_async_names(tree)
    if not async_names:
        return issues

    def add(lineno, name):
        desc = (
            f"Coroutine '{name}(...)' is called but never awaited; "
            f"the coroutine object is silently discarded and the function body never runs"
        )
        sug = (
            "Add 'await' before the call, or wrap it in "
            "asyncio.create_task()/asyncio.gather() to schedule it."
        )
        issues.append(CodeSmell(
            filename, lineno, st, desc, sug, "high",
            _get_line(lines, lineno),
        ))

    # Walk the AST looking for:
    # 1. ast.Expr whose value is a Call to an async name (discarded expression)
    # 2. ast.If / ast.While whose test is a Call to an async name
    for node in ast.walk(tree):
        # Case (a): bare expression statement  — `f()`
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            call = node.value
            name = _call_target_name(call)
            if name and name in async_names:
                # Must not be wrapped in await (it can't be in ast.Expr.value
                # form without await, but be safe) or a wrapper call
                # ast.Expr.value is the call itself; it cannot be an Await here
                # because `await f()` parses as Expr(value=Await(value=Call(...)))
                if not _is_wrapper_call(call):
                    add(call.lineno, name)

        # Case (b): condition of if/while — `if f():` / `while f():`
        elif isinstance(node, (ast.If, ast.While)):
            test = node.test
            if isinstance(test, ast.Call):
                name = _call_target_name(test)
                if name and name in async_names:
                    if not _is_wrapper_call(test):
                        add(test.lineno, name)

    return issues


def analyze_file(filepath: Path, ignore: set) -> list:
    try:
        source = filepath.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(filepath))
        return detect(tree, str(filepath), source.splitlines(), ignore)
    except (SyntaxError, Exception):
        return []


def find_python_files(path: Path) -> Iterator[Path]:
    if path.is_file() and path.suffix == ".py":
        yield path
    elif path.is_dir():
        for p in path.rglob("*.py"):
            if ".venv" not in p.parts and "node_modules" not in p.parts and "__pycache__" not in p.parts:
                yield p


def main():
    parser = argparse.ArgumentParser(
        description="Detect unawaited coroutines in Python"
    )
    parser.add_argument("path", nargs="?", default=".", help="File or directory")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--ignore", type=str, default="", help="Comma-separated smell types to ignore")
    args = parser.parse_args()
    ignore = set(args.ignore.split(",")) if args.ignore else set()

    all_issues = []
    for filepath in find_python_files(Path(args.path)):
        all_issues.extend(analyze_file(filepath, ignore))
    all_issues.sort(key=lambda x: (x.severity != "high", x.severity != "medium", x.file, x.line))

    if args.format == "json":
        print(json.dumps([asdict(i) for i in all_issues], indent=2))
    else:
        if not all_issues:
            print("✅ No unawaited coroutines found!")
            return
        by_type = defaultdict(int)
        for i in all_issues:
            by_type[i.smell_type] += 1
        print(f"Found {len(all_issues)} issue(s):\n\nSummary:")
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

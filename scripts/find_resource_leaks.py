#!/usr/bin/env python3
"""
Detect resources opened without a context manager (handle/fd leaks).

Finds:
  - unmanaged_open     : open() result assigned to a variable outside a `with`
                         statement (HIGH); also open() result immediately
                         attribute-accessed/called without `with` (LOW)
  - unmanaged_resource : socket.socket(), tempfile.NamedTemporaryFile(), or
                         tempfile.TemporaryFile() assigned outside `with` (MEDIUM)
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


def _is_open_call(node) -> bool:
    """Return True if node is a call to the builtin open()."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "open"
    )


def _is_attr_call(node, module: str, attr: str) -> bool:
    """Return True if node is a call like `module.attr(...)`."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == attr
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == module
    )


def _collect_with_context_exprs(tree) -> set:
    """
    Return the set of Call node ids (id()) that appear as context expressions
    in any `with` statement in the tree.
    """
    managed = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.With) or isinstance(node, ast.AsyncWith):
            for item in node.items:
                managed.add(id(item.context_expr))
    return managed


def detect(tree, filename, lines, ignore):
    issues = []

    def add(line, st, desc, sug, sev):
        if st in ignore:
            return
        issues.append(CodeSmell(filename, line, st, desc, sug, sev, _get_line(lines, line)))

    managed = _collect_with_context_exprs(tree)

    for node in ast.walk(tree):
        # --- Assign: x = open(...) / x = socket.socket(...) / etc. ---
        if isinstance(node, ast.Assign):
            value = node.value
            if id(value) in managed:
                continue

            if _is_open_call(value):
                add(
                    node.lineno,
                    "unmanaged_open",
                    "open() result assigned without a context manager — file handle may leak",
                    "Use `with open(...) as f:` so the handle is closed deterministically.",
                    "high",
                )
            elif _is_attr_call(value, "socket", "socket"):
                add(
                    node.lineno,
                    "unmanaged_resource",
                    "socket.socket() result assigned without a context manager — socket may leak",
                    "Use `with socket.socket(...) as s:` so the socket is closed deterministically.",
                    "medium",
                )
            elif _is_attr_call(value, "tempfile", "NamedTemporaryFile"):
                add(
                    node.lineno,
                    "unmanaged_resource",
                    "tempfile.NamedTemporaryFile() assigned without a context manager — resource may leak",
                    "Use `with tempfile.NamedTemporaryFile(...) as f:` so the file is cleaned up deterministically.",
                    "medium",
                )
            elif _is_attr_call(value, "tempfile", "TemporaryFile"):
                add(
                    node.lineno,
                    "unmanaged_resource",
                    "tempfile.TemporaryFile() assigned without a context manager — resource may leak",
                    "Use `with tempfile.TemporaryFile(...) as f:` so the file is cleaned up deterministically.",
                    "medium",
                )

        # --- AnnAssign: x: T = open(...) ---
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            value = node.value
            if id(value) in managed:
                continue

            if _is_open_call(value):
                add(
                    node.lineno,
                    "unmanaged_open",
                    "open() result assigned without a context manager — file handle may leak",
                    "Use `with open(...) as f:` so the handle is closed deterministically.",
                    "high",
                )
            elif _is_attr_call(value, "socket", "socket"):
                add(
                    node.lineno,
                    "unmanaged_resource",
                    "socket.socket() result assigned without a context manager — socket may leak",
                    "Use `with socket.socket(...) as s:` so the socket is closed deterministically.",
                    "medium",
                )
            elif _is_attr_call(value, "tempfile", "NamedTemporaryFile"):
                add(
                    node.lineno,
                    "unmanaged_resource",
                    "tempfile.NamedTemporaryFile() assigned without a context manager — resource may leak",
                    "Use `with tempfile.NamedTemporaryFile(...) as f:` so the file is cleaned up deterministically.",
                    "medium",
                )
            elif _is_attr_call(value, "tempfile", "TemporaryFile"):
                add(
                    node.lineno,
                    "unmanaged_resource",
                    "tempfile.TemporaryFile() assigned without a context manager — resource may leak",
                    "Use `with tempfile.TemporaryFile(...) as f:` so the file is cleaned up deterministically.",
                    "medium",
                )

        # --- Expr: open(p).read() style — open() result immediately used, no with ---
        elif isinstance(node, ast.Expr):
            expr_value = node.value
            # Look for Call whose func is an Attribute on an open() call
            # e.g. open(p).read()
            if (
                isinstance(expr_value, ast.Call)
                and isinstance(expr_value.func, ast.Attribute)
                and _is_open_call(expr_value.func.value)
                and id(expr_value.func.value) not in managed
            ):
                add(
                    node.lineno,
                    "unmanaged_open",
                    "open() result used inline without a context manager — file handle may leak",
                    "Use `with open(...) as f:` so the handle is closed deterministically.",
                    "low",
                )

        # Also catch assignment where value is attr-access on open():
        # data = open(p).read()
        elif isinstance(node, ast.Assign):
            pass  # already handled above; this branch is unreachable but kept for clarity

    # Second pass: catch `data = open(p).read()` — the Assign value is a Call
    # whose func.value is an open() call (chained attribute call assigned)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            value = node.value
            if (
                isinstance(value, ast.Call)
                and isinstance(value.func, ast.Attribute)
                and _is_open_call(value.func.value)
                and id(value.func.value) not in managed
            ):
                add(
                    node.lineno,
                    "unmanaged_open",
                    "open() result used inline without a context manager — file handle may leak",
                    "Use `with open(...) as f:` so the handle is closed deterministically.",
                    "low",
                )
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            value = node.value
            if (
                isinstance(value, ast.Call)
                and isinstance(value.func, ast.Attribute)
                and _is_open_call(value.func.value)
                and id(value.func.value) not in managed
            ):
                add(
                    node.lineno,
                    "unmanaged_open",
                    "open() result used inline without a context manager — file handle may leak",
                    "Use `with open(...) as f:` so the handle is closed deterministically.",
                    "low",
                )

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
    parser = argparse.ArgumentParser(description="Detect resource leaks in Python")
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
            print("✅ No resource leaks found!")
            return
        by_type = defaultdict(int)
        for i in all_issues:
            by_type[i.smell_type] += 1
        print(f"Found {len(all_issues)} resource leak(s):\n\nSummary:")
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

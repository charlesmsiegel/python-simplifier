#!/usr/bin/env python3
"""
Detect duplicate definitions and merge artifacts in Python code via AST analysis.

AI regeneration and bad merges frequently produce silent bugs where a later
definition silently shadows an earlier one in the same scope, or leave merge
conflict markers that break the file entirely.

Finds:
  - duplicate_definition  : two or more FunctionDef/AsyncFunctionDef (or ClassDef)
                            with the same name as direct siblings in the same body
                            list (module, class, or function body). The later one
                            silently shadows the earlier.
  - merge_conflict_marker : raw lines starting with '<<<<<<< ' or '>>>>>>> ', or
                            lines that are seven-or-more '=' characters when the
                            file also contains a '<<<<<<<' marker.
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


def _decorator_names(node):
    """Return the set of decorator name strings on a function/class definition."""
    names = set()
    for dec in node.decorator_list:
        if isinstance(dec, ast.Name):
            names.add(dec.id)
        elif isinstance(dec, ast.Attribute):
            # e.g. typing.overload  -> "overload"
            # e.g. myprop.setter    -> "myprop.setter" and "setter"
            names.add(dec.attr)
            if isinstance(dec.value, ast.Name):
                names.add(f"{dec.value.id}.{dec.attr}")
    return names


def _is_overload(node):
    decs = _decorator_names(node)
    return "overload" in decs


def _is_property_group(node):
    """True for property / .setter / .getter / .deleter decorators."""
    decs = _decorator_names(node)
    if "property" in decs:
        return True
    # match patterns like "foo.setter", "foo.deleter", "foo.getter"
    for d in decs:
        if "." in d and d.split(".")[-1] in ("setter", "deleter", "getter"):
            return True
    return False


def _check_body_for_duplicates(body, filename, lines, ignore):
    issues = []
    # Track first-seen line for each (kind, name) pair
    # kind: "def" for FunctionDef/AsyncFunctionDef, "class" for ClassDef
    seen = {}  # name -> (kind, lineno)
    for node in body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            kind = "def"
            name = node.name
        elif isinstance(node, ast.ClassDef):
            kind = "class"
            name = node.name
        else:
            continue

        # Skip overloads and property groups
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _is_overload(node) or _is_property_group(node):
                # Also skip recording so we don't flag the first non-overload either
                # Actually: just don't participate in duplicate tracking for this name
                seen[name] = (kind, node.lineno)  # update so later defs track correctly
                continue

        key = (kind, name)
        if key in seen:
            prev_kind, prev_line = seen[key]
            st = "duplicate_definition"
            if st not in ignore:
                desc = (
                    f"{'Function' if kind == 'def' else 'Class'} '{name}' is defined "
                    f"again at line {node.lineno}; the earlier definition at line "
                    f"{prev_line} is silently shadowed"
                )
                sug = "Remove the duplicate (older) definition, keeping only the intended version."
                issues.append(CodeSmell(
                    filename, node.lineno, st, desc, sug, "high",
                    _get_line(lines, node.lineno),
                ))
        seen[key] = (kind, node.lineno)

    return issues


def _scan_merge_conflicts(source, filename, lines, ignore):
    """Scan raw source for merge conflict markers."""
    issues = []
    st = "merge_conflict_marker"
    if st in ignore:
        return issues

    has_open_marker = any(
        line.startswith("<<<<<<<") for line in lines
    )

    for lineno, raw in enumerate(lines, 1):
        stripped = raw.strip()
        if raw.startswith("<<<<<<< ") or raw.startswith(">>>>>>> "):
            issues.append(CodeSmell(
                filename, lineno, st,
                f"Merge conflict marker found: {stripped[:60]}",
                "Resolve the merge conflict and remove all conflict markers.",
                "high",
                _get_line(lines, lineno),
            ))
        elif has_open_marker and len(stripped) >= 7 and all(c == "=" for c in stripped):
            issues.append(CodeSmell(
                filename, lineno, st,
                f"Merge conflict separator (=======) found",
                "Resolve the merge conflict and remove all conflict markers.",
                "high",
                _get_line(lines, lineno),
            ))

    return issues


def _walk_scopes(tree, filename, lines, ignore):
    """Walk module/class/function bodies and check each for duplicate definitions."""
    issues = []
    # Check module body
    issues.extend(_check_body_for_duplicates(tree.body, filename, lines, ignore))
    # Walk all nested scopes
    for node in ast.walk(tree):
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            issues.extend(_check_body_for_duplicates(node.body, filename, lines, ignore))
    return issues


def analyze_file(filepath: Path, ignore: set) -> list:
    try:
        source = filepath.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    lines = source.splitlines()
    filename = str(filepath)

    # Always scan for conflict markers on the raw text first
    conflict_issues = _scan_merge_conflicts(source, filename, lines, ignore)

    # Attempt AST parse; if it fails, return only conflict findings
    try:
        tree = ast.parse(source, filename=filename)
    except Exception:
        return conflict_issues

    dup_issues = _walk_scopes(tree, filename, lines, ignore)
    return conflict_issues + dup_issues


def find_python_files(path: Path) -> Iterator[Path]:
    if path.is_file() and path.suffix == ".py":
        yield path
    elif path.is_dir():
        for p in path.rglob("*.py"):
            if ".venv" not in p.parts and "node_modules" not in p.parts and "__pycache__" not in p.parts:
                yield p


def main():
    parser = argparse.ArgumentParser(
        description="Detect duplicate definitions and merge artifacts in Python"
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
            print("✅ No duplicate definitions or merge artifacts found!")
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

#!/usr/bin/env python3
"""
Review-a-change-request lens: run the file-level detectors against only the files
(and, by default, the added/modified lines) of a diff.

This is the tool for reviewing an AI-written feature or CR: you want findings about
*what changed*, not the legacy code around it. It runs the per-file detectors on
each changed .py file and keeps only findings that land on lines the diff touched.

Whole-repo / architecture detectors (find_import_cycles, find_dependency_issues,
find_untested_modules, find_duplicates, find_dead_code, find_overengineering,
find_coupling_issues) need the full tree to be correct, so they are deliberately
NOT part of the diff lens — run them with analyze_all.py against the whole repo.

Usage:
  python analyze_diff.py                 # working tree vs. the merge-base with the default branch
  python analyze_diff.py origin/main     # vs. an explicit base ref
  python analyze_diff.py HEAD~3
  python analyze_diff.py --all-lines     # every line of each changed file, not just changed lines
  python analyze_diff.py --format json | python format_findings.py
"""

import re
import ast
import sys
import json
import argparse
import subprocess
from pathlib import Path
from collections import defaultdict

# Per-file detectors only. Each is meaningful on a single file and reports a line
# within that file. Whole-repo detectors are excluded on purpose (see module docstring).
DIFF_SAFE_SCRIPTS = [
    "analyze_complexity.py",
    "find_code_smells.py",
    "find_design_smells.py",
    "find_unpythonic.py",
    "find_mutation_hazards.py",
    "find_exception_issues.py",
    "find_global_state.py",
    "find_boolean_params.py",
    "find_return_issues.py",
    "find_loop_simplifications.py",
    "find_naming_issues.py",
    "find_comment_smells.py",
    "find_resource_leaks.py",
    "find_security_issues.py",
    "find_debug_leftovers.py",
    "find_outdated_idioms.py",
    "find_missing_docstrings.py",
    "find_type_gaps.py",
    "find_test_smells.py",
    "find_ai_scaffolding.py",
    "find_duplicate_definitions.py",
    "find_unawaited_coroutines.py",
    "find_redundant_comments.py",
    "find_local_imports.py",
]

_ICON = {"high": "🔴", "medium": "🟡", "low": "🟢"}
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def _git(args):
    try:
        r = subprocess.run(["git", *args], capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            return None
        return r.stdout
    except (OSError, subprocess.SubprocessError):
        return None


def resolve_base(explicit):
    """Pick a base ref to diff against. Returns None for an invalid explicit ref."""
    if explicit:
        # A misspelled base must be an error, not an empty (falsely clean) diff.
        if _git(["rev-parse", "--verify", "--quiet", f"{explicit}^{{commit}}"]) is None:
            return None
        return explicit
    for candidate in ("origin/main", "origin/master", "main", "master"):
        mb = _git(["merge-base", "HEAD", candidate])
        if mb:
            return mb.strip()
    # Fall back to the previous commit, then the empty tree (first commit).
    if _git(["rev-parse", "HEAD~1"]) is not None:
        return "HEAD~1"
    return _git(["hash-object", "-t", "tree", "/dev/null"]).strip() if _git(["rev-parse", "HEAD"]) else None


def changed_lines(base):
    """Return {abs_path: set_of_changed_line_numbers or None (=all lines)},
    or None if git diff itself failed (e.g. unknown base ref)."""
    changed = {}
    # core.quotePath=false keeps non-ASCII filenames literal instead of
    # octal-escaped+quoted, so the paths resolve on the filesystem.
    diff = _git(["-c", "core.quotePath=false", "diff", "--unified=0", "--no-color", base, "--", "*.py"])
    if diff is None:
        return None
    if diff:
        current = None
        for line in diff.splitlines():
            if line.startswith("+++ "):
                target = line[4:].strip()
                current = None if target == "/dev/null" else target[2:] if target.startswith("b/") else target
                if current is not None:
                    changed.setdefault(str(Path(current).resolve()), set())
            elif current is not None and line.startswith("@@"):
                m = _HUNK.match(line)
                if m:
                    start = int(m.group(1))
                    count = int(m.group(2)) if m.group(2) is not None else 1
                    for ln in range(start, start + count):
                        changed[str(Path(current).resolve())].add(ln)
    # Untracked new files: treat every line as changed.
    others = _git(["-c", "core.quotePath=false", "ls-files", "--others", "--exclude-standard", "--", "*.py"])
    if others:
        for rel in others.splitlines():
            rel = rel.strip()
            if rel:
                changed[str(Path(rel).resolve())] = None
    # Drop files that no longer exist on disk (pure deletions).
    return {f: lines for f, lines in changed.items() if Path(f).exists()}


def _expand_to_definitions(filepath, lines):
    """Add the `def`/`class` line of every definition whose body intersects the
    changed lines. Detectors often anchor a finding at the (unchanged) def line
    even when the change that caused it is inside the body — without this, a
    diff that adds nesting inside an existing function would be silently clean."""
    expanded = set(lines)
    try:
        tree = ast.parse(Path(filepath).read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError, ValueError):
        return expanded
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            end = getattr(node, "end_lineno", node.lineno)
            if any(node.lineno <= ln <= end for ln in lines):
                expanded.add(node.lineno)
    return expanded


def run_detector(script, filepath):
    """Run one detector. Returns (findings, error): error is a short string when
    the detector crashed/timed out/emitted bad JSON — a silent [] would let the
    diff review claim clean for a category that was never actually evaluated."""
    script_path = Path(__file__).parent / script
    if not script_path.exists():
        return [], f"script not found: {script}"
    try:
        r = subprocess.run(
            [sys.executable, str(script_path), filepath, "--format", "json"],
            capture_output=True, text=True, timeout=120,
        )
    except (subprocess.SubprocessError, OSError) as e:
        return [], str(e)[:200] or "failed to run"
    if r.returncode != 0:
        tail = (r.stderr or "").strip().splitlines()
        return [], tail[-1][:200] if tail else f"exit code {r.returncode}"
    if not r.stdout.strip():
        return [], "no output"
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError as e:
        return [], f"bad JSON output: {e}"
    return (data if isinstance(data, list) else data.get("issues", [])), None


def collect(base, all_lines):
    files = changed_lines(base)
    if files is None:
        return None, None
    findings = []
    for filepath, lines in files.items():
        accepted = None if lines is None else _expand_to_definitions(filepath, lines)
        for script in DIFF_SAFE_SCRIPTS:
            issues, error = run_detector(script, filepath)
            if error is not None:
                # Detector failures bypass the changed-line filter: the reader
                # must see that this category was not evaluated for this file.
                findings.append({
                    "file": filepath, "line": 1, "smell_type": "detector_error",
                    "description": f"{script} did not complete ({error}) — its findings for this file are missing",
                    "suggestion": f"Run `python scripts/{script} {filepath}` directly to see the failure.",
                    "severity": "medium",
                })
                continue
            for issue in issues:
                if not isinstance(issue, dict):
                    continue
                ln = issue.get("line")
                if all_lines or accepted is None or (isinstance(ln, int) and ln in accepted):
                    issue.setdefault("severity", "medium")
                    findings.append(issue)
    # De-dupe identical findings (a line can be flagged by overlapping detectors).
    seen, unique = set(), []
    for f in findings:
        key = (f.get("file"), f.get("line"), f.get("smell_type") or f.get("issue_type"), f.get("description"))
        if key not in seen:
            seen.add(key)
            unique.append(f)
    rank = {"high": 0, "medium": 1, "low": 2}
    unique.sort(key=lambda f: (rank.get(f.get("severity", "medium"), 1), str(f.get("file")), f.get("line", 0)))
    return files, unique


def _type_of(issue):
    for key in ("smell_type", "issue_type", "pattern_type", "type"):
        if issue.get(key):
            return issue[key]
    return "issue"


def print_text(files, findings, base):
    n_files = len(files)
    print(f"\n📋 CR REVIEW — {n_files} changed file(s) vs. {base[:12]}")
    print("=" * 60)
    if not findings:
        print("✅ No findings on the changed lines.")
        return
    by_sev = defaultdict(int)
    for f in findings:
        by_sev[f.get("severity", "medium")] += 1
    print(f"Findings on changed lines: {len(findings)}  "
          f"({_ICON['high']} {by_sev['high']}  {_ICON['medium']} {by_sev['medium']}  {_ICON['low']} {by_sev['low']})\n")
    for f in findings:
        sev = f.get("severity", "medium")
        print(f"{_ICON.get(sev, '')} [{sev.upper()}] {f.get('file', '?')}:{f.get('line', '?')}")
        print(f"   {_type_of(f)}: {f.get('description', '')}")
        if f.get("suggestion"):
            print(f"   → {f['suggestion']}")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="Run the file-level detectors against only the changed lines of a diff (CR review lens)",
    )
    parser.add_argument("base", nargs="?", default=None,
                        help="Base ref to diff against (default: merge-base with origin/main, then HEAD~1)")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--all-lines", action="store_true",
                        help="Report findings on every line of each changed file, not just changed lines")
    args = parser.parse_args()

    if _git(["rev-parse", "--is-inside-work-tree"]) is None:
        print("Not a git repository (or git unavailable). The diff lens needs git.", file=sys.stderr)
        sys.exit(1)

    base = resolve_base(args.base)
    if not base:
        if args.base:
            print(f"Base ref '{args.base}' does not resolve to a commit.", file=sys.stderr)
        else:
            print("Could not resolve a base ref to diff against.", file=sys.stderr)
        sys.exit(1)

    files, findings = collect(base, args.all_lines)
    if files is None:
        print(f"git diff against '{base}' failed; refusing to report a falsely clean review.", file=sys.stderr)
        sys.exit(1)

    if args.format == "json":
        print(json.dumps(findings, indent=2))
    else:
        print_text(files, findings, base)


if __name__ == "__main__":
    main()

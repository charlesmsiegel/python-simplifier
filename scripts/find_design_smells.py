#!/usr/bin/env python3
"""
Detect classic refactoring-catalog design smells via AST analysis.

Covers the mechanically-detectable slice of the Fowler/refactoring.guru smell
catalog that the other detectors don't already handle:
  type_switch                     - if/elif ladder dispatching on one type tag (Switch Statements)
  duplicate_conditional_fragment  - identical statement in every branch of a conditional
  control_flag                    - boolean loop flag standing in for break/return
  inappropriate_intimacy          - reaching into another object's _private attributes
  temporary_field                 - field that is None except inside a single method
  refused_bequest                 - subclass no-ops or raises on inherited concrete behavior
  lazy_class                      - subclass that adds nothing over its base

Each finding names the catalog refactoring to apply. These are candidates: the
judgment call (and the subtler instances no parser can see) belongs to
references/refactoring-catalog.md and references/refactoring-techniques.md.
"""

import ast
import json
import argparse
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Iterator
from collections import defaultdict


@dataclass
class DesignSmell:
    file: str
    line: int
    smell_type: str
    description: str
    suggestion: str
    severity: str
    code_snippet: str = ""


# Public-by-convention namedtuple machinery; touching these is not intimacy.
NAMEDTUPLE_API = frozenset({"_replace", "_asdict", "_fields", "_make", "_field_defaults"})

# Receivers that mean "my own class", not someone else's internals.
OWN_RECEIVERS = frozenset({"self", "cls", "mcs", "mcls"})

# Base names whose empty subclasses are idiomatic, not lazy.
MARKER_BASES = frozenset({
    "object", "Exception", "BaseException", "Protocol", "ABC", "Generic",
    "NamedTuple", "TypedDict", "Enum", "IntEnum", "StrEnum", "Flag", "IntFlag",
})

PROPERTY_DECORATORS = frozenset({"property", "cached_property"})

# Ladders below this many branches don't count as a switch: short chains are
# often the clearest form, and conservatism keeps the output trustworthy.
MIN_EQ_BRANCHES = 4
MIN_ISINSTANCE_BRANCHES = 4


def _is_dunder(name: str) -> bool:
    return name.startswith("__") and name.endswith("__")


def _walk_same_scope(stmts: list[ast.stmt]) -> Iterator[ast.AST]:
    """Walk statements without descending into nested scopes (defs, classes,
    lambdas) — a name assigned there is a different variable."""
    stack: list[ast.AST] = list(stmts)
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            stack.extend(ast.iter_child_nodes(node))


def _strip_docstring(body: list[ast.stmt]) -> list[ast.stmt]:
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
            and isinstance(body[0].value.value, str):
        return body[1:]
    return body


def _body_kind(body: list[ast.stmt]) -> str | None:
    """Classify a trivial body: 'noop' (pass/.../docstring only), 'raise_nie', or None."""
    rest = _strip_docstring(body)
    if not rest or all(
        isinstance(s, ast.Pass)
        or (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant) and s.value.value is Ellipsis)
        for s in rest
    ):
        return "noop"
    if len(rest) == 1 and isinstance(rest[0], ast.Raise):
        exc = rest[0].exc
        if isinstance(exc, ast.Call):
            exc = exc.func
        if isinstance(exc, ast.Name) and exc.id == "NotImplementedError":
            return "raise_nie"
    return None


def _decorator_names(node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> set[str]:
    names = set()
    for dec in node.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(target, ast.Name):
            names.add(target.id)
        elif isinstance(target, ast.Attribute):
            names.add(target.attr)
    return names


class DesignSmellDetector(ast.NodeVisitor):
    def __init__(self, filename: str, source_lines: list[str], tree: ast.Module,
                 ignore: set[str] = None, is_test_file: bool = False):
        self.filename = filename
        self.source_lines = source_lines
        self.issues: list[DesignSmell] = []
        self.ignore = ignore or set()
        self.is_test_file = is_test_file
        self._func_stack: list[str] = []
        self._ladder_members: set[int] = set()
        # Names that are imports or same-module classes: touching their _private
        # members is module-internal by convention, not cross-class intimacy.
        self.known_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.known_names.add(alias.asname or alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    self.known_names.add(alias.asname or alias.name)
            elif isinstance(node, ast.ClassDef):
                self.known_names.add(node.name)
        # Base-class resolution uses only module-level classes: nested classes in
        # different containers can share a short name, and joining them would
        # attribute one container's methods to the other's hierarchy.
        self.class_defs: dict[str, ast.ClassDef] = {
            n.name: n for n in tree.body if isinstance(n, ast.ClassDef)
        }

    def _get_line(self, lineno: int) -> str:
        if 0 < lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()[:60]
        return ""

    def _add(self, line: int, smell_type: str, desc: str, suggestion: str, severity: str = "medium"):
        if smell_type in self.ignore:
            return
        self.issues.append(DesignSmell(
            file=self.filename, line=line, smell_type=smell_type,
            description=desc, suggestion=suggestion, severity=severity,
            code_snippet=self._get_line(line)
        ))

    # ----------------------------------------------------------------- #
    # Function context (used to skip dunders for intimacy)
    # ----------------------------------------------------------------- #

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._func_stack.append(node.name)
        self.generic_visit(node)
        self._func_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._func_stack.append(node.name)
        self.generic_visit(node)
        self._func_stack.pop()

    # ----------------------------------------------------------------- #
    # Switch Statements + Consolidate Duplicate Conditional Fragments
    # ----------------------------------------------------------------- #

    def visit_If(self, node: ast.If):
        if id(node) not in self._ladder_members:
            tests, bodies, final_else = self._collect_ladder(node)
            self._check_type_switch(node, tests)
            self._check_duplicate_fragments(node, bodies, final_else)
        self.generic_visit(node)

    def _collect_ladder(self, node: ast.If):
        """Walk an if/elif/else chain; returns (tests, branch bodies, has-final-else)."""
        tests, bodies = [], []
        current = node
        while True:
            tests.append(current.test)
            bodies.append(current.body)
            if (len(current.orelse) == 1 and isinstance(current.orelse[0], ast.If)
                    and current.orelse[0].col_offset == current.col_offset):
                current = current.orelse[0]
                self._ladder_members.add(id(current))
            else:
                break
        if current.orelse:
            bodies.append(current.orelse)
            return tests, bodies, True
        return tests, bodies, False

    @staticmethod
    def _switch_subject(test: ast.expr):
        """Return (subject node, kind) for `subject == constant` or isinstance(subject, T)."""
        if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq):
            left, right = test.left, test.comparators[0]
            if isinstance(right, ast.Constant) and isinstance(left, (ast.Name, ast.Attribute)):
                return left, "eq"
            if isinstance(left, ast.Constant) and isinstance(right, (ast.Name, ast.Attribute)):
                return right, "eq"
        if (isinstance(test, ast.Call) and isinstance(test.func, ast.Name)
                and test.func.id == "isinstance" and len(test.args) == 2
                and isinstance(test.args[0], (ast.Name, ast.Attribute))):
            return test.args[0], "isinstance"
        return None, None

    def _check_type_switch(self, node: ast.If, tests: list[ast.expr]):
        subjects = [self._switch_subject(t) for t in tests]
        if any(s is None for s, _ in subjects):
            return
        if len({ast.dump(s) for s, _ in subjects}) != 1:
            return
        kinds = {k for _, k in subjects}
        threshold = MIN_ISINSTANCE_BRANCHES if "isinstance" in kinds else MIN_EQ_BRANCHES
        if len(tests) < threshold:
            return
        subject_src = ast.unparse(subjects[0][0])
        via = "isinstance checks on" if "isinstance" in kinds else "comparisons against"
        self._add(node.lineno, "type_switch",
            f"if/elif ladder with {len(tests)} branches dispatching via {via} '{subject_src}'",
            "Replace Conditional with Polymorphism, a dispatch dict, or match — "
            "adding a case should mean adding an entry, not editing a ladder",
            "high" if len(tests) >= 6 else "medium")

    def _check_duplicate_fragments(self, node: ast.If, bodies: list[list[ast.stmt]], final_else: bool):
        if not final_else or len(bodies) < 2 or any(not b for b in bodies):
            return
        last_dumps = {ast.dump(b[-1]) for b in bodies}
        if len(last_dumps) == 1:
            self._add(node.lineno, "duplicate_conditional_fragment",
                f"All {len(bodies)} branches end with the same statement",
                "Move the shared statement after the conditional "
                "(Consolidate Duplicate Conditional Fragments)", "medium")
            return
        first_dumps = {ast.dump(b[0]) for b in bodies}
        if len(first_dumps) == 1:
            self._add(node.lineno, "duplicate_conditional_fragment",
                f"All {len(bodies)} branches start with the same statement",
                "Move the shared statement before the conditional — but verify the "
                "condition does not read anything that statement writes", "low")

    # ----------------------------------------------------------------- #
    # Remove Control Flag
    # ----------------------------------------------------------------- #

    def visit_While(self, node: ast.While):
        flag = None
        if isinstance(node.test, ast.Name):
            flag = node.test.id
        elif (isinstance(node.test, ast.UnaryOp) and isinstance(node.test.op, ast.Not)
                and isinstance(node.test.operand, ast.Name)):
            flag = node.test.operand.id
        if flag and any(
            isinstance(inner, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == flag for t in inner.targets)
            and isinstance(inner.value, ast.Constant)
            and isinstance(inner.value.value, bool)
            for inner in _walk_same_scope(node.body)
        ):
            self._add(node.lineno, "control_flag",
                f"Loop is steered by boolean flag '{flag}' reassigned in the body",
                "Use break/return at the point the flag is set, or make the loop "
                "condition the real condition (Remove Control Flag)", "low")
        self.generic_visit(node)

    # ----------------------------------------------------------------- #
    # Inappropriate Intimacy
    # ----------------------------------------------------------------- #

    def visit_Attribute(self, node: ast.Attribute):
        if (not self.is_test_file
                and node.attr.startswith("_") and not node.attr.startswith("__")
                and node.attr not in NAMEDTUPLE_API
                and isinstance(node.value, ast.Name)
                and node.value.id not in OWN_RECEIVERS
                and node.value.id not in self.known_names
                and not any(_is_dunder(f) for f in self._func_stack)):
            self._add(node.lineno, "inappropriate_intimacy",
                f"Reaching into '{node.value.id}.{node.attr}' — another object's private internals",
                "Move Method to where the data lives, or expose an intentional API "
                "(Hide Delegate); classes should know as little about each other as possible",
                "medium")
        self.generic_visit(node)

    # ----------------------------------------------------------------- #
    # Temporary Field, Refused Bequest, Lazy Class
    # ----------------------------------------------------------------- #

    def visit_ClassDef(self, node: ast.ClassDef):
        self._check_temporary_fields(node)
        self._check_refused_bequest(node)
        self._check_lazy_class(node)
        self.generic_visit(node)

    def _methods(self, node: ast.ClassDef) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
        return [n for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]

    def _check_temporary_fields(self, node: ast.ClassDef):
        init = next((m for m in self._methods(node) if m.name == "__init__"), None)
        if init is None:
            return
        none_fields: dict[str, int] = {}
        disqualified: set[str] = set()
        for inner in ast.walk(init):
            if isinstance(inner, ast.Attribute) and isinstance(inner.value, ast.Name) \
                    and inner.value.id == "self":
                if isinstance(inner.ctx, ast.Load):
                    disqualified.add(inner.attr)
            targets, value = [], None
            if isinstance(inner, ast.Assign):
                targets, value = inner.targets, inner.value
            elif isinstance(inner, ast.AnnAssign) and inner.value is not None:
                targets, value = [inner.target], inner.value
            for target in targets:
                if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) \
                        and target.value.id == "self":
                    if isinstance(value, ast.Constant) and value.value is None:
                        none_fields.setdefault(target.attr, inner.lineno)
                    else:
                        disqualified.add(target.attr)
        if not none_fields:
            return
        usage: dict[str, set[str]] = defaultdict(set)
        accessor_like: set[str] = set()
        for method in self._methods(node):
            if method.name == "__init__":
                continue
            decorators = _decorator_names(method)
            if decorators & PROPERTY_DECORATORS or {"setter", "getter", "deleter"} & decorators:
                accessor_like.add(method.name)
            for inner in ast.walk(method):
                if isinstance(inner, ast.Attribute) and isinstance(inner.value, ast.Name) \
                        and inner.value.id == "self" and inner.attr in none_fields:
                    usage[inner.attr].add(method.name)
        for attr, line in none_fields.items():
            if attr in disqualified:
                continue
            methods = usage.get(attr, set())
            # Lazy-init caches behind a property are idiomatic, not a smell.
            if len(methods) == 1 and not methods & accessor_like:
                only = next(iter(methods))
                self._add(line, "temporary_field",
                    f"Field 'self.{attr}' is None except inside '{only}' — a temporary field",
                    f"Pass the value through parameters or extract '{only}' and its data into "
                    "its own class (Extract Class / Replace Method with Method Object)", "low")

    def _resolve_real_methods(self, node: ast.ClassDef, seen: set[str] = None) -> set[str]:
        """Names of concretely-implemented methods on a class and its same-file bases."""
        seen = seen or set()
        if node.name in seen:
            return set()
        seen.add(node.name)
        real: set[str] = set()
        for base in node.bases:
            if isinstance(base, ast.Name) and base.id in self.class_defs:
                real |= self._resolve_real_methods(self.class_defs[base.id], seen)
        for method in self._methods(node):
            if "abstractmethod" in _decorator_names(method):
                real.discard(method.name)
            elif _body_kind(method.body) is None:
                real.add(method.name)
            else:
                real.discard(method.name)
        return real

    def _check_refused_bequest(self, node: ast.ClassDef):
        inherited: set[str] = set()
        for base in node.bases:
            if isinstance(base, ast.Name) and base.id in self.class_defs:
                inherited |= self._resolve_real_methods(self.class_defs[base.id])
        if not inherited:
            return
        for method in self._methods(node):
            if _is_dunder(method.name) or "abstractmethod" in _decorator_names(method):
                continue
            kind = _body_kind(method.body)
            if kind and method.name in inherited:
                action = "raises NotImplementedError on" if kind == "raise_nie" else "no-ops"
                self._add(method.lineno, "refused_bequest",
                    f"'{node.name}.{method.name}' {action} behavior inherited from a concrete base "
                    "— the subclass refuses its bequest",
                    "The hierarchy is off: Replace Inheritance with Delegation, or push the truly "
                    "shared part into a new superclass (Extract Superclass)", "medium")

    def _check_lazy_class(self, node: ast.ClassDef):
        if node.decorator_list or node.keywords or len(node.bases) != 1:
            return
        base = node.bases[0]
        if not isinstance(base, ast.Name):
            return
        if base.id in MARKER_BASES or base.id.endswith(("Error", "Exception", "Warning")):
            return
        if node.name.endswith(("Error", "Exception", "Warning")):
            return
        # A docstring is the documented opt-out: a deliberate marker type that
        # says what it marks has earned its keep.
        if ast.get_docstring(node):
            return
        if _body_kind(node.body) == "noop":
            self._add(node.lineno, "lazy_class",
                f"Class '{node.name}' adds nothing over '{base.id}'",
                f"Use '{base.id}' directly and delete this class (Inline Class / Collapse "
                "Hierarchy); if it is a deliberate marker type, say so in a docstring", "low")


def analyze_file(filepath: Path, ignore: set[str]) -> list[DesignSmell]:
    try:
        source = filepath.read_text(encoding='utf-8', errors='replace')
        tree = ast.parse(source, filename=str(filepath))
        lines = source.splitlines()
        is_test_file = (filepath.name.startswith("test_") or filepath.name == "conftest.py"
                        or "tests" in filepath.parts or "test" in filepath.parts)
        detector = DesignSmellDetector(str(filepath), lines, tree, ignore, is_test_file)
        detector.visit(tree)
        return detector.issues
    # Only expected per-file failures are skipped; an unexpected detector bug
    # must crash the process so analyze_all/analyze_diff report the category as
    # not-evaluated instead of falsely clean.
    except (SyntaxError, ValueError, OSError):
        return []


def find_python_files(path: Path) -> Iterator[Path]:
    if path.is_file() and path.suffix == '.py':
        yield path
    elif path.is_dir():
        for p in path.rglob('*.py'):
            if '.venv' not in p.parts and 'node_modules' not in p.parts and '__pycache__' not in p.parts:
                yield p


def main():
    parser = argparse.ArgumentParser(description="Detect classic refactoring-catalog design smells")
    parser.add_argument('path', nargs='?', default='.', help='File or directory')
    parser.add_argument('--format', choices=['text', 'json'], default='text')
    parser.add_argument('--ignore', type=str, default='',
        help='Comma-separated smells to ignore')

    args = parser.parse_args()
    ignore = set(args.ignore.split(',')) if args.ignore else set()

    all_issues = []
    for filepath in find_python_files(Path(args.path)):
        all_issues.extend(analyze_file(filepath, ignore))

    all_issues.sort(key=lambda x: (x.severity != 'high', x.severity != 'medium', x.file, x.line))

    if args.format == 'json':
        print(json.dumps([asdict(i) for i in all_issues], indent=2))
    else:
        if not all_issues:
            print("✅ No design smells found!")
            return

        by_type = defaultdict(int)
        for issue in all_issues:
            by_type[issue.smell_type] += 1

        print(f"Found {len(all_issues)} design smell(s):\n")
        print("Summary:")
        for smell, count in sorted(by_type.items(), key=lambda x: -x[1]):
            print(f"  {smell}: {count}")
        print()

        severity_icons = {'high': '🔴', 'medium': '🟡', 'low': '🟢'}
        for issue in all_issues:
            icon = severity_icons[issue.severity]
            print(f"{icon} [{issue.severity.upper()}] {issue.file}:{issue.line}")
            print(f"   {issue.smell_type}: {issue.description}")
            if issue.code_snippet:
                print(f"   Code: {issue.code_snippet}")
            print(f"   → {issue.suggestion}\n")


if __name__ == '__main__':
    main()

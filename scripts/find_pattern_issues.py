#!/usr/bin/env python3
"""
Detect design-pattern issues in both directions via AST analysis.

Direction 1 — pattern machinery Python makes unnecessary (the common case):
  handrolled_singleton       - __new__/accessor/metaclass instance-caching (use a module-level object)
  borg_shared_state          - self.__dict__ = shared class attr (Borg/Monostate)
  registry_metaclass         - metaclass that only registers subclasses (use __init_subclass__)
  getter_setter_pair         - Java-style get_x()/set_x() around a plain attribute
  handrolled_lazy_property   - if self._x is None: compute (use functools.cached_property)
  handrolled_memoize         - module-level dict used as a call cache (use functools.lru_cache)
  iterator_class             - __iter__/__next__ class a generator function replaces
  fluent_builder             - chained set_x()-returning-self builder (use keyword arguments)
  stateless_strategy_classes - sibling one-method classes with no state (use plain functions)
  finalizer_del              - __del__ for cleanup (use a context manager / weakref.finalize)

Direction 2 — a pattern (or stronger type) is missing where forces demand one:
  string_state_machine       - self.attr compared/assigned across methods as string literals
                               (use an Enum; consider State/dispatch if behavior branches)
  try_finally_close          - try/finally whose only job is .close()/.release()
                               (use with / contextlib.closing)

Complements find_overengineering.py (single-impl ABCs, one-type factories, thin
wrappers) and find_design_smells.py (type_switch → polymorphism/dispatch). Each
finding is a candidate: the judgment call — whether the forces for a pattern are
real — belongs to references/design-patterns.md.
"""

import ast
import json
import argparse
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Iterator
from collections import defaultdict


@dataclass
class PatternIssue:
    file: str
    line: int
    smell_type: str
    description: str
    suggestion: str
    severity: str
    code_snippet: str = ""


CLEANUP_METHODS = frozenset({"close", "release", "disconnect", "shutdown", "terminate"})

# Method names that mark a fluent-builder finisher.
BUILD_FINISHERS = frozenset({"build", "get_result", "result", "create", "finish"})

ABSTRACT_MARKER_BASES = frozenset({"ABC", "Protocol"})


def _strip_docstring(body: list[ast.stmt]) -> list[ast.stmt]:
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
            and isinstance(body[0].value.value, str):
        return body[1:]
    return body


def _decorator_names(node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> set[str]:
    names = set()
    for dec in node.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(target, ast.Name):
            names.add(target.id)
        elif isinstance(target, ast.Attribute):
            names.add(target.attr)
    return names


def _methods(node: ast.ClassDef) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    return [n for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


def _is_self_attr(node: ast.AST, attr: str | None = None) -> bool:
    return (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
            and node.value.id == "self" and (attr is None or node.attr == attr))


def _is_cls_attr(node: ast.AST) -> bool:
    return (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
            and node.value.id == "cls")


def _is_super_call_to(node: ast.AST, method: str) -> bool:
    """Match super().<method>(...) or super(X, cls).<method>(...)."""
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == method
            and isinstance(node.func.value, ast.Call)
            and isinstance(node.func.value.func, ast.Name)
            and node.func.value.func.id == "super")


class PatternIssueDetector(ast.NodeVisitor):
    def __init__(self, filename: str, source_lines: list[str], tree: ast.Module,
                 ignore: set[str] = None):
        self.filename = filename
        self.source_lines = source_lines
        self.issues: list[PatternIssue] = []
        self.ignore = ignore or set()
        # Module-level names bound to an empty dict — candidate hand-rolled caches.
        self.module_dicts: set[str] = set()
        for stmt in tree.body:
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 \
                    and isinstance(stmt.targets[0], ast.Name):
                value = stmt.value
                if (isinstance(value, ast.Dict) and not value.keys) or (
                        isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
                        and value.func.id == "dict" and not value.args and not value.keywords):
                    self.module_dicts.add(stmt.targets[0].id)
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
        self.issues.append(PatternIssue(
            file=self.filename, line=line, smell_type=smell_type,
            description=desc, suggestion=suggestion, severity=severity,
            code_snippet=self._get_line(line)
        ))

    def check_module(self):
        self._check_stateless_strategy_hierarchies()

    # ----------------------------------------------------------------- #
    # Classes
    # ----------------------------------------------------------------- #

    def visit_ClassDef(self, node: ast.ClassDef):
        is_metaclass = any(isinstance(b, ast.Name) and b.id == "type" for b in node.bases)
        if is_metaclass:
            self._check_singleton_metaclass(node)
            self._check_registry_metaclass(node)
        else:
            self._check_singleton_new(node)
            self._check_singleton_accessor(node)
            self._check_borg(node)
            self._check_getter_setter_pairs(node)
            self._check_lazy_properties(node)
            self._check_iterator_class(node)
            self._check_fluent_builder(node)
            self._check_finalizer(node)
            self._check_string_state_machine(node)
        self.generic_visit(node)

    # --- Singletons ---------------------------------------------------- #

    def _check_singleton_new(self, node: ast.ClassDef):
        """__new__ that caches the instance on a class attribute."""
        for method in _methods(node):
            if method.name != "__new__":
                continue
            for inner in ast.walk(method):
                if isinstance(inner, ast.Assign) \
                        and any(_is_cls_attr(t) or isinstance(t, ast.Attribute)
                                and isinstance(t.value, ast.Name) and t.value.id == node.name
                                for t in inner.targets) \
                        and _is_super_call_to(inner.value, "__new__"):
                    self._add(method.lineno, "handrolled_singleton",
                        f"'{node.name}.__new__' caches the instance on a class attribute "
                        "— a hand-rolled Singleton",
                        "A module is already a singleton: create one instance at module level "
                        "and import it (Global Object pattern). If construction must be lazy, "
                        "expose a module-level @functools.cache function instead. Hidden single "
                        "instances are global state — prefer passing the object in", "medium")
                    return

    def _check_singleton_accessor(self, node: ast.ClassDef):
        """classmethod get_instance()-style cached accessor: cls._x = cls(...)."""
        for method in _methods(node):
            if "instance" not in method.name.lower():
                continue
            if "classmethod" not in _decorator_names(method):
                continue
            for inner in ast.walk(method):
                if isinstance(inner, ast.Assign) and any(_is_cls_attr(t) for t in inner.targets) \
                        and isinstance(inner.value, ast.Call) \
                        and isinstance(inner.value.func, ast.Name) and inner.value.func.id == "cls":
                    self._add(method.lineno, "handrolled_singleton",
                        f"'{node.name}.{method.name}' is a get-instance accessor caching a "
                        "single instance — a hand-rolled Singleton",
                        "Create the instance once at module level and import it (Global Object "
                        "pattern), or use a module-level @functools.cache factory function. "
                        "Callers should receive the object, not fetch it", "medium")
                    return

    def _check_singleton_metaclass(self, node: ast.ClassDef):
        """Metaclass whose __call__ caches the result of super().__call__."""
        for method in _methods(node):
            if method.name != "__call__":
                continue
            caches = any(_is_super_call_to(inner.value, "__call__")
                         for inner in ast.walk(method)
                         if isinstance(inner, ast.Assign))
            gated = any(isinstance(inner, ast.If) for inner in ast.walk(method))
            if caches and gated:
                self._add(node.lineno, "handrolled_singleton",
                    f"Metaclass '{node.name}' caches instances in __call__ — a Singleton metaclass",
                    "A metaclass is the heaviest possible way to get one instance. Create the "
                    "instance at module level and import it (Global Object pattern)", "medium")
                return

    def _check_borg(self, node: ast.ClassDef):
        """self.__dict__ = <shared> in __init__ (Borg / Monostate)."""
        for method in _methods(node):
            if method.name != "__init__":
                continue
            for inner in ast.walk(method):
                if isinstance(inner, ast.Assign) \
                        and any(_is_self_attr(t, "__dict__") for t in inner.targets) \
                        and isinstance(inner.value, (ast.Attribute, ast.Name)):
                    self._add(inner.lineno, "borg_shared_state",
                        f"'{node.name}' shares one __dict__ across instances (Borg/Monostate)",
                        "Shared state without shared identity is still hidden global state. "
                        "A single module-level object is simpler and honest about being one thing",
                        "low")
                    return

    # --- Metaclass that only registers subclasses ----------------------- #

    def _check_registry_metaclass(self, node: ast.ClassDef):
        for method in _methods(node):
            if method.name not in ("__new__", "__init__"):
                continue
            # The registry signature is storing the *newly created class* into a
            # mapping — a metaclass that subscript-assigns other things (EnumType
            # building value maps, say) is doing real metaclass work.
            new_cls_names = {
                t.id
                for inner in ast.walk(method) if isinstance(inner, ast.Assign)
                and _is_super_call_to(inner.value, "__new__")
                for t in inner.targets if isinstance(t, ast.Name)
            }
            if method.name == "__init__":
                new_cls_names.add(method.args.args[0].arg if method.args.args else "cls")
            if any(isinstance(inner, ast.Assign)
                   and any(isinstance(t, ast.Subscript) for t in inner.targets)
                   and isinstance(inner.value, ast.Name) and inner.value.id in new_cls_names
                   for inner in ast.walk(method)):
                self._add(node.lineno, "registry_metaclass",
                    f"Metaclass '{node.name}' writes new classes into a registry",
                    "Use __init_subclass__ on the base class for subclass registration — "
                    "same effect, no metaclass, composes with other bases", "low")
                return

    # --- Java-style accessors ------------------------------------------- #

    def _check_getter_setter_pairs(self, node: ast.ClassDef):
        getters: dict[str, ast.FunctionDef] = {}
        setters: dict[str, ast.FunctionDef] = {}
        properties = {m.name for m in _methods(node)
                      if _decorator_names(m) & {"property", "cached_property", "setter"}}
        for method in _methods(node):
            if _decorator_names(method):
                continue
            body = _strip_docstring(method.body)
            args = method.args.posonlyargs + method.args.args
            if method.name.startswith("get_") and len(args) == 1 and len(body) == 1 \
                    and isinstance(body[0], ast.Return) and _is_self_attr(body[0].value):
                getters[method.name[4:]] = method
            if method.name.startswith("set_") and len(args) == 2 and len(body) == 1 \
                    and isinstance(body[0], ast.Assign) and len(body[0].targets) == 1 \
                    and _is_self_attr(body[0].targets[0]) \
                    and isinstance(body[0].value, ast.Name) \
                    and body[0].value.id == args[1].arg:
                setters[method.name[4:]] = method
        for name in sorted(getters.keys() & setters.keys()):
            if name in properties:
                continue
            self._add(getters[name].lineno, "getter_setter_pair",
                f"'{node.name}' has Java-style accessors get_{name}/set_{name} around a plain attribute",
                "Expose the attribute directly — Python is not Java; @property exists for the "
                "day logic is needed, with no caller changes", "medium")

    # --- Lazy property → functools.cached_property ----------------------- #

    def _check_lazy_properties(self, node: ast.ClassDef):
        for method in _methods(node):
            if "property" not in _decorator_names(method):
                continue
            body = _strip_docstring(method.body)
            if len(body) != 2 or not isinstance(body[0], ast.If) or body[0].orelse \
                    or not isinstance(body[1], ast.Return):
                continue
            attr = self._none_check_attr(body[0].test)
            if attr is None or not _is_self_attr(body[1].value, attr):
                continue
            assigns = [s for s in body[0].body if isinstance(s, ast.Assign)]
            if any(any(_is_self_attr(t, attr) for t in a.targets) for a in assigns):
                self._add(method.lineno, "handrolled_lazy_property",
                    f"'{node.name}.{method.name}' is a hand-rolled lazy property "
                    f"(None-check on self.{attr})",
                    "Use @functools.cached_property — same laziness, one decorator, "
                    "no sentinel field", "low")

    @staticmethod
    def _none_check_attr(test: ast.expr) -> str | None:
        """Return attr name for `self.<attr> is None` / `not hasattr(self, '<attr>')`."""
        if isinstance(test, ast.Compare) and len(test.ops) == 1 \
                and isinstance(test.ops[0], ast.Is) \
                and isinstance(test.comparators[0], ast.Constant) \
                and test.comparators[0].value is None and _is_self_attr(test.left):
            return test.left.attr
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not) \
                and isinstance(test.operand, ast.Call) \
                and isinstance(test.operand.func, ast.Name) \
                and test.operand.func.id == "hasattr" and len(test.operand.args) == 2 \
                and isinstance(test.operand.args[0], ast.Name) \
                and test.operand.args[0].id == "self" \
                and isinstance(test.operand.args[1], ast.Constant):
            return test.operand.args[1].value
        return None

    # --- Iterator class → generator -------------------------------------- #

    def _check_iterator_class(self, node: ast.ClassDef):
        methods = {m.name: m for m in _methods(node)}
        if "__next__" not in methods or "__iter__" not in methods:
            return
        iter_body = _strip_docstring(methods["__iter__"].body)
        if len(iter_body) == 1 and isinstance(iter_body[0], ast.Return) \
                and isinstance(iter_body[0].value, ast.Name) and iter_body[0].value.id == "self":
            self._add(node.lineno, "iterator_class",
                f"'{node.name}' is a hand-rolled iterator class (__iter__ returning self, "
                "__next__ tracking position)",
                "A generator function (yield) implements the Iterator pattern in a few lines — "
                "the language keeps the position for you. Keep a class only if callers need "
                "to inspect or rewind mid-iteration state", "low")

    # --- Fluent builder → keyword arguments ------------------------------- #

    def _check_fluent_builder(self, node: ast.ClassDef):
        chained = []
        has_finisher = False
        for method in _methods(node):
            if method.name in BUILD_FINISHERS:
                has_finisher = True
            body = _strip_docstring(method.body)
            if not body or not isinstance(body[-1], ast.Return):
                continue
            ret = body[-1].value
            if not (isinstance(ret, ast.Name) and ret.id == "self"):
                continue
            if any(isinstance(s, ast.Assign) and any(_is_self_attr(t) for t in s.targets)
                   for s in body):
                chained.append(method)
        if len(chained) >= 3 and has_finisher:
            self._add(node.lineno, "fluent_builder",
                f"'{node.name}' is a fluent Builder: {len(chained)} chained setters plus a "
                "finisher method",
                "Keyword arguments (with defaults) or a dataclass replace most Builders in "
                "Python — construction in one call, validation in __post_init__. Keep a builder "
                "only for genuinely staged construction where partial states are meaningful",
                "low")

    # --- __del__ as destructor -------------------------------------------- #

    def _check_finalizer(self, node: ast.ClassDef):
        for method in _methods(node):
            if method.name == "__del__" and _strip_docstring(method.body):
                if all(isinstance(s, ast.Pass) for s in _strip_docstring(method.body)):
                    continue
                self._add(method.lineno, "finalizer_del",
                    f"'{node.name}.__del__' is used for cleanup",
                    "__del__ runs at unpredictable times (or never, on interpreter exit/cycles). "
                    "Make the class a context manager (__enter__/__exit__) or use "
                    "weakref.finalize so cleanup is deterministic", "medium")
                return

    # --- String-typed state machine ----------------------------------------- #

    def _check_string_state_machine(self, node: ast.ClassDef):
        compare_methods: dict[str, set[str]] = defaultdict(set)
        values: dict[str, set[str]] = defaultdict(set)
        transition_assigns: dict[str, int] = defaultdict(int)
        first_line: dict[str, int] = {}
        for method in _methods(node):
            for inner in ast.walk(method):
                if isinstance(inner, ast.Compare) and len(inner.ops) == 1 \
                        and isinstance(inner.ops[0], (ast.Eq, ast.NotEq)) \
                        and _is_self_attr(inner.left) \
                        and isinstance(inner.comparators[0], ast.Constant) \
                        and isinstance(inner.comparators[0].value, str):
                    attr = inner.left.attr
                    compare_methods[attr].add(method.name)
                    values[attr].add(inner.comparators[0].value)
                    first_line.setdefault(attr, inner.lineno)
                if isinstance(inner, ast.Assign) and isinstance(inner.value, ast.Constant) \
                        and isinstance(inner.value.value, str):
                    for target in inner.targets:
                        if _is_self_attr(target):
                            values[target.attr].add(inner.value.value)
                            if method.name != "__init__":
                                transition_assigns[target.attr] += 1
        for attr, methods in compare_methods.items():
            if len(methods) >= 2 and len(values[attr]) >= 3 and transition_assigns[attr] >= 1:
                self._add(first_line[attr], "string_state_machine",
                    f"'self.{attr}' is a string-typed state machine: {len(values[attr])} "
                    f"states compared in {len(methods)} methods and reassigned at runtime",
                    "At minimum make the states an Enum (typo-proof, exhaustiveness-checkable). "
                    "If behavior branches on the state in several methods, dispatch on it — "
                    "a dict keyed by state or the State pattern — so a new state is an entry, "
                    "not another elif", "medium")

    # ----------------------------------------------------------------- #
    # Stateless single-method hierarchies (module-level pass)
    # ----------------------------------------------------------------- #

    def _check_stateless_strategy_hierarchies(self):
        by_base: dict[str, list[ast.ClassDef]] = defaultdict(list)
        for cls in self.class_defs.values():
            if len(cls.bases) == 1 and isinstance(cls.bases[0], ast.Name) \
                    and cls.bases[0].id in self.class_defs:
                by_base[cls.bases[0].id].append(cls)
        for base_name, subclasses in by_base.items():
            if len(subclasses) < 2:
                continue
            method_names = set()
            ok = True
            for cls in subclasses:
                body = _strip_docstring(cls.body)
                if len(body) != 1 or not isinstance(body[0], ast.FunctionDef) \
                        or body[0].name.startswith("_"):
                    ok = False
                    break
                method_names.add(body[0].name)
            if not ok or len(method_names) != 1:
                continue
            method = next(iter(method_names))
            base = self.class_defs[base_name]
            base_extra = [s for s in _strip_docstring(base.body)
                          if not (isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef))
                                  and s.name == method)
                          and not isinstance(s, ast.Pass)]
            if base_extra:
                continue
            self._add(base.lineno, "stateless_strategy_classes",
                f"{len(subclasses)} stateless subclasses of '{base_name}' each implement only "
                f"'{method}' — a class hierarchy standing in for functions",
                "Functions are first-class in Python: replace each class with a plain function "
                "and select via a dispatch dict (or pass the callable directly). Keep classes "
                "only when strategies carry configuration or state", "medium")


def analyze_file(filepath: Path, ignore: set[str]) -> list[PatternIssue]:
    try:
        source = filepath.read_text(encoding='utf-8', errors='replace')
        tree = ast.parse(source, filename=str(filepath))
        lines = source.splitlines()
        detector = PatternIssueDetector(str(filepath), lines, tree, ignore)
        detector.visit(tree)
        detector.check_module()
        detector.issues.extend(_function_level_checks(filepath, tree, lines, detector))
        return detector.issues
    # Only expected per-file failures are skipped; an unexpected detector bug
    # must crash so the aggregators report the category as not-evaluated.
    except (SyntaxError, ValueError, OSError):
        return []


def _function_level_checks(filepath: Path, tree: ast.Module, lines: list[str],
                           detector: PatternIssueDetector) -> list[PatternIssue]:
    issues: list[PatternIssue] = []

    def get_line(lineno: int) -> str:
        return lines[lineno - 1].strip()[:60] if 0 < lineno <= len(lines) else ""

    def add(line: int, smell_type: str, desc: str, suggestion: str, severity: str):
        if smell_type not in detector.ignore:
            issues.append(PatternIssue(str(filepath), line, smell_type, desc,
                                       suggestion, severity, get_line(line)))

    # handrolled_memoize: function that gates on / reads / writes a module-level dict
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for cache in detector.module_dicts:
                gates = reads = writes = False
                for inner in ast.walk(node):
                    if isinstance(inner, ast.Compare) and len(inner.ops) == 1 \
                            and isinstance(inner.ops[0], (ast.In, ast.NotIn)) \
                            and isinstance(inner.comparators[0], ast.Name) \
                            and inner.comparators[0].id == cache:
                        gates = True
                    if isinstance(inner, ast.Subscript) and isinstance(inner.value, ast.Name) \
                            and inner.value.id == cache:
                        if isinstance(inner.ctx, ast.Load):
                            reads = True
                        elif isinstance(inner.ctx, ast.Store):
                            writes = True
                if gates and reads and writes:
                    add(node.lineno, "handrolled_memoize",
                        f"'{node.name}' hand-rolls memoization through module-level dict '{cache}'",
                        "Use @functools.lru_cache (or @functools.cache) if the function is pure "
                        "and its arguments hashable — it also gives you cache_clear() and stats. "
                        "The module dict is hidden global state", "low")
                    break

        # try_finally_close: a finally whose only job is releasing one resource
        if isinstance(node, ast.Try) and len(node.finalbody) == 1:
            stmt = node.finalbody[0]
            # self.release()-style internal lifecycle management is not a drop-in
            # `with` candidate — only flag cleanup of a separate object.
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call) \
                    and isinstance(stmt.value.func, ast.Attribute) \
                    and stmt.value.func.attr in CLEANUP_METHODS \
                    and not stmt.value.args and not stmt.value.keywords \
                    and not (isinstance(stmt.value.func.value, ast.Name)
                             and stmt.value.func.value.id in ("self", "cls")):
                add(node.lineno, "try_finally_close",
                    f"try/finally exists only to call .{stmt.value.func.attr}()",
                    "Use a with block — the object is probably already a context manager; "
                    "if not, wrap it in contextlib.closing(). The cleanup then cannot be "
                    "forgotten on the next edit", "low")

    return issues


def find_python_files(path: Path) -> Iterator[Path]:
    if path.is_file() and path.suffix == '.py':
        yield path
    elif path.is_dir():
        for p in path.rglob('*.py'):
            if '.venv' not in p.parts and 'node_modules' not in p.parts and '__pycache__' not in p.parts:
                yield p


def main():
    parser = argparse.ArgumentParser(
        description="Detect design-pattern issues: hand-rolled machinery Python provides, "
                    "and missing patterns where forces demand one")
    parser.add_argument('path', nargs='?', default='.', help='File or directory')
    parser.add_argument('--format', choices=['text', 'json'], default='text')
    parser.add_argument('--ignore', type=str, default='',
        help='Comma-separated smell types to ignore')

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
            print("✅ No design-pattern issues found!")
            return

        by_type = defaultdict(int)
        for issue in all_issues:
            by_type[issue.smell_type] += 1

        print(f"Found {len(all_issues)} design-pattern issue(s):\n")
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

"""Smoke tests: every detector fires on a known-bad fixture and stays quiet on clean code.

These are characterization tests for the detectors themselves — the safety net the
skill tells everyone else to build first. Fixtures are written to tmp_path at runtime
(not committed) so the intentionally-bad code never trips the linters or the
detectors' own path-based skip rules (e.g. files under a "tests" segment).
"""

import ast
import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"


def run_detector(script: str, target: Path, *extra: str) -> list[dict]:
    result = subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / script), str(target), "--format", "json", *extra],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"{script} exited {result.returncode}: {result.stderr[:500]}"
    return json.loads(result.stdout)


def smell_types(findings: list[dict]) -> set[str]:
    return {f["smell_type"] for f in findings}


# (detector script, {relative path: file content}, smell types that must fire)
CASES = [
    (
        "find_debug_leftovers.py",
        {"sample.py": "import pdb\n\ndef f():\n    pdb.set_trace()\n    breakpoint()\n"},
        {"pdb_trace", "breakpoint_call"},
    ),
    (
        "find_resource_leaks.py",
        {"sample.py": "def f(p):\n    handle = open(p)\n    return handle.read()\n"},
        {"unmanaged_open"},
    ),
    (
        "find_security_issues.py",
        {
            "sample.py": (
                "import subprocess\n"
                "password = 'hunter2secret'\n"
                "def f(x, d):\n"
                "    eval(x)\n"
                "    subprocess.run(f'ls {d}', shell=True)\n"
                "    cursor.execute(f'select * from t where id={x}')\n"
            )
        },
        {"eval_exec", "command_injection", "sql_injection", "hardcoded_secret"},
    ),
    (
        "find_exception_issues.py",
        {
            "sample.py": (
                "def f():\n"
                "    try:\n"
                "        g()\n"
                "    except Exception:\n"
                "        pass\n"
                "    try:\n"
                "        g()\n"
                "    except KeyError:\n"
                "        raise RuntimeError('boom')\n"
            )
        },
        {"swallowed_exception", "raise_without_from"},
    ),
    (
        "find_global_state.py",
        {"sample.py": "CACHE = {}\n\ndef put(k, v):\n    CACHE[k] = v\n"},
        {"mutated_global"},
    ),
    (
        "find_ai_scaffolding.py",
        {
            "sample.py": (
                "API_KEY = 'your-api-key'\n"
                "# TODO: implement the parser\n"
                "def f():\n"
                "    raise NotImplementedError\n"
                "def g(a, **kwargs):\n"
                "    return a + 1\n"
            )
        },
        {"placeholder_value", "todo_implement", "stub_not_implemented", "unused_kwargs"},
    ),
    (
        "find_duplicate_definitions.py",
        {"sample.py": "def f():\n    return 1\n\ndef f():\n    return 2\n"},
        {"duplicate_definition"},
    ),
    (
        "find_duplicate_definitions.py",
        {"conflicted.py": "<<<<<<< HEAD\nx = 1\n=======\nx = 2\n>>>>>>> branch\n"},
        {"merge_conflict_marker"},
    ),
    (
        "find_unawaited_coroutines.py",
        {"sample.py": "async def work():\n    return 1\n\ndef main():\n    work()\n"},
        {"unawaited_coroutine"},
    ),
    (
        "find_local_imports.py",
        {"sample.py": "x = 1\nimport os\n\ndef f():\n    import re\n    return re, os\n"},
        {"local_import", "import_not_at_top"},
    ),
    (
        "find_redundant_comments.py",
        {"sample.py": "def f(count):\n    # increment count\n    count += 1\n    return count\n"},
        {"redundant_comment"},
    ),
    (
        "find_outdated_idioms.py",
        {
            "sample.py": (
                "import os\n"
                "def f(name, d):\n"
                "    a = '%s!' % name\n"
                "    b = '{}!'.format(name)\n"
                "    return a, b, os.path.join(d, 'x')\n"
            )
        },
        {"percent_format", "str_format_call", "os_path_join"},
    ),
    (
        "find_missing_docstrings.py",
        {"sample.py": "def visible(a):\n    b = a + 1\n    c = b * 2\n    return c\n"},
        {"public_function_no_docstring"},
    ),
    (
        "find_type_gaps.py",
        {
            "sample.py": (
                "from typing import Any\n"
                "def f(a):\n"
                "    return a\n"
                "def g(b: Any) -> Any:\n"
                "    return b\n"
                "x = 1  # type: ignore\n"
            )
        },
        {"missing_return_annotation", "missing_param_annotation", "any_overuse", "broad_type_ignore"},
    ),
    (
        "find_test_smells.py",
        {
            "test_sample.py": (
                "def test_nothing():\n"
                "    x = 1\n"
                "def test_trivial():\n"
                "    assert True\n"
            )
        },
        {"test_without_assertion", "trivial_assertion"},
    ),
    (
        "find_untested_modules.py",
        {"sample.py": "def thing():\n    return 1\n"},
        {"no_tests_in_repo"},
    ),
    (
        "find_import_cycles.py",
        {
            "pkg/__init__.py": "",
            "pkg/a.py": "from pkg import b\n",
            "pkg/b.py": "from pkg import a\n",
            "pkg/c.py": "from os import *\n",
        },
        {"circular_import", "wildcard_import"},
    ),
    (
        "find_dependency_issues.py",
        {
            "requirements.txt": "leftpadpy\n",
            "main.py": "import requests\n\ndef f():\n    return requests\n",
        },
        {"missing_dependency", "unpinned_dependency"},
    ),
    (
        "find_design_smells.py",
        {
            "sample.py": (
                "def dispatch(kind, other):\n"
                "    print(other._secret)\n"
                "    if kind == 'a':\n"
                "        out = 1\n"
                "        log()\n"
                "    elif kind == 'b':\n"
                "        out = 2\n"
                "        log()\n"
                "    elif kind == 'c':\n"
                "        out = 3\n"
                "        log()\n"
                "    elif kind == 'd':\n"
                "        out = 4\n"
                "        log()\n"
                "    else:\n"
                "        out = 5\n"
                "        log()\n"
                "    return out\n"
                "\n"
                "def wait(jobs):\n"
                "    done = False\n"
                "    while not done:\n"
                "        if not jobs:\n"
                "            done = True\n"
            )
        },
        {"type_switch", "duplicate_conditional_fragment", "control_flag", "inappropriate_intimacy"},
    ),
    (
        "find_design_smells.py",
        {
            "sample.py": (
                "class Base:\n"
                "    def render(self):\n"
                "        return 'base'\n"
                "\n"
                "class Child(Base):\n"
                "    def __init__(self):\n"
                "        self.scratch = None\n"
                "        self.kept = 1\n"
                "\n"
                "    def render(self):\n"
                "        raise NotImplementedError\n"
                "\n"
                "    def only_user(self):\n"
                "        self.scratch = object()\n"
                "        return self.scratch\n"
                "\n"
                "class Echo(Child):\n"
                "    pass\n"
            )
        },
        {"refused_bequest", "temporary_field", "lazy_class"},
    ),
    (
        "find_pattern_issues.py",
        {
            "sample.py": (
                "_CACHE = {}\n"
                "\n"
                "def slow(x):\n"
                "    if x in _CACHE:\n"
                "        return _CACHE[x]\n"
                "    _CACHE[x] = x * 2\n"
                "    return _CACHE[x]\n"
                "\n"
                "class Config:\n"
                "    _instance = None\n"
                "    def __new__(cls):\n"
                "        if cls._instance is None:\n"
                "            cls._instance = super().__new__(cls)\n"
                "        return cls._instance\n"
                "\n"
                "class Borg:\n"
                "    _shared = {}\n"
                "    def __init__(self):\n"
                "        self.__dict__ = self._shared\n"
                "\n"
                "class RegistryMeta(type):\n"
                "    REGISTRY = {}\n"
                "    def __new__(mcs, name, bases, ns):\n"
                "        new_cls = super().__new__(mcs, name, bases, ns)\n"
                "        mcs.REGISTRY[name] = new_cls\n"
                "        return new_cls\n"
                "\n"
                "class Person:\n"
                "    def get_name(self):\n"
                "        return self._name\n"
                "    def set_name(self, value):\n"
                "        self._name = value\n"
                "    @property\n"
                "    def conn(self):\n"
                "        if self._conn is None:\n"
                "            self._conn = object()\n"
                "        return self._conn\n"
            )
        },
        {"handrolled_memoize", "handrolled_singleton", "borg_shared_state",
         "registry_metaclass", "getter_setter_pair", "handrolled_lazy_property"},
    ),
    (
        "find_pattern_issues.py",
        {
            "sample.py": (
                "class CountUp:\n"
                "    def __iter__(self):\n"
                "        return self\n"
                "    def __next__(self):\n"
                "        self.i += 1\n"
                "        return self.i\n"
                "\n"
                "class QueryBuilder:\n"
                "    def set_table(self, t):\n"
                "        self.table = t\n"
                "        return self\n"
                "    def set_cols(self, c):\n"
                "        self.cols = c\n"
                "        return self\n"
                "    def set_limit(self, n):\n"
                "        self.limit = n\n"
                "        return self\n"
                "    def build(self):\n"
                "        return (self.table, self.cols, self.limit)\n"
                "\n"
                "class Conn:\n"
                "    def __del__(self):\n"
                "        self.sock.close()\n"
                "\n"
                "class Order:\n"
                "    def pay(self):\n"
                "        if self.status == 'new':\n"
                "            self.status = 'paid'\n"
                "    def ship(self):\n"
                "        if self.status == 'paid':\n"
                "            self.status = 'shipped'\n"
                "    def cancel(self):\n"
                "        if self.status == 'shipped':\n"
                "            raise ValueError\n"
                "        self.status = 'cancelled'\n"
                "\n"
                "class Discount:\n"
                "    def apply(self, order):\n"
                "        raise NotImplementedError\n"
                "\n"
                "class TenPercent(Discount):\n"
                "    def apply(self, order):\n"
                "        return order * 0.9\n"
                "\n"
                "class OnSale(Discount):\n"
                "    def apply(self, order):\n"
                "        return order * 0.5\n"
                "\n"
                "def read(f):\n"
                "    try:\n"
                "        return f.read()\n"
                "    finally:\n"
                "        f.close()\n"
            )
        },
        {"iterator_class", "fluent_builder", "finalizer_del",
         "string_state_machine", "stateless_strategy_classes", "try_finally_close"},
    ),
]


@pytest.mark.parametrize(
    "script,files,expected", CASES, ids=[f"{c[0]}:{'+'.join(sorted(c[2]))}" for c in CASES]
)
def test_detector_fires_on_known_bad_fixture(tmp_path, script, files, expected):
    for rel, content in files.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    found = smell_types(run_detector(script, tmp_path))
    missing = expected - found
    assert not missing, f"{script} did not report {missing}; reported {found or '{}'}"


CLEAN_CODE = '''"""A clean module."""


def add(first: int, second: int) -> int:
    """Add two integers."""
    return first + second
'''

QUIET_ON_CLEAN = [
    "find_debug_leftovers.py",
    "find_resource_leaks.py",
    "find_security_issues.py",
    "find_exception_issues.py",
    "find_global_state.py",
    "find_ai_scaffolding.py",
    "find_duplicate_definitions.py",
    "find_unawaited_coroutines.py",
    "find_local_imports.py",
    "find_redundant_comments.py",
    "find_outdated_idioms.py",
    "find_missing_docstrings.py",
    "find_type_gaps.py",
    "find_test_smells.py",
    "find_design_smells.py",
    "find_pattern_issues.py",
]


@pytest.mark.parametrize("script", QUIET_ON_CLEAN)
def test_detector_quiet_on_clean_code(tmp_path, script):
    (tmp_path / "sample.py").write_text(CLEAN_CODE)
    findings = run_detector(script, tmp_path)
    assert findings == [], f"{script} false-positives on clean code: {smell_types(findings)}"


def test_ignore_flag_suppresses_smell_type(tmp_path):
    (tmp_path / "sample.py").write_text("def f(x):\n    return eval(x)\n")
    assert "eval_exec" in smell_types(run_detector("find_security_issues.py", tmp_path))
    suppressed = run_detector("find_security_issues.py", tmp_path, "--ignore", "eval_exec")
    assert "eval_exec" not in smell_types(suppressed)


def test_analyze_all_aggregates_and_is_valid_json(tmp_path):
    (tmp_path / "sample.py").write_text("def f(x):\n    return eval(x)\n")
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPTS_DIR / "analyze_all.py"),
            str(tmp_path),
            "--format",
            "json",
            "--skip-duplicates",
        ],
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert result.returncode == 0, result.stderr[:500]
    report = json.loads(result.stdout)
    assert {"meta", "summary", "categories"} <= report.keys()
    assert report["summary"]["by_category"].get("security", 0) >= 1


def test_every_script_parses():
    scripts = sorted(SCRIPTS_DIR.glob("*.py"))
    assert len(scripts) >= 30
    for script in scripts:
        ast.parse(script.read_text(encoding="utf-8"), filename=str(script))


# --------------------------------------------------------------------------- #
# Regression tests for review findings (each pins a fixed false pos/neg)
# --------------------------------------------------------------------------- #


def test_cross_kind_duplicate_definition_is_flagged(tmp_path):
    (tmp_path / "sample.py").write_text("def thing():\n    return 1\n\nclass thing:\n    pass\n")
    assert "duplicate_definition" in smell_types(run_detector("find_duplicate_definitions.py", tmp_path))


def test_subprocess_without_shell_is_not_command_injection(tmp_path):
    (tmp_path / "sample.py").write_text(
        "import subprocess\n\ndef f(name):\n    subprocess.run(f'tool-{name}')\n"
    )
    assert "command_injection" not in smell_types(run_detector("find_security_issues.py", tmp_path))


def test_open_closed_in_finally_is_not_a_leak(tmp_path):
    (tmp_path / "sample.py").write_text(
        "def f(p):\n"
        "    handle = open(p)\n"
        "    try:\n"
        "        return handle.read()\n"
        "    finally:\n"
        "        handle.close()\n"
    )
    assert "unmanaged_open" not in smell_types(run_detector("find_resource_leaks.py", tmp_path))


def test_assert_in_nested_helper_does_not_count_as_test_assertion(tmp_path):
    (tmp_path / "test_sample.py").write_text(
        "def test_a():\n"
        "    def helper():\n"
        "        assert False\n"
        "    helper()\n"
    )
    assert "test_without_assertion" in smell_types(run_detector("find_test_smells.py", tmp_path))


def test_sync_method_sharing_name_with_async_function_not_flagged(tmp_path):
    (tmp_path / "sample.py").write_text(
        "async def fetch():\n"
        "    return 1\n"
        "\n"
        "class Cache:\n"
        "    def fetch(self):\n"
        "        return 2\n"
        "\n"
        "def main():\n"
        "    Cache().fetch()\n"
    )
    assert "unawaited_coroutine" not in smell_types(run_detector("find_unawaited_coroutines.py", tmp_path))


def test_import_cycle_detected_in_src_layout(tmp_path):
    pkg = tmp_path / "src" / "pkg"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    (pkg / "a.py").write_text("from pkg import b\n")
    (pkg / "b.py").write_text("from pkg import a\n")
    assert "circular_import" in smell_types(run_detector("find_import_cycles.py", tmp_path))


def test_empty_manifest_yields_missing_dependency_not_no_manifest(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\nversion = "0"\ndependencies = []\n')
    (tmp_path / "main.py").write_text("import requests\n\ndef f():\n    return requests\n")
    found = smell_types(run_detector("find_dependency_issues.py", tmp_path))
    assert "missing_dependency" in found
    assert "no_dependency_manifest" not in found


def test_dotted_test_import_does_not_bless_same_stem_module(tmp_path):
    for pkg in ("pkg1", "pkg2"):
        d = tmp_path / pkg
        d.mkdir()
        (d / "__init__.py").write_text("")
        (d / "util.py").write_text("def helper():\n    return 1\n")
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_u.py").write_text("from pkg1 import util\n\ndef test_x():\n    assert util.helper() == 1\n")
    findings = run_detector("find_untested_modules.py", tmp_path)
    untested_files = {f["file"] for f in findings if f["smell_type"] == "untested_module"}
    assert any(f.endswith("pkg2/util.py") for f in untested_files)
    assert not any(f.endswith("pkg1/util.py") for f in untested_files)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.email=t@t.co", "-c", "user.name=t", "-c", "commit.gpgsign=false", *args],
        cwd=repo, check=True, capture_output=True, text=True,
    )


def test_analyze_diff_rejects_invalid_base_ref(tmp_path):
    _git(tmp_path, "init", "-q")
    result = subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "analyze_diff.py"), "no-such-ref"],
        cwd=tmp_path, capture_output=True, text=True, timeout=60,
    )
    assert result.returncode != 0
    assert "does not resolve" in result.stderr


def test_analyze_diff_retains_findings_anchored_at_changed_definition(tmp_path):
    _git(tmp_path, "init", "-q")
    target = tmp_path / "mod.py"
    target.write_text("def f(x):\n    return x\n")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "base")
    # Change only the body; the missing-annotation finding anchors at the def line.
    target.write_text("def f(x):\n    return x + 1\n")
    result = subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "analyze_diff.py"), "HEAD", "--format", "json"],
        cwd=tmp_path, capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stderr[:500]
    found = {f["smell_type"] for f in json.loads(result.stdout)}
    assert "missing_return_annotation" in found


# --------------------------------------------------------------------------- #
# Regression tests for the second review round
# --------------------------------------------------------------------------- #


def test_conditional_close_is_still_a_leak(tmp_path):
    (tmp_path / "sample.py").write_text(
        "def f(p, ok):\n"
        "    handle = open(p)\n"
        "    if ok:\n"
        "        handle.close()\n"
        "    return ok\n"
    )
    assert "unmanaged_open" in smell_types(run_detector("find_resource_leaks.py", tmp_path))


def test_unconditional_close_is_not_a_leak(tmp_path):
    (tmp_path / "sample.py").write_text(
        "def f(p):\n"
        "    handle = open(p)\n"
        "    data = handle.read()\n"
        "    handle.close()\n"
        "    return data\n"
    )
    assert "unmanaged_open" not in smell_types(run_detector("find_resource_leaks.py", tmp_path))


def test_yaml_load_with_positional_safe_loader_not_flagged(tmp_path):
    (tmp_path / "sample.py").write_text(
        "import yaml\n\ndef f(x):\n    a = yaml.load(x)\n    b = yaml.load(x, yaml.SafeLoader)\n    return a, b\n"
    )
    findings = [f for f in run_detector("find_security_issues.py", tmp_path) if f["smell_type"] == "unsafe_yaml"]
    assert len(findings) == 1 and findings[0]["line"] == 4


def test_weak_hash_usedforsecurity_false_not_flagged(tmp_path):
    (tmp_path / "sample.py").write_text(
        "import hashlib\n\ndef f(b):\n    return hashlib.md5(b, usedforsecurity=False).hexdigest()\n"
    )
    assert "weak_hash" not in smell_types(run_detector("find_security_issues.py", tmp_path))


def test_verify_false_only_flagged_on_http_apis(tmp_path):
    (tmp_path / "sample.py").write_text(
        "import requests\n"
        "\n"
        "def f(url, v):\n"
        "    check_result(v, verify=False)\n"
        "    return requests.get(url, verify=False)\n"
    )
    findings = [f for f in run_detector("find_security_issues.py", tmp_path) if f["smell_type"] == "tls_verify_disabled"]
    assert len(findings) == 1 and findings[0]["line"] == 5


def test_pytest_approx_alone_is_not_an_assertion(tmp_path):
    (tmp_path / "test_sample.py").write_text(
        "import pytest\n\ndef test_x(actual):\n    pytest.approx(actual)\n"
    )
    assert "test_without_assertion" in smell_types(run_detector("find_test_smells.py", tmp_path))


def test_src_layout_local_package_is_not_missing_dependency(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\nversion = "0"\ndependencies = []\n')
    pkg = tmp_path / "src" / "pkg"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    (pkg / "a.py").write_text("from pkg import b\n")
    (pkg / "b.py").write_text("x = 1\n")
    missing = {f["description"] for f in run_detector("find_dependency_issues.py", tmp_path)
               if f["smell_type"] == "missing_dependency"}
    assert not any("pkg" in d.split("'")[1] for d in missing if "'" in d), missing


def test_plain_def_after_property_group_is_flagged(tmp_path):
    (tmp_path / "sample.py").write_text(
        "class C:\n"
        "    @property\n"
        "    def x(self):\n"
        "        return self._x\n"
        "    @x.setter\n"
        "    def x(self, v):\n"
        "        self._x = v\n"
        "    def x(self):\n"
        "        return 1\n"
    )
    assert "duplicate_definition" in smell_types(run_detector("find_duplicate_definitions.py", tmp_path))


def test_overload_set_with_implementation_not_flagged(tmp_path):
    (tmp_path / "sample.py").write_text(
        "from typing import overload\n"
        "\n"
        "@overload\n"
        "def f(x: int) -> int: ...\n"
        "@overload\n"
        "def f(x: str) -> str: ...\n"
        "def f(x):\n"
        "    return x\n"
    )
    assert "duplicate_definition" not in smell_types(run_detector("find_duplicate_definitions.py", tmp_path))


def test_nested_stub_in_abstract_class_is_flagged(tmp_path):
    (tmp_path / "sample.py").write_text(
        "from abc import ABC, abstractmethod\n"
        "\n"
        "class C(ABC):\n"
        "    @abstractmethod\n"
        "    def m(self): ...\n"
        "    def concrete(self):\n"
        "        def helper():\n"
        "            pass\n"
        "        return helper\n"
    )
    found = smell_types(run_detector("find_ai_scaffolding.py", tmp_path))
    assert "empty_stub" in found


def test_docstring_with_example_url_is_not_a_placeholder(tmp_path):
    (tmp_path / "sample.py").write_text(
        '"""See https://example.com/docs for details."""\n'
        "\n"
        "def f() -> int:\n"
        '    """Compute. See https://example.com/docs."""\n'
        "    return 1\n"
    )
    assert "placeholder_value" not in smell_types(run_detector("find_ai_scaffolding.py", tmp_path))


def test_design_smells_skip_idiomatic_patterns(tmp_path):
    """Lazy-init property, dunder privates, namedtuple API, imported modules,
    exception subclasses and short ladders are idioms, not smells."""
    (tmp_path / "sample.py").write_text(
        "import os\n"
        "from collections import namedtuple\n"
        "\n"
        "Point = namedtuple('Point', 'x y')\n"
        "\n"
        "class Config:\n"
        "    def __init__(self):\n"
        "        self._cache = None\n"
        "\n"
        "    @property\n"
        "    def cache(self):\n"
        "        if self._cache is None:\n"
        "            self._cache = os.environ.get('X')\n"
        "        return self._cache\n"
        "\n"
        "    def __eq__(self, other):\n"
        "        return self._cache == other._cache\n"
        "\n"
        "class MyError(ValueError):\n"
        "    pass\n"
        "\n"
        "def move(p):\n"
        "    os._exit\n"
        "    return p._replace(x=p.x + 1)\n"
        "\n"
        "def two_way(kind):\n"
        "    if kind == 'a':\n"
        "        return 1\n"
        "    elif kind == 'b':\n"
        "        return 2\n"
        "    return 3\n"
    )
    assert smell_types(run_detector("find_design_smells.py", tmp_path)) == set()


def test_ladder_on_mixed_subjects_is_not_a_type_switch(tmp_path):
    (tmp_path / "sample.py").write_text(
        "def f(kind, size, mode, flag):\n"
        "    if kind == 'a':\n"
        "        return 1\n"
        "    elif size == 2:\n"
        "        return 2\n"
        "    elif mode == 'x':\n"
        "        return 3\n"
        "    elif flag == 'y':\n"
        "        return 4\n"
        "    else:\n"
        "        return 5\n"
    )
    assert "type_switch" not in smell_types(run_detector("find_design_smells.py", tmp_path))


def test_flag_assigned_only_in_nested_scope_is_not_a_control_flag(tmp_path):
    (tmp_path / "sample.py").write_text(
        "def wait(register):\n"
        "    done = False\n"
        "    while not done:\n"
        "        def callback():\n"
        "            done = True\n"
        "        register(callback)\n"
    )
    assert "control_flag" not in smell_types(run_detector("find_design_smells.py", tmp_path))


def test_documented_marker_subclass_is_not_lazy(tmp_path):
    (tmp_path / "sample.py").write_text(
        "class Node:\n"
        "    def walk(self):\n"
        "        return []\n"
        "\n"
        "class Leaf(Node):\n"
        '    """Marker type: distinguishes terminal nodes in isinstance checks."""\n'
    )
    assert "lazy_class" not in smell_types(run_detector("find_design_smells.py", tmp_path))


def test_annotated_none_field_is_a_temporary_field(tmp_path):
    (tmp_path / "sample.py").write_text(
        "class Job:\n"
        "    def __init__(self):\n"
        "        self.scratch: object | None = None\n"
        "\n"
        "    def run(self):\n"
        "        self.scratch = object()\n"
        "        return self.scratch\n"
    )
    assert "temporary_field" in smell_types(run_detector("find_design_smells.py", tmp_path))


def test_nested_classes_sharing_a_name_do_not_cross_hierarchies(tmp_path):
    (tmp_path / "sample.py").write_text(
        "class ContainerA:\n"
        "    class Base:\n"
        "        def render(self):\n"
        "            return 'a'\n"
        "\n"
        "class ContainerB:\n"
        "    class Base:\n"
        "        pass\n"
        "\n"
        "    class Child(Base):\n"
        "        def render(self):\n"
        "            raise NotImplementedError\n"
    )
    assert "refused_bequest" not in smell_types(run_detector("find_design_smells.py", tmp_path))


def test_analyze_diff_keeps_finding_anchored_at_unchanged_conditional(tmp_path):
    _git(tmp_path, "init", "-q")
    target = tmp_path / "mod.py"
    target.write_text(
        "def f(kind):\n"
        "    if kind == 'a':\n"
        "        first()\n"
        "    else:\n"
        "        second()\n"
    )
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "base")
    # Edit only the branch bodies so they now end identically; the resulting
    # duplicate_conditional_fragment finding anchors at the unchanged `if` line.
    target.write_text(
        "def f(kind):\n"
        "    if kind == 'a':\n"
        "        log()\n"
        "    else:\n"
        "        log()\n"
    )
    result = subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "analyze_diff.py"), "HEAD", "--format", "json"],
        cwd=tmp_path, capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stderr[:500]
    found = {f["smell_type"] for f in json.loads(result.stdout)}
    assert "duplicate_conditional_fragment" in found


def test_abstract_stub_with_imported_base_is_not_refused_bequest(tmp_path):
    (tmp_path / "sample.py").write_text(
        "from abc import ABC, abstractmethod\n"
        "\n"
        "class Renderer(ABC):\n"
        "    @abstractmethod\n"
        "    def render(self):\n"
        "        raise NotImplementedError\n"
    )
    assert "refused_bequest" not in smell_types(run_detector("find_design_smells.py", tmp_path))


def test_analyze_diff_surfaces_detector_failures(tmp_path):
    import shutil

    broken_scripts = tmp_path / "scripts"
    shutil.copytree(SCRIPTS_DIR, broken_scripts)
    (broken_scripts / "find_type_gaps.py").write_text("import sys\nsys.exit(3)\n")
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "m.py").write_text("def f(x):\n    return x\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "base")
    (repo / "m.py").write_text("def f(x):\n    return x + 1\n")
    result = subprocess.run(
        [sys.executable, str(broken_scripts / "analyze_diff.py"), "HEAD", "--format", "json"],
        cwd=repo, capture_output=True, text=True, timeout=240,
    )
    assert result.returncode == 0, result.stderr[:500]
    errors = [f for f in json.loads(result.stdout) if f["smell_type"] == "detector_error"]
    assert errors and "find_type_gaps.py" in errors[0]["description"]


def test_working_metaclass_is_not_a_registry(tmp_path):
    # EnumType-style metaclasses subscript-assign while building the class;
    # only storing the *new class itself* into a mapping is registration.
    (tmp_path / "sample.py").write_text(
        "class WorkingMeta(type):\n"
        "    def __new__(mcs, name, bases, ns):\n"
        "        ns['_value_map'] = {}\n"
        "        new_cls = super().__new__(mcs, name, bases, ns)\n"
        "        new_cls._value_map['x'] = 1\n"
        "        return new_cls\n"
    )
    assert "registry_metaclass" not in smell_types(
        run_detector("find_pattern_issues.py", tmp_path)
    )


def test_self_release_in_finally_is_not_flagged(tmp_path):
    # logging.Handler-style self.acquire()/self.release() is internal lifecycle
    # management, not a drop-in `with` candidate.
    (tmp_path / "sample.py").write_text(
        "class Handler:\n"
        "    def emit(self):\n"
        "        self.acquire()\n"
        "        try:\n"
        "            self.write()\n"
        "        finally:\n"
        "            self.release()\n"
    )
    assert "try_finally_close" not in smell_types(
        run_detector("find_pattern_issues.py", tmp_path)
    )


def test_stateful_strategy_classes_are_not_flagged(tmp_path):
    # Strategies that carry configuration earn their classes.
    (tmp_path / "sample.py").write_text(
        "class Discount:\n"
        "    def apply(self, order):\n"
        "        raise NotImplementedError\n"
        "\n"
        "class Percent(Discount):\n"
        "    def __init__(self, rate):\n"
        "        self.rate = rate\n"
        "\n"
        "    def apply(self, order):\n"
        "        return order * self.rate\n"
        "\n"
        "class OnSale(Discount):\n"
        "    def apply(self, order):\n"
        "        return order * 0.5\n"
    )
    assert "stateless_strategy_classes" not in smell_types(
        run_detector("find_pattern_issues.py", tmp_path)
    )

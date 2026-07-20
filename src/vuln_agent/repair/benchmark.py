"""Reproducible benchmark inventory and patch-quality metrics."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class BenchmarkCase:
    case_id: str
    family: str
    vulnerability_type: str
    source_path: str
    source: str
    function: str
    expected_strategy: str
    tags: tuple[str, ...] = ()
    finding_input: dict[str, Any] = field(default_factory=dict)
    test_path: str = ""
    test_source: str = ""
    business_commands: tuple[str, ...] = ()
    security_commands: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class QualityObservation:
    case_id: str
    baseline_reproduced: bool
    exact_apply: bool
    build_passed: bool
    security_passed: bool
    business_passed: bool
    accepted: bool
    correct: bool
    attempts: int
    duplicate_failures: int = 0


@dataclass(frozen=True, slots=True)
class PatchQualityMetrics:
    total: int
    baseline_reproduction_rate: float
    exact_apply_rate: float
    security_pass_rate: float
    business_pass_rate: float
    accepted_patch_precision: float
    pass_at_1: float
    pass_at_3: float
    duplicate_failure_rate: float

    @classmethod
    def from_observations(
        cls,
        observations: list[QualityObservation],
    ) -> "PatchQualityMetrics":
        total = len(observations)
        if not total:
            return cls(0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)

        def rate(predicate) -> float:
            return round(sum(1 for item in observations if predicate(item)) / total, 4)

        accepted = [item for item in observations if item.accepted]
        precision = (
            sum(1 for item in accepted if item.correct) / len(accepted)
            if accepted else 0.0
        )
        total_failures = sum(max(0, item.attempts - 1) for item in observations)
        duplicates = sum(item.duplicate_failures for item in observations)
        return cls(
            total=total,
            baseline_reproduction_rate=rate(lambda item: item.baseline_reproduced),
            exact_apply_rate=rate(lambda item: item.exact_apply),
            security_pass_rate=rate(lambda item: item.security_passed),
            business_pass_rate=rate(lambda item: item.business_passed),
            accepted_patch_precision=round(precision, 4),
            pass_at_1=rate(lambda item: item.correct and item.attempts <= 1),
            pass_at_3=rate(lambda item: item.correct and item.attempts <= 3),
            duplicate_failure_rate=round(
                duplicates / total_failures, 4
            ) if total_failures else 0.0,
        )

    def to_dict(self) -> dict:
        return asdict(self)


def default_phase1_inventory() -> list[BenchmarkCase]:
    """Return the 60-case phase-one inventory without network dependencies."""
    cases: list[BenchmarkCase] = []
    sql_shapes = [
        ("name", "select * from users where name = '", "'"),
        ("email", "select * from users where email = '", "'"),
        ("title", "select * from posts where title like '%", "%'"),
        ("owner", "select * from files where owner = '", "'"),
        ("token", "select * from sessions where token = '", "'"),
    ]
    for index in range(20):
        field, before, after = sql_shapes[index % len(sql_shapes)]
        path = f"src/sql_case_{index}.py"
        function = f"query_{index}"
        test_path = f"tests/test_sql_case_{index}.py"
        command = f'python -m pytest -q "{test_path}"'
        cases.append(BenchmarkCase(
            f"sql-{index:02d}",
            "sql_injection",
            "SQL Injection",
            path,
            (
                "class _Request:\n"
                "    args = {}\n\n"
                "request = _Request()\n\n\n"
                f"def {function}(cursor):\n"
                f"    {field} = request.args.get(\"q\", \"\")\n"
                f"    sql = {before!r} + {field} + {after!r}\n"
                "    cursor.execute(sql)\n"
                "    return cursor.fetchall()\n"
            ),
            function,
            "parameterized_query",
            ("python", "dbapi", "source_to_sink"),
            finding_input={
                "finding_id": f"sql-{index:02d}",
                "vulnerability_type": "SQL Injection",
                "severity": "high",
                "scanner": "phase1-benchmark",
                "affected_file": path,
                "affected_function": function,
                "line": 7,
                "evidence": "request input is concatenated into cursor.execute SQL",
            },
            test_path=test_path,
            test_source="def test_existing_business_baseline():\n    assert True\n",
            business_commands=(command,),
            security_commands=(command,),
        ))

    commands = ["ping ", "nslookup ", "dig ", "host ", "curl "]
    for index in range(15):
        prefix = commands[index % len(commands)]
        path = f"src/command_case_{index}.py"
        function = f"run_{index}"
        test_path = f"tests/test_command_case_{index}.py"
        command = f'python -m pytest -q "{test_path}"'
        cases.append(BenchmarkCase(
            f"command-{index:02d}",
            "command_injection",
            "Command Injection",
            path,
            (
                "import os\n\n"
                f"def {function}(value):\n"
                f"    return os.system({prefix!r} + value)\n"
            ),
            function,
            "argv_without_shell",
            ("python", "os_system"),
            finding_input={
                "finding_id": f"command-{index:02d}",
                "vulnerability_type": "Command Injection",
                "severity": "high",
                "scanner": "phase1-benchmark",
                "affected_file": path,
                "affected_function": function,
                "line": 4,
                "evidence": "untrusted input reaches os.system",
            },
            test_path=test_path,
            test_source="def test_existing_business_baseline():\n    assert True\n",
            business_commands=(command,),
            security_commands=(command,),
        ))

    methods = ["read_text()", "read_bytes()", "open()"]
    for index in range(15):
        method = methods[index % len(methods)]
        path = f"src/path_case_{index}.py"
        function = f"read_{index}"
        test_path = f"tests/test_path_case_{index}.py"
        command = f'python -m pytest -q "{test_path}"'
        cases.append(BenchmarkCase(
            f"path-{index:02d}",
            "path_traversal",
            "Path Traversal",
            path,
            (
                "from pathlib import Path\n\n"
                f"def {function}(base, user_path):\n"
                f"    return (Path(base) / user_path).{method}\n"
            ),
            function,
            "resolved_path_containment",
            ("python", "pathlib"),
            finding_input={
                "finding_id": f"path-{index:02d}",
                "vulnerability_type": "Path Traversal",
                "severity": "high",
                "scanner": "phase1-benchmark",
                "affected_file": path,
                "affected_function": function,
                "line": 4,
                "evidence": "untrusted path is joined without resolved containment",
            },
            test_path=test_path,
            test_source="def test_existing_business_baseline():\n    assert True\n",
            business_commands=(command,),
            security_commands=(command,),
        ))

    for index in range(10):
        version = f"1.{index}.0"
        command = "python -c \"print('dependency-consumer-ok')\""
        cases.append(BenchmarkCase(
            f"sca-{index:02d}",
            "dependency",
            "Vulnerable Dependency",
            "requirements.txt",
            f"example-package=={version}\n",
            "",
            "minimum_safe_direct_dependency_upgrade",
            ("python", "requirements"),
            finding_input={
                "finding_id": f"sca-{index:02d}",
                "vulnerability_type": "dependency",
                "severity": "high",
                "scanner": "phase1-benchmark",
                "affected_file": "requirements.txt",
                "component": "example-package",
                "current_version": version,
                "fixed_versions": [f"1.{index}.1"],
                "evidence": "direct vulnerable dependency",
            },
            business_commands=(command,),
            security_commands=(command,),
        ))
    return cases

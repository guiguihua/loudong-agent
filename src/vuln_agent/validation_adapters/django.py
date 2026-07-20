"""Focused validation commands for a Django source checkout."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable


class DjangoValidationCommandAdapter:
    """Recognize Django's own test suite and build safe focused labels."""

    runner = "tests/runtests.py"
    _safe_label = re.compile(r"^[A-Za-z0-9_.]+$")

    @classmethod
    def detects_paths(cls, paths: Iterable[str]) -> bool:
        normalized = {cls._normalize(path) for path in paths}
        return cls.runner in normalized and "django/__init__.py" in normalized

    @classmethod
    def detects_workspace(cls, workspace: Path) -> bool:
        return (
            (workspace / cls.runner).is_file()
            and (workspace / "django" / "__init__.py").is_file()
        )

    @classmethod
    def focused_labels(cls, test_paths: Iterable[str]) -> tuple[str, ...]:
        labels: list[str] = []
        for raw_path in test_paths:
            path = cls._normalize(raw_path)
            if not path.startswith("tests/") or not path.endswith(".py"):
                continue
            relative = path[len("tests/") : -len(".py")]
            parts = [part for part in relative.split("/") if part]
            if not parts or parts[-1] in {"runtests", "__init__"}:
                continue
            if parts[-1] in {"tests", "test"}:
                parts = parts[:-1]
            if not parts:
                continue
            label = ".".join(parts)
            if cls._safe_label.fullmatch(label) and label not in labels:
                labels.append(label)
        return tuple(labels)

    @classmethod
    def focused_command(
        cls,
        python_command: str,
        test_paths: Iterable[str],
        *,
        maximum_labels: int = 5,
    ) -> str | None:
        labels = cls.focused_labels(test_paths)[:maximum_labels]
        if not labels:
            return None
        return f"{python_command} {cls.runner} {' '.join(labels)}"

    @staticmethod
    def _normalize(path: str) -> str:
        return str(path).replace("\\", "/").strip().lstrip("./")

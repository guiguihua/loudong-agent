"""SQL injection repair scenario."""

from typing import TYPE_CHECKING

from .taxonomy import SQLInjectionKind, classify_sql_injection, is_sql_injection

if TYPE_CHECKING:
    from .adapter import SQLInjectionRepairScenario

__all__ = [
    "SQLInjectionKind",
    "SQLInjectionRepairScenario",
    "classify_sql_injection",
    "is_sql_injection",
]


def __getattr__(name: str):
    if name == "SQLInjectionRepairScenario":
        from .adapter import SQLInjectionRepairScenario

        return SQLInjectionRepairScenario
    raise AttributeError(name)

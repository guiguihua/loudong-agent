"""SQL-injection subtypes used by analysis, generation, and validation."""

from __future__ import annotations

from enum import StrEnum

from ...models import NormalizedVulnerability


class SQLInjectionKind(StrEnum):
    VALUE = "value"
    IDENTIFIER = "identifier"
    ORM_EXPRESSION = "orm_expression"
    ORDERING = "ordering"


def classify_sql_injection(finding: NormalizedVulnerability) -> SQLInjectionKind:
    """Classify the injection context without relying on a CVE or file path."""

    text = " ".join(
        [
            finding.vulnerability_type,
            finding.recommendation or "",
            *(finding.evidence or []),
            *(
                f"{location.function or ''} {location.file}"
                for location in finding.locations
            ),
        ]
    ).lower()

    if any(
        term in text
        for term in (
            "order by",
            "order_by",
            "ordering",
            "sort field",
            "sort column",
            "sorting",
            "排序字段",
            "排序列",
        )
    ):
        return SQLInjectionKind.ORDERING
    if any(
        term in text
        for term in (
            "identifier",
            "column name",
            "field name",
            "table name",
            "sql alias",
            "column alias",
            "check_alias",
            "set_values",
            "values()",
            "values_list",
            "jsonfield",
            "标识符",
            "字段名",
            "列名",
            "表名",
            "别名",
        )
    ):
        return SQLInjectionKind.IDENTIFIER
    if any(
        term in text
        for term in (
            "orm expression",
            "query expression",
            "rawsql",
            "annotate",
            "annotation",
            "aggregate",
            "lookup_name",
            "extra(",
            "orm 表达式",
            "查询表达式",
        )
    ):
        return SQLInjectionKind.ORM_EXPRESSION
    return SQLInjectionKind.VALUE


def is_sql_injection(finding: NormalizedVulnerability) -> bool:
    text = finding.vulnerability_type.lower()
    return (
        "sql" in text
        and any(
            term in text
            for term in (
                "inject",
                "injection",
                "alias",
                "identifier",
                "expression",
                "order",
                "注入",
                "别名",
                "标识符",
            )
        )
    )

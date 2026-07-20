"""预置 Demo 注册表 — 每个 demo 封装完整的漏洞场景数据。

新增场景只需在此模块中添加一个 `DemoPreset` 实例，
无需编写独立的 run_xxx_demo.py 脚本。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .models import (
    ApiEntryPoint,
    CodePoint,
    EngineeringContext,
    FailedControl,
    PropagationStep,
    RepositoryContext,
    SourceFile,
    ValidationLayer,
)
from .tools import (
    AssetContext,
    CodeContext,
    DependencyRootCauseContext,
    RootCauseCodeContext,
    RuntimeContext,
)

# ── helpers ──────────────────────────────────────────────────────────

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES_DIR = ROOT / "examples"
VALIDATION_DIR = ROOT / "validation-coverage"


def _django_version(project_dir: Path) -> str:
    init_py = project_dir / "django" / "__init__.py"
    match = re.search(r"VERSION\s*=\s*\((\d+),\s*(\d+),\s*(\d+),", init_py.read_text(encoding="utf-8"))
    if not match:
        raise RuntimeError(f"无法从 {init_py} 解析 Django VERSION")
    return ".".join(match.groups())


# ── demo preset dataclass ────────────────────────────────────────────


@dataclass(slots=True)
class DemoPreset:
    """单个预置 demo 的完整描述。"""

    key: str
    title: str
    description: str

    # 漏洞数据来源：要么是 examples/*.json 文件名，要么是返回 dict 的 callable
    raw_input: str | Callable[[], dict[str, Any]]

    # 上下文构建
    code_context: Callable[[str], CodeContext]
    asset_context: Callable[[str], AssetContext]
    runtime_context: Callable[[str], RuntimeContext]
    root_cause_context: Callable[[str], RootCauseCodeContext | DependencyRootCauseContext]

    engineering: EngineeringContext
    repository: RepositoryContext
    source_files: Callable[[], list[SourceFile]]

    is_dependency_type: bool = False
    vulnerability_type_hint: str | None = None

    # 各验证层通过摘要（可为 callable，接收 finding_id）
    validation_summaries: Callable[[str], list[tuple[ValidationLayer, str, str]]] | None = None


# ── 共享工厂 ─────────────────────────────────────────────────────────


# ── code‑sqli ────────────────────────────────────────────────────────


def _code_sqli_code_ctx(finding_id: str) -> CodeContext:
    return CodeContext(
        services=["customer-service"],
        call_paths=[["GET /users/search", "search_users", "cursor.execute"]],
        entry_points=[ApiEntryPoint("/users/search", "GET", "required", False)],
        data_classification=["user profile data"],
        upstream_dependencies=["browser-client"],
        downstream_dependencies=["postgresql-users-db"],
        related_tests=["tests/test_user_search.py"],
    )


def _code_sqli_asset_ctx(finding_id: str) -> AssetContext:
    return AssetContext(
        deployed_assets=["customer-service:local-demo"],
        affected_artifacts=["customer-service:local-demo"],
        internet_exposure_known=True,
    )


def _code_sqli_runtime_ctx(finding_id: str) -> RuntimeContext:
    return RuntimeContext(
        observed_routes=["GET /users/search"],
        observed_call_paths=[["GET /users/search", "search_users", "cursor.execute"]],
        evidence_available=True,
    )


def _code_sqli_root_cause_ctx(finding_id: str) -> RootCauseCodeContext:
    return RootCauseCodeContext(
        source=CodePoint("request.args.get", "src/user/search.py", 5),
        propagation=[
            PropagationStep("keyword", "assigned_from_request_query_parameter"),
            PropagationStep("sql", "string_concatenation_with_untrusted_input"),
        ],
        sink=CodePoint("cursor.execute", "src/user/search.py", 7),
        guards=["default empty string"],
        failed_controls=[FailedControl("default empty string", "does not prevent SQL syntax injection")],
        trigger_conditions=["GET /users/search?q=' OR '1'='1"],
        vulnerable_code='sql = "select * from users where name like \'%" + keyword + "%\'"',
        language="Python",
        framework="Flask",
        evidence_available=True,
    )


def _code_sqli_sources() -> list[SourceFile]:
    return [
        SourceFile(
            "src/user/search.py",
            'from flask import request\n\n\ndef search_users(cursor):\n'
            '    keyword = request.args.get("q", "")\n'
            '    sql = "select * from users where name like \'%" + keyword + "%\'"\n'
            "    cursor.execute(sql)\n"
            "    return cursor.fetchall()\n",
        ),
        SourceFile("tests/test_user_search.py", "def test_search_users_returns_results():\n    assert True\n"),
    ]


def _code_sqli_validation(finding_id: str) -> list[tuple[ValidationLayer, str, str]]:
    return [
        (ValidationLayer.BUILD, "python compile", "候选补丁为 Python 参数化查询 diff，可进入 pytest/构建阶段。"),
        (ValidationLayer.BUSINESS_REGRESSION, "pytest tests/test_user_search.py", "正常关键字搜索仍返回用户搜索结果，接口契约保持不变。"),
        (ValidationLayer.SECURITY_REGRESSION, "SQLi payload regression", "payload q=' OR '1'='1 被作为绑定参数处理，不再改变 SQL 查询结构。"),
        (ValidationLayer.SCANNER_RESCAN, "SAST rescan", "原 SAST 规则 user input concatenated into SQL query 不再命中修复后的 execute 调用。"),
        (ValidationLayer.DIFFERENTIAL_RISK, "diff risk review", "候选补丁只修改 SQL 构造与对应回归测试，没有绕过认证、关闭扫描或访问生产数据。"),
    ]


# ── django-alias-sqli ────────────────────────────────────────────────


def _django_alias_code_ctx(finding_id: str) -> CodeContext:
    return CodeContext(
        services=["django-orm"],
        call_paths=[[
            "QuerySet.values()/values_list()",
            "Query._values()",
            "Query.set_values(fields)",
            "Query.add_fields()/setup_joins()",
            "Query.set_group_by()",
            "SQLCompiler AS alias generation",
        ]],
        entry_points=[ApiEntryPoint("QuerySet.values", "PYTHON_API", "library-user", None)],
        data_classification=["query metadata", "relational data"],
        upstream_dependencies=["application code using Django ORM"],
        downstream_dependencies=["database backend"],
        related_tests=["tests/queries/test_qs_combinators.py"],
    )


def _django_alias_asset_ctx(finding_id: str) -> AssetContext:
    return AssetContext(
        deployed_assets=["django ORM library"],
        affected_artifacts=["django/db/models/sql/query.py"],
        internet_exposure_known=False,
    )


def _django_alias_runtime_ctx(finding_id: str) -> RuntimeContext:
    return RuntimeContext(
        observed_routes=["Python API: QuerySet.values", "Python API: QuerySet.values_list"],
        observed_call_paths=[["values()", "_values()", "set_values()", "set_group_by()", "SQLCompiler"]],
        evidence_available=True,
    )


def _django_alias_root_cause_ctx(finding_id: str) -> RootCauseCodeContext:
    return RootCauseCodeContext(
        source=CodePoint("QuerySet.values()/values_list()", "django/db/models/query.py", 1360),
        propagation=[
            PropagationStep("_values()", "forwards field names unchanged to clone.query.set_values(fields)"),
            PropagationStep("set_values(fields)", "stores raw field names without check_alias()"),
            PropagationStep("add_fields()/setup_joins()", "resolves KeyTransform expression and keeps original field name in values_select"),
            PropagationStep("set_group_by()", "promotes non-Col expressions to annotations using values_select as alias"),
            PropagationStep("SQLCompiler", "renders annotation alias into AS alias clause"),
        ],
        sink=CodePoint('SQLCompiler: AS "alias"', "django/db/models/sql/compiler.py", None),
        guards=["check_alias() exists", "add_annotation() calls check_alias()", "add_extra() calls check_alias()"],
        failed_controls=[FailedControl("Query.set_values() missing check_alias()", "values()/values_list() path bypasses the alias guard used by add_annotation() and add_extra()")],
        trigger_conditions=["attacker-controlled or unsafe field expression reaches values()/values_list() and later becomes a SQL alias"],
        vulnerable_code="if fields:\n    field_names = []",
        language="Python",
        framework="Django ORM",
        evidence_available=True,
    )


def _django_alias_sources() -> list[SourceFile]:
    return [
        SourceFile("django/db/models/sql/query.py", (
            'class Query:\n'
            '    def check_alias(self, alias):\n'
            '        if FORBIDDEN_ALIAS_PATTERN.search(alias):\n'
            '            raise ValueError("Column aliases cannot contain whitespace characters, quotation marks, semicolons, or SQL comments.")\n'
            '\n'
            '    def set_values(self, fields):\n'
            '        self.select_related = False\n'
            '        if fields:\n'
            '            field_names = []\n'
            '            extra_names = []\n'
            '            annotation_names = []\n'
            '            if not self.extra and not self.annotations:\n'
            '                field_names = list(fields)\n'
            '            self.values_select = tuple(field_names)\n'
        )),
        SourceFile("tests/queries/test_qs_combinators.py", "def test_values_rejects_forbidden_alias_payload():\n    assert True\n"),
    ]


def _django_alias_validation(finding_id: str) -> list[tuple[ValidationLayer, str, str]]:
    return [
        (ValidationLayer.BUILD, "python compile", "query.py 修改为纯 Python 控制流插入，语法可编译。"),
        (ValidationLayer.BUSINESS_REGRESSION, "ORM values regression", "正常 values()/values_list() 字段选择行为保持不变。"),
        (ValidationLayer.SECURITY_REGRESSION, "alias injection regression", "包含分号、引号、空白或 SQL 注释标记的 alias payload 会在 set_values() 被 check_alias() 拒绝。"),
        (ValidationLayer.SCANNER_RESCAN, "manual rule rescan", "set_values(fields) 分支已覆盖 check_alias(field) 调用，不再存在该绕过路径。"),
        (ValidationLayer.DIFFERENTIAL_RISK, "diff risk review", "补丁只在 set_values() 入口增加别名校验，不改变 SQL compiler 或 quote_name() 行为。"),
    ]


# ── 依赖 CVE demo ───────────────────────────────────────────────────


def _make_dep_cve_code_ctx(service: str, route: str, component: str, regression_test: str) -> Callable[[str], CodeContext]:
    def _ctx(finding_id: str) -> CodeContext:
        return CodeContext(
            services=[service],
            call_paths=[[f"POST {route}", component, "runtime dependency usage"]],
            entry_points=[ApiEntryPoint(route, "POST", "required", True)],
            upstream_dependencies=["browser-client"],
            downstream_dependencies=["application-server"],
            related_tests=[regression_test],
        )
    return _ctx


def _make_dep_cve_asset_ctx(artifact: str) -> Callable[[str], AssetContext]:
    def _ctx(finding_id: str) -> AssetContext:
        return AssetContext(
            deployed_assets=[artifact],
            affected_artifacts=[artifact],
            internet_exposure_known=True,
        )
    return _ctx


def _make_dep_cve_runtime_ctx(route: str) -> Callable[[str], RuntimeContext]:
    def _ctx(finding_id: str) -> RuntimeContext:
        return RuntimeContext(observed_routes=[f"POST {route}"], evidence_available=True)
    return _ctx


def _make_dep_cve_root_cause(component: str, service: str) -> Callable[[str], DependencyRootCauseContext]:
    def _ctx(finding_id: str) -> DependencyRootCauseContext:
        return DependencyRootCauseContext(
            component=component,
            dependency_path=[service, component],
            runtime_used=True,
            vulnerable_feature_used=True,
            cve_match_confirmed=True,
        )
    return _ctx


def _make_dep_cve_sources(pom_snippet: str) -> Callable[[], list[SourceFile]]:
    def _src() -> list[SourceFile]:
        return [SourceFile("pom.xml", pom_snippet)]
    return _src


# ── validation-coverage-django ────────────────────────────────────────


def _vc_django_raw() -> dict[str, Any]:
    vulnerable_dir = VALIDATION_DIR / "sql-injection" / "django-5.0.6"
    fixed_dir = VALIDATION_DIR / "upstream-fixed" / "django-5.0.8"
    vulnerable_ver = _django_version(vulnerable_dir)
    fixed_ver = _django_version(fixed_dir)

    return {
        "finding_id": "VALIDATION-COVERAGE-DJANGO-SQLI-5.0.6",
        "vulnerability_type": "dependency",
        "severity": "high",
        "confidence": "high",
        "scanner": "validation-coverage",
        "affected_file": "requirements.txt",
        "locations": [{"file": "requirements.txt"}, {"file": "pyproject.toml"}],
        "component": "django",
        "current_version": vulnerable_ver,
        "fixed_versions": [fixed_ver],
        "breaking_upgrade": False,
        "affected_artifacts": [str(vulnerable_dir.relative_to(ROOT))],
        "evidence": [
            f"本地样例目录存在 vulnerable 版本：{vulnerable_dir.relative_to(ROOT)}",
            f"本地样例目录存在 upstream fixed 版本：{fixed_dir.relative_to(ROOT)}",
            "安全回归测试包含 SQL 注入用例：tests/db_functions/datetime/test_extract_trunc.py",
        ],
        "recommendation": f"将 Django 从 {vulnerable_ver} 升级到 {fixed_ver}，并保留 Extract/Trunc lookup_name SQL 注入回归测试。",
        "repository": str(vulnerable_dir.relative_to(ROOT)),
        "raw_reference": "validation-coverage/sql-injection/django-5.0.6",
    }


REGRESSION_TEST = "tests/db_functions/datetime/test_extract_trunc.py"


def _vc_django_code_ctx(finding_id: str) -> CodeContext:
    return CodeContext(
        services=["django-validation-webapp"],
        call_paths=[[
            "HTTP request with ORM date/datetime filter input",
            "Django QuerySet annotate/filter",
            "Extract/Trunc lookup_name",
            "SQL compiler",
        ]],
        entry_points=[ApiEntryPoint("/reports/date-search", "GET", "required", True)],
        data_classification=["application data", "queryable relational data"],
        upstream_dependencies=["browser-client", "api-client"],
        downstream_dependencies=["relational-database"],
        related_tests=[REGRESSION_TEST],
    )


def _vc_django_asset_ctx(finding_id: str) -> AssetContext:
    return AssetContext(
        deployed_assets=["django-validation-webapp:local-fixture"],
        affected_artifacts=[str((VALIDATION_DIR / "sql-injection" / "django-5.0.6").relative_to(ROOT))],
        internet_exposure_known=True,
    )


def _vc_django_runtime_ctx(finding_id: str) -> RuntimeContext:
    return RuntimeContext(
        observed_routes=["GET /reports/date-search"],
        observed_call_paths=[["GET /reports/date-search", "Django ORM", "Extract/Trunc SQL generation"]],
        evidence_available=True,
    )


def _vc_django_root_cause(finding_id: str) -> DependencyRootCauseContext:
    return DependencyRootCauseContext(
        component="django",
        dependency_path=["django-validation-webapp", "django"],
        runtime_used=True,
        vulnerable_feature_used=True,
        cve_match_confirmed=True,
    )


def _vc_django_sources() -> list[SourceFile]:
    return [
        SourceFile("requirements.txt", "Django==5.0.6\n"),
        SourceFile("pyproject.toml", 'dependencies = ["Django==5.0.6"]\n'),
    ]


def _vc_django_validation(finding_id: str) -> list[tuple[ValidationLayer, str, str]]:
    v_dir = VALIDATION_DIR
    return [
        (ValidationLayer.BUILD, "local version sanity check",
         f"已确认 vulnerable 版本为 Django 5.0.6，upstream fixed 版本为 Django 5.0.8。"),
        (ValidationLayer.BUSINESS_REGRESSION, "Django ORM datetime regression",
         f"保留 Django ORM 日期/时间函数测试目标；证据：{(v_dir / 'sql-injection' / 'django-5.0.6' / REGRESSION_TEST).relative_to(ROOT)}。"),
        (ValidationLayer.SECURITY_REGRESSION, "SQL injection regression",
         "安全回归覆盖 test_extract_lookup_name_sql_injection 与 test_trunc_lookup_name_sql_injection。"),
        (ValidationLayer.SCANNER_RESCAN, "validation-coverage fixed fixture",
         f"补丁目标版本指向 upstream-fixed/django-5.0.8；证据：{(v_dir / 'upstream-fixed' / 'django-5.0.8').relative_to(ROOT)}。"),
        (ValidationLayer.DIFFERENTIAL_RISK, "dependency diff review",
         "本轮候选补丁仅升级 Django 依赖版本并要求保留安全回归测试，不直接修改生产配置或数据。"),
    ]


# ── 注册表 ───────────────────────────────────────────────────────────

DEMOS: list[DemoPreset] = [
    DemoPreset(
        key="code-sqli",
        title="SQL 注入 - 代码修复 (Flask)",
        description="SAST 报告的 SQL 注入漏洞（字符串拼接），"
        "生成参数化查询补丁并通过五层验证。",
        raw_input="sast_sql_injection.json",
        code_context=_code_sqli_code_ctx,
        asset_context=_code_sqli_asset_ctx,
        runtime_context=_code_sqli_runtime_ctx,
        root_cause_context=_code_sqli_root_cause_ctx,
        engineering=EngineeringContext(
            language="Python", framework="Flask", database="PostgreSQL",
            data_access_library="DB-API cursor",
            available_test_commands=["python -m pytest tests/test_user_search.py"],
            related_tests=["tests/test_user_search.py"],
            deployment_targets=["customer-service"],
        ),
        repository=RepositoryContext(
            repository="customer-service", branch="fix/sqli-search-users",
            language="Python", framework="Flask", package_manager="pip", test_framework="pytest",
        ),
        source_files=_code_sqli_sources,
        validation_summaries=_code_sqli_validation,
    ),
    DemoPreset(
        key="django-alias",
        title="SQL Alias 注入 - 代码修复 (Django ORM)",
        description="Django ORM Query.set_values() 缺少 check_alias() 校验，"
        "导致不可信字段名进入 SQL AS alias。",
        raw_input=lambda: {
            "finding_id": "DJANGO-ALIAS-SQLI-001",
            "vulnerability_type": "SQL Alias Injection",
            "severity": "high", "confidence": "high",
            "scanner": "manual-security-review",
            "affected_file": "django/db/models/sql/query.py",
            "affected_function": "Query.set_values", "line": 6,
            "evidence": "set_values() stores fields into values_select without check_alias(); set_group_by() later promotes aliases into SQL annotations.",
            "recommendation": "call self.check_alias(field) for every field at the beginning of set_values(fields)",
            "repository": "django",
        },
        code_context=_django_alias_code_ctx,
        asset_context=_django_alias_asset_ctx,
        runtime_context=_django_alias_runtime_ctx,
        root_cause_context=_django_alias_root_cause_ctx,
        engineering=EngineeringContext(
            language="Python", framework="Django ORM", database="multiple backends",
            available_test_commands=["python tests/runtests.py queries"],
            related_tests=["tests/queries/test_qs_combinators.py"],
        ),
        repository=RepositoryContext(
            repository="django", branch="fix/check-alias-in-set-values",
            language="Python", framework="Django", test_framework="Django test runner",
        ),
        source_files=_django_alias_sources,
        validation_summaries=_django_alias_validation,
    ),
    DemoPreset(
        key="struts-cve",
        title="Apache Struts CVE-2017-5638 - 依赖升级",
        description="Apache Struts2 远程代码执行漏洞，通过升级依赖版本修复。",
        raw_input="struts_cve_2017_5638.json",
        code_context=_make_dep_cve_code_ctx("struts-showcase", "/upload", "org.apache.struts:struts2-core", "src/test/java/org/apache/struts2/FileUploadRegressionTest.java"),
        asset_context=_make_dep_cve_asset_ctx("struts-showcase-webapp:2.3.31"),
        runtime_context=_make_dep_cve_runtime_ctx("/upload"),
        root_cause_context=_make_dep_cve_root_cause("org.apache.struts:struts2-core", "struts-showcase"),
        engineering=EngineeringContext(
            language="Java", framework="Apache Struts 2", package_manager="maven",
            related_tests=["src/test/java/org/apache/struts2/FileUploadRegressionTest.java"],
            available_test_commands=["mvn test"],
        ),
        repository=RepositoryContext(
            repository="https://github.com/apache/struts", branch="struts-2-3-31-cve-validation",
            package_manager="maven", test_framework="maven",
        ),
        source_files=_make_dep_cve_sources("<dependency><groupId>org.apache.struts</groupId><artifactId>struts2-core</artifactId><version>2.3.31</version></dependency>\n"),
        is_dependency_type=True,
    ),
    DemoPreset(
        key="log4j-cve",
        title="Log4j CVE-2021-44228 (Log4Shell) - 依赖升级",
        description="Log4j JNDI 注入漏洞，通过升级 log4j-core 版本修复。",
        raw_input="log4j_cve_2021_44228.json",
        code_context=_make_dep_cve_code_ctx("demo-java-webapp", "/login", "org.apache.logging.log4j:log4j-core", "src/test/java/demo/LoggingRegressionTest.java"),
        asset_context=_make_dep_cve_asset_ctx("demo-java-webapp:1.0.0"),
        runtime_context=_make_dep_cve_runtime_ctx("/login"),
        root_cause_context=_make_dep_cve_root_cause("org.apache.logging.log4j:log4j-core", "demo-java-webapp"),
        engineering=EngineeringContext(
            language="Java", framework="Java web application", package_manager="maven",
            related_tests=["src/test/java/demo/LoggingRegressionTest.java"],
            available_test_commands=["mvn test"],
        ),
        repository=RepositoryContext(
            repository="https://github.com/apache/logging-log4j2", branch="log4j-2-14-1-cve-validation",
            package_manager="maven", test_framework="maven",
        ),
        source_files=_make_dep_cve_sources("<dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency>\n"),
        is_dependency_type=True,
    ),
    DemoPreset(
        key="commons-text-cve",
        title="Apache Commons Text CVE-2022-42889 - 依赖升级",
        description="Commons Text 不安全插值漏洞，通过升级版本修复。",
        raw_input="commons_text_cve_2022_42889.json",
        code_context=_make_dep_cve_code_ctx("template-service", "/render-template", "org.apache.commons:commons-text", "src/test/java/demo/TemplateInterpolationRegressionTest.java"),
        asset_context=_make_dep_cve_asset_ctx("template-service:1.4.0"),
        runtime_context=_make_dep_cve_runtime_ctx("/render-template"),
        root_cause_context=_make_dep_cve_root_cause("org.apache.commons:commons-text", "template-service"),
        engineering=EngineeringContext(
            language="Java", framework="Java web application", package_manager="maven",
            related_tests=["src/test/java/demo/TemplateInterpolationRegressionTest.java"],
            available_test_commands=["mvn test"],
        ),
        repository=RepositoryContext(
            repository="https://github.com/apache/commons-text", branch="commons-text-1-9-cve-validation",
            package_manager="maven", test_framework="maven",
        ),
        source_files=_make_dep_cve_sources("<dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId><version>1.9</version></dependency>\n"),
        is_dependency_type=True,
    ),
    DemoPreset(
        key="spring-cve",
        title="Spring Framework CVE-2022-22965 (Spring4Shell) - 依赖升级",
        description="Spring MVC 不安全数据绑定漏洞，通过升级 spring-webmvc 版本修复。",
        raw_input="spring_cve_2022_22965.json",
        code_context=_make_dep_cve_code_ctx("spring-mvc-war", "/profile/update", "org.springframework:spring-webmvc", "src/test/java/demo/SpringMvcBindingRegressionTest.java"),
        asset_context=_make_dep_cve_asset_ctx("spring-mvc-war:5.3.17"),
        runtime_context=_make_dep_cve_runtime_ctx("/profile/update"),
        root_cause_context=_make_dep_cve_root_cause("org.springframework:spring-webmvc", "spring-mvc-war"),
        engineering=EngineeringContext(
            language="Java", framework="Spring MVC", package_manager="maven",
            related_tests=["src/test/java/demo/SpringMvcBindingRegressionTest.java"],
            available_test_commands=["mvn test"],
        ),
        repository=RepositoryContext(
            repository="https://github.com/spring-projects/spring-framework", branch="spring-5-3-17-cve-validation",
            package_manager="maven", test_framework="maven",
        ),
        source_files=_make_dep_cve_sources("<dependency><groupId>org.springframework</groupId><artifactId>spring-webmvc</artifactId><version>5.3.17</version></dependency>\n"),
        is_dependency_type=True,
    ),
    DemoPreset(
        key="vc-django",
        title="Validation Coverage - Django SQL 注入依赖升级",
        description="基于 validation-coverage 本地 fixture 的 Django SQL 注入依赖升级验证。",
        raw_input=_vc_django_raw,
        code_context=_vc_django_code_ctx,
        asset_context=_vc_django_asset_ctx,
        runtime_context=_vc_django_runtime_ctx,
        root_cause_context=_vc_django_root_cause,
        engineering=EngineeringContext(
            language="Python", framework="Django", package_manager="pip",
            dependency_versions={"django": "5.0.6"},
            available_test_commands=["python tests/runtests.py db_functions.datetime.test_extract_trunc"],
            related_tests=[REGRESSION_TEST],
            deployment_targets=["django-validation-webapp"],
        ),
        repository=RepositoryContext(
            repository=str((VALIDATION_DIR / "sql-injection" / "django-5.0.6").relative_to(ROOT)),
            branch="validation-coverage-django-5.0.6",
            language="Python", framework="Django", package_manager="pip", test_framework="Django test runner",
        ),
        source_files=_vc_django_sources,
        is_dependency_type=True,
        validation_summaries=_vc_django_validation,
    ),
]


def get_demo(key: str) -> DemoPreset | None:
    """根据 key 获取预置 demo。"""
    for d in DEMOS:
        if d.key == key:
            return d
    return None


def list_demos() -> list[dict[str, str]]:
    """列出所有预置 demo（摘要信息）。"""
    return [{"key": d.key, "title": d.title, "description": d.description} for d in DEMOS]

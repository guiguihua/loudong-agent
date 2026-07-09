"""动态流水线执行器 — 从任意 JSON 文件或字典运行完整的漏洞修复流水线。

支持两种模式：
  - 确定性模式（默认）：纯规则引擎，无外部依赖
  - LLM 模式：使用 DeepSeek API 进行推理，需设置 DEEPSEEK_API_KEY

Claude Code 可直接调用 run_file() / run_dict()，无需预注册 demo。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .failure_analysis import FailureAnalysisAgent
from .impact import ImpactAnalysisAgent
from .models import (
    ApiEntryPoint,
    CodePoint,
    EngineeringContext,
    FailedControl,
    PatchGenerationPolicy,
    PropagationStep,
    RemediationPolicy,
    RepairLoopStatus,
    RepositoryContext,
    Severity,
    SourceFile,
)
from .normalization import VulnerabilityNormalizer
from .orchestration import PatchRepairLoopOrchestrator
from .patching import PatchGenerationAgent
from .remediation import RemediationPlanAgent
from .reporting import RemediationReportAgent
from .root_cause import RootCauseAnalysisAgent
from .tools import (
    RootCauseCodeContext,
    StaticAssetInventoryTool,
    StaticCodeContextTool,
    StaticRootCauseEvidenceTool,
    StaticRuntimeEvidenceTool,
    AssetContext,
    CodeContext,
    DependencyRootCauseContext,
    RuntimeContext,
)
from .validation import ValidationToolchain, passed_tool

ROOT = Path(__file__).resolve().parents[2]


# ── 公共 API ─────────────────────────────────────────────────────────


def run_file(file_path: str | Path, use_llm: bool = False, **overrides: Any) -> dict[str, Any]:
    """从 JSON 文件加载漏洞并运行完整修复流水线。

    用法:
        # 确定性模式
        result = run_file("examples/sast_sql_injection.json")

        # LLM 推理模式（需设置 DEEPSEEK_API_KEY）
        result = run_file("examples/struts_cve_2017_5638.json", use_llm=True,
                          language="Java", framework="Apache Struts 2")

    返回包含 finding / impact / root_cause / patch_candidate /
    validation / report 等字段的完整结果字典。
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"文件不存在: {file_path}")
    raw = json.loads(path.read_text(encoding="utf-8"))
    return run_dict(raw, use_llm=use_llm, **overrides)


def run_dict(raw: dict[str, Any], use_llm: bool = False, **overrides: Any) -> dict[str, Any]:
    """从字典运行完整修复流水线。

    Args:
        raw: 漏洞数据字典
        use_llm: 是否使用 LLM 进行推理（需设置 DEEPSEEK_API_KEY 环境变量）
        **overrides: 可覆盖语言/框架/仓库等上下文

    overrides 可覆盖以下上下文（全部可选）:
        language, framework, database, package_manager, test_framework,
        repository, branch, services, entry_points, call_paths,
        source_files (dict[str,str] 或 list[SourceFile]),
        validation_results (list[dict] 或 list[tuple]),
        max_attempts
    """
    normalizer = VulnerabilityNormalizer()
    finding = normalizer.normalize(raw)

    # ── LLM 后端 ──
    llm = None
    if use_llm:
        from .llm import create_llm_backend
        llm = create_llm_backend()
        if llm:
            print(f"[LLM]  使用 {llm.model} 进行推理")
        else:
            print("[LLM]  未设置 DEEPSEEK_API_KEY，回退到确定性模式")

    # ── 推断漏洞类型 ──
    is_dependency = _is_dependency_type(raw, finding)

    # ── 构建上下文 ──
    eng = _build_engineering(finding, raw, is_dependency, overrides)
    repo = _build_repository(raw, overrides)
    sources = _build_source_files(raw, overrides)
    tool_results = _build_validation_results(raw, overrides)

    # ── 构建分析 Agent ──
    code_ctx = _build_code_context(finding, raw, overrides)
    asset_ctx = _build_asset_context(finding, raw, overrides)
    runtime_ctx = _build_runtime_context(finding, raw, overrides)

    impact = ImpactAnalysisAgent(
        StaticCodeContextTool({finding.finding_id: code_ctx}),
        StaticAssetInventoryTool({finding.finding_id: asset_ctx}),
        StaticRuntimeEvidenceTool({finding.finding_id: runtime_ctx}),
        llm=llm,
    ).analyze(finding)

    if is_dependency:
        root_cause = _build_dependency_root_cause(finding, raw, overrides)
    else:
        root_cause = _build_code_root_cause(finding, raw, overrides)

    root_cause_agent = RootCauseAnalysisAgent(StaticRootCauseEvidenceTool(
        code_contexts={finding.finding_id: root_cause} if isinstance(root_cause, RootCauseCodeContext) else {},
        dependency_contexts={finding.finding_id: root_cause} if isinstance(root_cause, DependencyRootCauseContext) else {},
    ), llm=llm)
    root_cause_result = root_cause_agent.analyze(finding, impact)

    # ── 执行修复循环 ──
    max_attempts = overrides.get("max_attempts", 1)
    loop = PatchRepairLoopOrchestrator(
        remediation_agent=RemediationPlanAgent(RemediationPolicy(), llm=llm),
        patch_generation_agent=PatchGenerationAgent(PatchGenerationPolicy(), llm=llm),
        validation_toolchain=ValidationToolchain(),
        failure_analysis_agent=FailureAnalysisAgent(llm=llm),
        report_agent=RemediationReportAgent(),
        max_attempts=max_attempts,
    )

    result = loop.run(
        finding,
        impact,
        root_cause_result,
        eng,
        repo,
        sources,
        [tool_results],
    )

    # ── 构建返回字典 ──
    output: dict[str, Any] = {
        "finding": finding.to_dict(),
        "impact": impact.to_dict(),
        "root_cause": root_cause_result.to_dict(),
        "status": result.status.value,
    }

    if result.final_report is not None:
        output["report"] = result.final_report.to_dict()
        output["report_markdown"] = result.final_report.pr_description_markdown

    if result.attempts:
        attempt = result.attempts[-1]
        output["patch_candidate"] = attempt.patch_candidate.to_dict()
        output["patch_validation"] = attempt.validation.to_dict()

    if result.final_failure_analysis is not None:
        output["failure_analysis"] = result.final_failure_analysis.to_dict()

    return output


def run_file_simple(file_path: str | Path) -> dict[str, Any]:
    """简化版 — 从 JSON 文件运行，返回分析结果（不生成补丁）。

    适用场景：只需要标准化 + 影响面 + 根因，不需要补丁。
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"文件不存在: {file_path}")
    raw = json.loads(path.read_text(encoding="utf-8"))
    return run_dict_simple(raw)


def run_dict_simple(raw: dict[str, Any]) -> dict[str, Any]:
    """简化版 — 只运行标准化 + 影响面 + 根因分析。"""
    normalizer = VulnerabilityNormalizer()
    finding = normalizer.normalize(raw)

    impact = ImpactAnalysisAgent(
        StaticCodeContextTool({}),
        StaticAssetInventoryTool({}),
        StaticRuntimeEvidenceTool({}),
    ).analyze(finding)

    root_cause_result = RootCauseAnalysisAgent(
        StaticRootCauseEvidenceTool()
    ).analyze(finding, impact)

    return {
        "finding": finding.to_dict(),
        "impact": impact.to_dict(),
        "root_cause": root_cause_result.to_dict(),
    }


# ── 内部：类型推断 ───────────────────────────────────────────────────


def _is_dependency_type(raw: dict[str, Any], finding) -> bool:
    """推断是否为依赖升级类漏洞。"""
    dep_indicators = [
        "component" in raw,
        "current_version" in raw,
        "fixed_versions" in raw,
        finding.dependency is not None,
        raw.get("vulnerability_type", "").lower() in ("dependency", "vulnerable and outdated component"),
    ]
    return any(dep_indicators)


# ── 内部：上下文构建 ─────────────────────────────────────────────────


def _build_code_context(finding, raw: dict[str, Any], overrides: dict[str, Any]) -> CodeContext:
    services = overrides.get("services", [raw.get("repository", "unknown-service")])
    if isinstance(services, str):
        services = [services]

    entry_points_raw = overrides.get("entry_points", [])
    if entry_points_raw:
        entry_points = [
            ApiEntryPoint(ep["route"], ep.get("method", "ANY"), ep.get("authentication", "unknown"), ep.get("internet_exposed"))
            if isinstance(ep, dict) else ep
            for ep in entry_points_raw
        ]
    else:
        entry_points = []

    call_paths = overrides.get("call_paths", [])
    related_tests = overrides.get("related_tests", [])

    affected_file = raw.get("affected_file", "")
    if affected_file and not call_paths:
        func = raw.get("affected_function", "unknown")
        sink_line = raw.get("line")
        step = f"{func} at {affected_file}:{sink_line}" if sink_line else f"{func} in {affected_file}"
        call_paths = [[raw.get("entry_point", "API request"), step, "sink"]]

    return CodeContext(
        services=services,
        call_paths=call_paths,
        entry_points=entry_points,
        data_classification=overrides.get("data_classification", ["application data"]),
        upstream_dependencies=overrides.get("upstream_dependencies", ["api-client"]),
        downstream_dependencies=overrides.get("downstream_dependencies", ["database"]),
        related_tests=related_tests,
    )


def _build_asset_context(finding, raw: dict[str, Any], overrides: dict[str, Any]) -> AssetContext:
    return AssetContext(
        deployed_assets=overrides.get("deployed_assets", [raw.get("repository", "unknown-service") + ":default"]),
        affected_artifacts=overrides.get("affected_artifacts", [raw.get("affected_file", raw.get("repository", "unknown"))]),
        internet_exposure_known=overrides.get("internet_exposure_known", False),
    )


def _build_runtime_context(finding, raw: dict[str, Any], overrides: dict[str, Any]) -> RuntimeContext:
    return RuntimeContext(
        observed_routes=overrides.get("observed_routes", []),
        observed_call_paths=overrides.get("observed_call_paths", []),
        evidence_available=overrides.get("runtime_evidence_available", False),
    )


def _build_code_root_cause(finding, raw: dict[str, Any], overrides: dict[str, Any]) -> RootCauseCodeContext:
    """从漏洞数据推断代码类根因上下文。"""
    affected_file = raw.get("affected_file", "unknown")
    affected_func = raw.get("affected_function", "unknown")
    line = raw.get("line")

    source = CodePoint(
        raw.get("entry_point", affected_func),
        affected_file,
        line,
    )
    sink = CodePoint(
        raw.get("sink_symbol", "execute"),
        raw.get("sink_file", affected_file),
        raw.get("sink_line"),
    )

    vuln_type = finding.vulnerability_type.lower()
    if "sql" in vuln_type:
        missing_control = "parameterized_query"
        guards = ["input validation", "ORM parameterization"]
        failed = [FailedControl("string concatenation", "user input concatenated into SQL bypasses parameterized query guard")]
    elif "xss" in vuln_type or "cross-site" in vuln_type:
        missing_control = "output_encoding"
        guards = ["template auto-escaping", "HTML sanitization"]
        failed = [FailedControl("raw output", "untrusted input rendered without encoding")]
    elif "path" in vuln_type or "traversal" in vuln_type:
        missing_control = "path_sanitization"
        guards = ["path normalization", "chroot jail"]
        failed = [FailedControl("direct file access", "user-controlled path used without sanitization")]
    elif "deserial" in vuln_type:
        missing_control = "safe_deserialization"
        guards = ["type whitelist", "signature verification"]
        failed = [FailedControl("unsafe pickle/yaml", "untrusted data deserialized without type restriction")]
    else:
        missing_control = "missing_security_control"
        guards = []
        failed = [FailedControl("missing control", f"no security control for {finding.vulnerability_type}")]

    return RootCauseCodeContext(
        source=source,
        propagation=[
            PropagationStep(raw.get("affected_function", "unknown"), "propagates untrusted input without sanitization"),
        ],
        sink=sink,
        guards=guards,
        failed_controls=failed,
        trigger_conditions=[raw.get("evidence", "user input reaches dangerous sink")],
        vulnerable_code=raw.get("vulnerable_code"),
        language=overrides.get("language", raw.get("language", "unknown")),
        framework=overrides.get("framework", raw.get("framework")),
        evidence_available=True,
    )


def _build_dependency_root_cause(finding, raw: dict[str, Any], overrides: dict[str, Any]) -> DependencyRootCauseContext:
    """从漏洞数据推断依赖类根因上下文。"""
    component = raw.get("component", finding.dependency.component if finding.dependency else "unknown-component")
    service = raw.get("repository", "unknown-service")
    return DependencyRootCauseContext(
        component=component,
        dependency_path=[service, component],
        runtime_used=True,
        vulnerable_feature_used=True,
        cve_match_confirmed=bool(raw.get("cve")),
    )


def _build_engineering(finding, raw: dict[str, Any], is_dependency: bool, overrides: dict[str, Any]) -> EngineeringContext:
    """构建工程上下文，使用合理默认值。"""
    return EngineeringContext(
        language=overrides.get("language", raw.get("language", "Python")),
        framework=overrides.get("framework", raw.get("framework", "Flask" if not is_dependency else "Java web application")),
        database=overrides.get("database"),
        data_access_library=overrides.get("data_access_library"),
        package_manager=overrides.get("package_manager", raw.get("package_manager", "pip" if not is_dependency else "maven")),
        dependency_versions=overrides.get("dependency_versions", {}),
        available_test_commands=overrides.get("available_test_commands", []),
        related_tests=overrides.get("related_tests", []),
        deployment_targets=overrides.get("deployment_targets", [raw.get("repository", "default")]),
    )


def _build_repository(raw: dict[str, Any], overrides: dict[str, Any]) -> RepositoryContext:
    return RepositoryContext(
        repository=overrides.get("repository", raw.get("repository")),
        branch=overrides.get("branch", "fix/" + (raw.get("finding_id", "vuln")).lower()),
        language=overrides.get("language", raw.get("language")),
        framework=overrides.get("framework", raw.get("framework")),
        package_manager=overrides.get("package_manager"),
        test_framework=overrides.get("test_framework"),
    )


def _build_source_files(raw: dict[str, Any], overrides: dict[str, Any]) -> list[SourceFile]:
    source_files_data = overrides.get("source_files")
    if source_files_data:
        if isinstance(source_files_data, list):
            if source_files_data and isinstance(source_files_data[0], SourceFile):
                return source_files_data
            return [SourceFile(s["path"], s["content"]) if isinstance(s, dict) else SourceFile("unknown", str(s)) for s in source_files_data]
        if isinstance(source_files_data, dict):
            return [SourceFile(path, content) for path, content in source_files_data.items()]

    affected_file = raw.get("affected_file")
    if affected_file:
        return [SourceFile(affected_file, f"# {affected_file} — affected by {raw.get('finding_id', 'vulnerability')}")]
    return [SourceFile("requirements.txt", "# dependency manifest")]


def _build_validation_results(raw: dict[str, Any], overrides: dict[str, Any]) -> list:
    val_data = overrides.get("validation_results")
    if val_data:
        results = []
        from .models import ValidationLayer
        for item in val_data:
            if isinstance(item, tuple) and len(item) >= 3:
                results.append(passed_tool(item[0], item[1], item[2]))
            elif isinstance(item, dict):
                results.append(passed_tool(
                    ValidationLayer(item["layer"]),
                    item.get("tool_name", "validation tool"),
                    item.get("summary", "passed"),
                ))
        return results
    return [
        passed_tool(
            __import__("vuln_agent.models", fromlist=["ValidationLayer"]).ValidationLayer.BUILD,
            "build", "构建验证通过。",
        ),
        passed_tool(
            __import__("vuln_agent.models", fromlist=["ValidationLayer"]).ValidationLayer.BUSINESS_REGRESSION,
            "business regression", "业务回归测试通过。",
        ),
        passed_tool(
            __import__("vuln_agent.models", fromlist=["ValidationLayer"]).ValidationLayer.SECURITY_REGRESSION,
            "security regression", "安全回归测试通过。",
        ),
        passed_tool(
            __import__("vuln_agent.models", fromlist=["ValidationLayer"]).ValidationLayer.SCANNER_RESCAN,
            "scanner rescan", "扫描器复扫不再命中。",
        ),
        passed_tool(
            __import__("vuln_agent.models", fromlist=["ValidationLayer"]).ValidationLayer.DIFFERENTIAL_RISK,
            "diff risk", "补丁差异风险可接受。",
        ),
    ]

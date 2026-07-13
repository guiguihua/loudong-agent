"""动态流水线执行器 — 输入漏洞 JSON + 源码，运行完整的 Agent 修复流水线。

5 个真正的 Agent（基于 BaseAgent，拥有工具和多轮推理能力）：
  ImpactAnalysis → RootCauseAnalysis → RemediationPlan → PatchGeneration → Validation
  失败时触发 FailureAnalysis → 重试（最多3次）
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .failure_analysis import FailureAnalysisAgent
from .evidence import EvidenceCollector
from .impact import ImpactAnalysisAgent
from .models import (
    ApiEntryPoint,
    CodePoint,
    EngineeringContext,
    FailedControl,
    PatchGenerationPolicy,
    PropagationStep,
    RemediationPolicy,
    RepositoryContext,
    SourceFile,
)
from .normalization import VulnerabilityNormalizer
from .orchestration import PatchRepairLoopOrchestrator
from .patching import PatchGenerationAgent
from .remediation import RemediationPlanAgent
from .reporting import RemediationReportAgent
from .root_cause import RootCauseAnalysisAgent
from .tools import (
    AssetContext,
    CodeContext,
    DependencyRootCauseContext,
    RootCauseCodeContext,
    RuntimeContext,
    StaticAssetInventoryTool,
    StaticCodeContextTool,
    StaticRootCauseEvidenceTool,
    StaticRuntimeEvidenceTool,
)
from .validation import ValidationToolchain, passed_tool, skipped_tool
from .execution import WorkspaceValidationExecutor

ROOT = Path(__file__).resolve().parents[2]


# ── 公共 API ─────────────────────────────────────────────────────────


def run_file(file_path: str | Path, **overrides: Any) -> dict[str, Any]:
    """从 JSON 文件加载漏洞并运行 Agent 修复流水线。

    用法:
        result = run_file("vulnerability.json")
        result = run_file("vulnerability.json", source_dir="./src",
                          language="Python", framework="Flask")

    返回包含 finding / impact / root_cause / patch_candidate /
    validation / report 等字段的完整结果字典。
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"文件不存在: {file_path}")
    raw = json.loads(path.read_text(encoding="utf-8"))
    return run_dict(raw, **overrides)


def run_dict(raw: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    """从字典运行 Agent 修复流水线。

    Args:
        raw: 漏洞数据字典
        **overrides: 可覆盖上下文（全部可选）
            language, framework, database, package_manager, test_framework,
            repository, branch, services, entry_points, call_paths,
            source_files (dict[str,str] 或 list[SourceFile]),
            source_dir (str — 加载目录下所有代码文件),
            validation_results, max_attempts
    """
    normalizer = VulnerabilityNormalizer()
    finding = normalizer.normalize(raw)

    # ── Agent 后端（始终使用 LLM）──
    from .llm import create_llm_backend
    llm = create_llm_backend()
    if llm:
        print(f"[Agent] 使用 {llm.model} 进行推理")
    else:
        raise RuntimeError(
            "未设置 DEEPSEEK_API_KEY 环境变量。\n"
            "请设置: $env:DEEPSEEK_API_KEY = 'sk-...'"
        )

    # ── 工作目录 ──
    source_dir = overrides.get("source_dir")
    workspace = Path(source_dir).resolve() if source_dir else Path.cwd()

    # ── 加载源文件 ──
    source_files_data = overrides.get("source_files")
    if source_files_data is None and source_dir:
        source_files_data = _load_source_dir(source_dir)

    # ── 推断漏洞类型 ──
    is_dependency = _is_dependency_type(raw, finding)

    # ── 构建上下文 ──
    eng = _build_engineering(finding, raw, is_dependency, overrides)
    repo = _build_repository(raw, overrides)
    sources = _build_source_files(raw, source_files_data, overrides)
    tool_results = _build_validation_results(raw, overrides)
    evidence_bundle = EvidenceCollector().collect(finding, sources, repo, eng)

    # ── 构建 Agent ──
    code_ctx = _build_code_context(finding, raw, overrides)
    asset_ctx = _build_asset_context(finding, raw, overrides)
    runtime_ctx = _build_runtime_context(finding, raw, overrides)

    impact = ImpactAnalysisAgent(
        StaticCodeContextTool({finding.finding_id: code_ctx}),
        StaticAssetInventoryTool({finding.finding_id: asset_ctx}),
        StaticRuntimeEvidenceTool({finding.finding_id: runtime_ctx}),
        llm=llm,
        workspace=workspace,
    ).analyze(finding, evidence_bundle)

    if is_dependency:
        root_cause_ctx = _build_dependency_root_cause(finding, raw, overrides)
    else:
        root_cause_ctx = _build_code_root_cause(finding, raw, overrides)

    rc_agent = RootCauseAnalysisAgent(
        StaticRootCauseEvidenceTool(
            code_contexts={finding.finding_id: root_cause_ctx}
            if isinstance(root_cause_ctx, RootCauseCodeContext) else {},
            dependency_contexts={finding.finding_id: root_cause_ctx}
            if isinstance(root_cause_ctx, DependencyRootCauseContext) else {},
        ),
        llm=llm,
        workspace=workspace,
    )
    root_cause_result = rc_agent.analyze(finding, impact, evidence_bundle)

    # ── 修复循环 ──
    max_attempts = overrides.get("max_attempts", 2)
    validation_commands = overrides.get("validation_commands", raw.get("validation_commands", {}))
    validation_executor = WorkspaceValidationExecutor(
        workspace=workspace,
        commands=validation_commands,
        timeout_seconds=int(overrides.get("validation_timeout", raw.get("validation_timeout", 300))),
    )
    loop = PatchRepairLoopOrchestrator(
        remediation_agent=RemediationPlanAgent(llm=llm, workspace=workspace),
        patch_generation_agent=PatchGenerationAgent(PatchGenerationPolicy(), llm=llm, workspace=workspace),
        validation_toolchain=ValidationToolchain(executor=validation_executor),
        failure_analysis_agent=FailureAnalysisAgent(llm=llm, workspace=workspace),
        report_agent=RemediationReportAgent(),
        max_attempts=max_attempts,
    )

    result = loop.run(
        finding, impact, root_cause_result,
        eng, repo, sources, [tool_results], evidence_bundle,
    )

    # ── 构建返回字典 ──
    output: dict[str, Any] = {
        "finding": finding.to_dict(),
        "impact": impact.to_dict(),
        "root_cause": root_cause_result.to_dict(),
        "evidence_bundle": evidence_bundle.to_dict(),
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


# ── 内部：类型推断 ───────────────────────────────────────────────────


def _is_dependency_type(raw: dict[str, Any], finding) -> bool:
    dep_indicators = [
        "component" in raw,
        "current_version" in raw,
        "fixed_versions" in raw,
        finding.dependency is not None,
        raw.get("vulnerability_type", "").lower() in ("dependency", "vulnerable and outdated component"),
    ]
    return any(dep_indicators)


# ── 内部：源码加载 ───────────────────────────────────────────────────


_SOURCE_EXTENSIONS = {
    ".py", ".java", ".js", ".ts", ".go", ".rs", ".c", ".cpp", ".h", ".hpp",
    ".rb", ".php", ".swift", ".kt", ".scala", ".cs", ".vb", ".sh", ".bash",
    ".xml", ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini", ".conf",
    ".txt", ".md", ".sql", ".html", ".css", ".jsx", ".tsx", ".vue", ".svelte",
    ".dockerfile", ".env",
}

_SOURCE_EXCLUDE_DIRS = {
    ".git", ".svn", "__pycache__", "node_modules", ".venv", "venv",
    ".tox", ".mypy_cache", ".pytest_cache", "dist", "build", "target",
    ".idea", ".vscode", ".claude",
}

_SOURCE_EXCLUDE_NAMES = {
    "package-lock.json", "yarn.lock", "poetry.lock", "pnpm-lock.yaml",
    "Cargo.lock", "Gemfile.lock", "pipfile.lock",
}


def _load_source_dir(source_dir: str) -> dict[str, str]:
    """从目录加载源码文件。"""
    src_path = Path(source_dir)
    if not src_path.exists():
        return {}

    files: dict[str, str] = {}
    for f in src_path.rglob("*"):
        if not f.is_file():
            continue
        if any(excl in f.parts for excl in _SOURCE_EXCLUDE_DIRS):
            continue
        if f.name in _SOURCE_EXCLUDE_NAMES:
            continue
        if f.suffix.lower() not in _SOURCE_EXTENSIONS and f.name.lower() not in _SOURCE_EXTENSIONS:
            continue
        try:
            content = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        try:
            rel = str(f.relative_to(src_path))
        except ValueError:
            rel = str(f)
        files[rel] = content

    if files:
        print(f"[源码] 从 {source_dir} 加载了 {len(files)} 个文件")
    return files


# ── 内部：上下文构建 ─────────────────────────────────────────────────


def _build_code_context(finding, raw: dict[str, Any], overrides: dict[str, Any]) -> CodeContext:
    services = overrides.get("services", [raw.get("repository", "unknown-service")])
    if isinstance(services, str):
        services = [services]

    entry_points_raw = overrides.get("entry_points", [])
    if entry_points_raw:
        entry_points = [
            ApiEntryPoint(ep["route"], ep.get("method", "ANY"),
                         ep.get("authentication", "unknown"), ep.get("internet_exposed"))
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
        services=services, call_paths=call_paths, entry_points=entry_points,
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
    affected_file = raw.get("affected_file", "unknown")
    affected_func = raw.get("affected_function", "unknown")
    line = raw.get("line")

    source = CodePoint(raw.get("entry_point", affected_func), affected_file, line)
    sink = CodePoint(
        raw.get("sink_symbol", "execute"),
        raw.get("sink_file", affected_file),
        raw.get("sink_line"),
    )

    # 提供最小线索，Agent 会自己探索
    return RootCauseCodeContext(
        source=source,
        propagation=[
            PropagationStep(raw.get("affected_function", "unknown"),
                          "propagates untrusted input without sanitization"),
        ],
        sink=sink,
        guards=[],
        failed_controls=[FailedControl("missing control", f"no security control for {finding.vulnerability_type}")],
        trigger_conditions=[raw.get("evidence", "user input reaches dangerous sink")],
        vulnerable_code=raw.get("vulnerable_code"),
        language=overrides.get("language", raw.get("language", "unknown")),
        framework=overrides.get("framework", raw.get("framework")),
        evidence_available=True,
    )


def _build_dependency_root_cause(finding, raw: dict[str, Any], overrides: dict[str, Any]) -> DependencyRootCauseContext:
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


def _build_source_files(
    raw: dict[str, Any],
    source_files_data: dict[str, str] | list | None,
    overrides: dict[str, Any],
) -> list[SourceFile]:
    if source_files_data is None:
        source_files_data = overrides.get("source_files")
    if source_files_data:
        if isinstance(source_files_data, list):
            if source_files_data and isinstance(source_files_data[0], SourceFile):
                return source_files_data
            return [SourceFile(s["path"], s["content"]) if isinstance(s, dict) else SourceFile("unknown", str(s))
                    for s in source_files_data]
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
                    ValidationLayer(item["layer"]), item.get("tool_name", "validation tool"),
                    item.get("summary", "passed"),
                ))
        return results
    from .models import ValidationLayer
    # 当没有真实验证结果时，标记为 SKIPPED 而非 PASSED。
    # 真实验证需要外部 CI/CD 系统提供构建/测试/扫描结果。
    return [
        skipped_tool(ValidationLayer.BUILD, "build", "未提供真实构建输出——需在 CI/CD 中验证。"),
        skipped_tool(ValidationLayer.BUSINESS_REGRESSION, "business regression", "未提供真实测试输出——需人工验证业务行为不变。"),
        skipped_tool(ValidationLayer.SECURITY_REGRESSION, "security regression", "未提供真实安全测试——需人工验证漏洞已修复。"),
        skipped_tool(ValidationLayer.SCANNER_RESCAN, "scanner rescan", "未提供真实扫描输出——需复扫确认漏洞不再命中。"),
        skipped_tool(ValidationLayer.DIFFERENTIAL_RISK, "diff risk", "未提供真实 diff 审查——需人工审查补丁变更范围。"),
    ]

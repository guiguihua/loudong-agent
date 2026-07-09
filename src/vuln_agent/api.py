"""REST API — 提供漏洞分析和修复流水线的 HTTP 接口。

端点:
  GET  /health                 健康检查
  POST /v1/findings/analyze    分析（标准化 + 影响面 + 根因）
  POST /v1/findings/fix        完整修复流水线（分析 + 补丁生成 + 验证）
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI

from .impact import ImpactAnalysisAgent
from .models import EngineeringContext, PatchGenerationPolicy, RemediationPolicy, RepositoryContext, SourceFile
from .normalization import VulnerabilityNormalizer
from .orchestration import PatchRepairLoopOrchestrator
from .patching import PatchGenerationAgent
from .remediation import RemediationPlanAgent
from .reporting import RemediationReportAgent
from .root_cause import RootCauseAnalysisAgent
from .failure_analysis import FailureAnalysisAgent
from .runner import run_dict
from .tools import (
    StaticAssetInventoryTool,
    StaticCodeContextTool,
    StaticRootCauseEvidenceTool,
    StaticRuntimeEvidenceTool,
)
from .validation import ValidationToolchain

app = FastAPI(title="Vulnerability Fix Agent API", version="0.2.0")

# 分析服务（轻量，仅标准化+影响面+根因）
from .service import IntakeImpactService

analyze_service = IntakeImpactService(
    normalizer=VulnerabilityNormalizer(),
    impact_agent=ImpactAnalysisAgent(
        code_tool=StaticCodeContextTool({}),
        asset_tool=StaticAssetInventoryTool({}),
        runtime_tool=StaticRuntimeEvidenceTool({}),
    ),
    root_cause_agent=RootCauseAnalysisAgent(StaticRootCauseEvidenceTool()),
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/findings/analyze")
def analyze_finding(payload: dict[str, Any]) -> dict[str, Any]:
    """分析漏洞 — 标准化 + 影响面评估 + 根因分析。"""
    return analyze_service.process(payload)


@app.post("/v1/findings/fix")
def fix_finding(payload: dict[str, Any]) -> dict[str, Any]:
    """完整修复流水线 — 从漏洞报告到补丁和报告。

    请求体:
    {
        // 漏洞信息（以下为最简字段，完整字段参考 examples/）
        "finding_id": "F-001",
        "vulnerability_type": "SQL Injection",
        "severity": "high",
        "affected_file": "src/api/search.py",
        "evidence": "...",
        "scanner": "SAST",

        // 源码（可选，用于补丁生成）
        "source_files": {
            "src/api/search.py": "def search_users(q): ...",
            "requirements.txt": "flask==2.3.0"
        },

        // 上下文覆盖（全部可选）
        "language": "Python",
        "framework": "Flask",
        "database": "PostgreSQL",
        "repository": "my-service",
        "use_llm": true
    }
    """
    # 提取 source_files
    source_files_raw = payload.pop("source_files", {})
    source_files: dict[str, str] = {}
    if isinstance(source_files_raw, dict):
        source_files = source_files_raw
    elif isinstance(source_files_raw, list):
        for item in source_files_raw:
            if isinstance(item, dict):
                source_files[item.get("path", item.get("file", ""))] = item.get("content", "")
            else:
                source_files[str(item)] = ""

    use_llm = payload.pop("use_llm", False)

    # 提取上下文覆盖
    overrides = {
        k: v for k, v in payload.items()
        if k in (
            "language", "framework", "database", "package_manager",
            "repository", "branch", "services", "entry_points",
            "call_paths", "test_framework", "max_attempts",
        )
    }

    # 漏洞数据
    finding_data = {
        k: v for k, v in payload.items()
        if k not in overrides
    }

    result = run_dict(
        finding_data,
        use_llm=use_llm,
        source_files=source_files,
        **overrides,
    )
    return result

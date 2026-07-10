"""ImpactAnalysisAgent — 分析漏洞影响面。

继承 BaseAgent，拥有 read_file / search_code / list_dir 工具，
能自己探索代码库来确定受影响服务、API 入口和攻击面。
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from .agent import BaseAgent, create_default_tools
from .models import (
    ApiEntryPoint,
    AssessmentStatus,
    Confidence,
    Evidence,
    ImpactAssessment,
    NormalizedVulnerability,
)
from .tools import AssetInventoryTool, CodeContextTool, RuntimeEvidenceTool

if TYPE_CHECKING:
    from .llm import LLMBackend

IMPACT_AGENT_PROMPT = """你是一位应用安全工程师，负责分析安全漏洞的影响面。

## 你的任务
根据漏洞报告和代码库，推理并输出：
1. 受影响的服务/组件
2. 可触发漏洞的 API 入口点
3. 从入口到危险操作的调用路径
4. 受影响的资产和数据
5. 建议的回归测试

## 可用工具
- read_file: 读取源码文件
- search_code: 搜索代码中的路由、API 定义、函数调用
- list_dir: 浏览项目目录结构

## 工作方式
1. 先读漏洞报告中指出的文件
2. 搜索相关的路由/入口点定义
3. 追踪调用链，理解数据如何流动
4. 最后给出完整的 JSON 格式影响面评估

在确认收集到足够信息后，直接输出 JSON 结果，不要再调用工具。"""


class ImpactAnalysisAgent(BaseAgent):
    """分析漏洞影响面 — 真正的 Agent，能自己读代码探索。"""

    def __init__(
        self,
        code_tool: CodeContextTool,
        asset_tool: AssetInventoryTool,
        runtime_tool: RuntimeEvidenceTool,
        llm: LLMBackend | None = None,
        workspace: Path | None = None,
    ):
        ws = workspace or Path.cwd()
        super().__init__(
            name="ImpactAnalysis",
            system_prompt=IMPACT_AGENT_PROMPT,
            tools=create_default_tools(ws),
            llm=llm,
            max_turns=10,
            workspace=ws,
        )
        self.code_tool = code_tool
        self.asset_tool = asset_tool
        self.runtime_tool = runtime_tool

    def analyze(self, finding: NormalizedVulnerability) -> ImpactAssessment:
        """运行 Impact Analysis Agent。"""
        from .llm import IMPACT_SCHEMA
        self.output_schema = IMPACT_SCHEMA

        task = self._build_task(finding)
        raw = self.run(task)

        if "_raw_output" in raw:
            return self._dict_to_assessment(finding, {"reasoning": raw["_raw_output"]})
        return self._dict_to_assessment(finding, raw)

    def _build_task(self, finding: NormalizedVulnerability) -> str:
        """构建 Agent 任务描述。"""
        code = self.code_tool.collect(finding)
        assets = self.asset_tool.collect(finding)
        runtime = self.runtime_tool.collect(finding)

        locs = [f"{loc.file}:{loc.line}" for loc in finding.locations if loc.line] if finding.locations else ["unknown"]

        return f"""分析以下漏洞的影响面：

## 漏洞信息
- ID: {finding.finding_id}
- 类型: {finding.vulnerability_type}
- 严重性: {finding.severity.value}
- 来源: {finding.scanner}
- 受影响文件: {', '.join(locs)}
- 证据: {'; '.join(finding.evidence) if finding.evidence else '无'}
- 建议: {finding.recommendation or '未提供'}
- 仓库: {finding.repository or 'unknown'}
{f'- 依赖组件: {finding.dependency.component} {finding.dependency.current_version}' if finding.dependency else ''}

## 已知上下文
- 服务: {code.services or '未提供（请探索代码后推断）'}
- 入口点: {[(e.route, e.method) for e in code.entry_points] or '未提供'}
- 调用路径: {code.call_paths or '未提供'}
- 资产: {assets.deployed_assets or '未提供'}
- 运行时路径: {runtime.observed_call_paths or runtime.observed_routes or '未提供'}

## 要求
请先读代码文件确认服务、路由和调用关系，再给出影响面评估。
如果你不确定某项信息，可以在 unknowns 中列出。"""

    @staticmethod
    def _dict_to_assessment(finding: NormalizedVulnerability, raw: dict) -> ImpactAssessment:
        """将 LLM 输出转为 ImpactAssessment。"""
        from .models import Evidence as Ev
        evidence = [
            Ev("llm-impact", "agent_reasoning", "Agent 探索代码后推理的影响面评估",
               raw.get("reasoning", ""), Confidence.MEDIUM)
        ]
        return ImpactAssessment(
            finding_id=finding.finding_id,
            status=AssessmentStatus(raw.get("status", "unknown")),
            affected_services=raw.get("affected_services", []),
            entry_points=[
                ApiEntryPoint(
                    ep.get("route", ""), ep.get("method", "ANY"),
                    ep.get("authentication", "unknown"), ep.get("internet_exposed"),
                )
                for ep in raw.get("entry_points", [])
            ],
            call_paths=raw.get("call_paths", []),
            affected_assets=raw.get("affected_assets", []),
            affected_artifacts=raw.get("affected_artifacts", []),
            data_classification=raw.get("data_classification", []),
            upstream_dependencies=raw.get("upstream_dependencies", []),
            downstream_dependencies=raw.get("downstream_dependencies", []),
            regression_targets=raw.get("regression_targets", []),
            suggested_tests=raw.get("suggested_tests", []),
            evidence=evidence,
            unknowns=raw.get("unknowns", []),
            confidence_score=float(raw.get("confidence_score", 0.5)),
            needs_human_review=bool(raw.get("needs_human_review", True)),
        )

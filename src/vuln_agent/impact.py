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

在确认收集到足够信息后，调用 submit_final_result 工具提交最终结果。"""


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
            max_turns=15,
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
            extracted = self._extract_impact_from_raw(raw["_raw_output"], finding)
            return self._dict_to_assessment(finding, extracted)
        return self._dict_to_assessment(finding, raw)

    def _extract_impact_from_raw(
        self,
        raw_text: str,
        finding: NormalizedVulnerability,
    ) -> dict:
        """从非结构化的影响面分析文本中二次提取结构化字段。"""
        if not self.llm:
            return ImpactAnalysisAgent._fallback_impact_extraction(raw_text, finding)

        from .llm import IMPACT_SCHEMA

        locs = [f"{loc.file}:{loc.line}" for loc in finding.locations if loc.line]
        extraction_prompt = f"""以下是一段漏洞影响面分析的原始文本。请从中提取关键信息，填入指定 JSON 结构。

## 漏洞基本信息
- ID: {finding.finding_id}
- 类型: {finding.vulnerability_type}
- 文件: {', '.join(locs) if locs else 'unknown'}
- 证据: {'; '.join(finding.evidence) if finding.evidence else '无'}

## 原始分析文本
{raw_text[:8000]}

## 要求
请仔细阅读上面的分析文本，尽量提取所有你能找到的结构化信息。
如果某个字段在文本中找不到对应信息，使用合理的默认值（空数组/unknown），不要编造。"""

        try:
            structured = self.llm.reason(
                user_prompt=extraction_prompt,
                system_prompt="你是一个结构化数据提取器。从安全分析文本中提取影响面信息并填入 JSON。只输出 JSON。",
                output_schema={
                    "type": "object",
                    "description": "从原始分析文本中提取的影响面评估",
                    "properties": {
                        k: v for k, v in IMPACT_SCHEMA.get("properties", {}).items()
                        if k not in ("reasoning",)
                    },
                    "required": ["status", "affected_services", "entry_points", "call_paths", "unknowns", "confidence_score", "needs_human_review"],
                },
                temperature=0.1,
            )
            if isinstance(structured, dict) and structured.get("affected_services"):
                return structured
        except Exception:
            pass

        return ImpactAnalysisAgent._fallback_impact_extraction(raw_text, finding)

    @staticmethod
    def _fallback_impact_extraction(raw_text: str, finding: NormalizedVulnerability) -> dict:
        """LLM 不可用时的纯文本回退 — 从分析文本和漏洞报告中提取影响面信息。"""
        import re

        result: dict = {
            "status": "possible",
            "affected_services": [],
            "entry_points": [],
            "call_paths": [],
            "affected_assets": [],
            "affected_artifacts": [],
            "data_classification": [],
            "upstream_dependencies": [],
            "downstream_dependencies": [],
            "regression_targets": [],
            "suggested_tests": [],
            "unknowns": [],
            "confidence_score": 0.3,
            "needs_human_review": True,
            "reasoning": "",
        }

        # 1. Try to find JSON block
        json_match = re.search(r'\{[^{}]*"affected_services"[^{}]*\}', raw_text, re.DOTALL)
        if not json_match:
            json_match = re.search(r'\{[^{}]*"entry_points"[^{}]*\}', raw_text, re.DOTALL)
        if json_match:
            import json as _json
            try:
                parsed = _json.loads(json_match.group(0))
                if isinstance(parsed, dict):
                    for k, v in parsed.items():
                        if k in result and v:
                            result[k] = v
            except (_json.JSONDecodeError, ValueError):
                pass

        # 2. Extract affected services from text patterns
        service_patterns = [
            r'(?:受影响|影响)\s*(?:服务|组件|系统)[：:\s]*(.+?)(?:\n|$)',
            r'(?:affected.service|impacted.service)[：:\s]*(.+?)(?:\n|$)',
        ]
        for pat in service_patterns:
            match = re.search(pat, raw_text, re.IGNORECASE)
            if match and not result.get("affected_services"):
                services = [s.strip() for s in re.split(r'[,，、]', match.group(1)) if s.strip()]
                result["affected_services"] = services[:10]
                break

        # 3. Build meaningful fallback from finding data
        locs = [f"{loc.file}:{loc.line}" for loc in finding.locations if loc.line]
        evidence_text = "; ".join(e for e in (finding.evidence or []) if e.strip())

        if not result["affected_services"]:
            # Infer from vulnerability context
            if finding.repository:
                result["affected_services"] = [finding.repository]
            elif finding.dependency:
                result["affected_services"] = [
                    f"所有使用 {finding.dependency.component} 的下游应用和服务"
                ]
            elif locs:
                result["affected_services"] = [
                    f"{finding.vulnerability_type} 相关的认证/授权服务",
                    f"受影响文件: {', '.join(locs[:3])}"
                ]
            else:
                result["affected_services"] = [
                    f"受 {finding.vulnerability_type} 影响的服务组件（需人工确认具体范围）"
                ]

        if not result["entry_points"] and locs:
            result["entry_points"] = [
                {
                    "route": f"{finding.vulnerability_type} 触发入口",
                    "method": "ANY",
                    "authentication": "unknown",
                    "internet_exposed": None,
                }
            ]

        if not result["call_paths"] and locs:
            func = finding.locations[0].function if finding.locations and finding.locations[0].function else "unknown"
            result["call_paths"] = [[
                f"外部输入/请求",
                f"{func} @ {locs[0]}",
                f"{finding.vulnerability_type} 危险操作"
            ]]

        if not result["data_classification"] and evidence_text:
            result["data_classification"] = [f"受影响数据（证据: {evidence_text[:100]}）"]

        if not result["regression_targets"]:
            result["regression_targets"] = [
                f"{finding.vulnerability_type} 安全回归",
                "认证/授权行为回归",
            ]

        if not result["suggested_tests"]:
            result["suggested_tests"] = [
                f"验证 {finding.vulnerability_type} 的利用条件在修复后是否被阻断",
                "验证正常认证流程不受影响",
            ]

        result["reasoning"] = (
            f"影响面分析从非结构化文本中尽力提取。"
            f"漏洞类型: {finding.vulnerability_type}。"
            f"{' 证据: ' + evidence_text[:200] if evidence_text else ''}"
        )
        return result

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

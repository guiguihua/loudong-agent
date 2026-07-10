"""RootCauseAnalysisAgent — 分析漏洞根因。

继承 BaseAgent，拥有 read_file / search_code 工具，
能自己读代码追踪 source-to-sink 数据流，识别缺失的安全控制。
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from .agent import BaseAgent, create_default_tools
from .models import (
    AffectedCode,
    AlternativeHypothesis,
    AssessmentStatus,
    CodePoint,
    Confidence,
    Evidence,
    FailedControl,
    ImpactAssessment,
    NormalizedVulnerability,
    PropagationStep,
    RootCause,
    RootCauseAssessment,
    RootCauseCategory,
)
from .tools import DependencyRootCauseContext, RootCauseCodeContext, RootCauseEvidenceTool

if TYPE_CHECKING:
    from .llm import LLMBackend

ROOT_CAUSE_AGENT_PROMPT = """你是一位资深安全研究员，负责分析漏洞的完整根因。

## 你的任务
追踪不可信数据的完整数据流：
1. Source: 不可信输入从哪里进入系统？
2. Propagation: 经过哪些步骤传播？
3. Sink: 最终到达哪个危险操作（SQL执行、命令执行、文件读写等）？
4. Missing Control: 缺失了什么安全控制？

## 可用工具
- read_file: 读取源码文件的具体行范围
- search_code: 搜索代码中的危险函数调用（execute、eval、open、render 等）

## 工作方式
1. 先读漏洞报告中指出的文件
2. 搜索代码中相关的危险函数
3. 追踪变量从入口到危险操作的数据流
4. 识别路径上缺失或失效的安全控制
5. 给出安全不变量和修复约束

确认分析完成后，直接输出 JSON 结果。"""


class RootCauseAnalysisAgent(BaseAgent):
    """分析漏洞根因 — 自己读代码追踪数据流。"""

    def __init__(
        self,
        evidence_tool: RootCauseEvidenceTool,
        llm: LLMBackend | None = None,
        workspace: Path | None = None,
    ):
        ws = workspace or Path.cwd()
        super().__init__(
            name="RootCauseAnalysis",
            system_prompt=ROOT_CAUSE_AGENT_PROMPT,
            tools=create_default_tools(ws),
            llm=llm,
            max_turns=10,
            workspace=ws,
        )
        self.evidence_tool = evidence_tool

    def analyze(
        self,
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
    ) -> RootCauseAssessment:
        """运行 Root Cause Analysis Agent。"""
        from .llm import ROOT_CAUSE_SCHEMA
        self.output_schema = ROOT_CAUSE_SCHEMA

        task = self._build_task(finding, impact)
        raw = self.run(task)

        if "_raw_output" in raw:
            return self._dict_to_root_cause(finding, {"summary": raw["_raw_output"]})
        return self._dict_to_root_cause(finding, raw)

    def _build_task(
        self,
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
    ) -> str:
        """构建根因分析任务。"""
        code = self.evidence_tool.collect_code_evidence(finding)
        locs = [f"{loc.file}:{loc.line}" for loc in finding.locations if loc.line]

        return f"""分析以下漏洞的根因：

## 漏洞信息
- ID: {finding.finding_id}
- 类型: {finding.vulnerability_type}
- 严重性: {finding.severity.value}
- 文件: {', '.join(locs) if locs else 'unknown'}
- 函数: {finding.locations[0].function if finding.locations and finding.locations[0].function else 'unknown'}
- 证据: {'; '.join(finding.evidence) if finding.evidence else '无'}
- 建议: {finding.recommendation or '未提供'}

## 影响面
- 服务: {impact.affected_services}
- 入口点: {[(e.route, e.method) for e in impact.entry_points]}
- 调用路径: {impact.call_paths}

## 代码线索
- Source: {code.source.symbol + ' @ ' + code.source.file if code.source else 'unknown'}
- Sink: {code.sink.symbol + ' @ ' + code.sink.file if code.sink else 'unknown'}
- 传播步骤: {[(s.symbol, s.operation) for s in code.propagation] if code.propagation else 'unknown'}
- 已有守卫: {code.guards or 'none'}
- 失效控制: {[(c.control, c.reason) for c in code.failed_controls] if code.failed_controls else 'none'}
- 触发条件: {code.trigger_conditions or 'unknown'}
- 语言: {code.language or 'unknown'}
- 框架: {code.framework or 'unknown'}

## 要求
请先读相关源码文件，追踪完整的 source-to-sink 数据流。
识别缺失的安全控制，给出安全不变量和修复约束。"""

    @staticmethod
    def _dict_to_root_cause(finding: NormalizedVulnerability, raw: dict) -> RootCauseAssessment:
        """将 LLM 输出转为 RootCauseAssessment。"""
        source_raw = raw.get("source", {}) or {}
        sink_raw = raw.get("sink", {}) or {}
        evidence = [
            Evidence("llm-root-cause", "agent_reasoning", "Agent 探索代码后推理的根因分析",
                     raw.get("reasoning", ""), Confidence.MEDIUM)
        ]
        return RootCauseAssessment(
            finding_id=finding.finding_id,
            status=AssessmentStatus(raw.get("status", "probable")),
            root_cause_category=RootCauseCategory(raw.get("root_cause_category", "unknown")),
            root_cause=RootCause(
                summary=raw.get("summary", ""),
                source=CodePoint(source_raw.get("symbol", ""), source_raw.get("file"), source_raw.get("line"))
                if source_raw else None,
                propagation=[PropagationStep(p["symbol"], p["operation"]) for p in raw.get("propagation", [])],
                sink=CodePoint(sink_raw.get("symbol", ""), sink_raw.get("file"), sink_raw.get("line"))
                if sink_raw else None,
                missing_control=raw.get("missing_control"),
                failed_existing_controls=[
                    FailedControl(fc["control"], fc["reason"])
                    for fc in raw.get("failed_existing_controls", [])
                ],
                trigger_conditions=raw.get("trigger_conditions", []),
            ),
            contributing_factors=raw.get("contributing_factors", []),
            causal_chain=raw.get("causal_chain", []),
            affected_code=[
                AffectedCode(ac["file"], ac.get("function"), ac.get("lines", []), ac.get("role", "primary_cause"))
                for ac in raw.get("affected_code", [])
            ],
            evidence=evidence,
            alternative_hypotheses=[
                AlternativeHypothesis(ah["hypothesis"], ah["result"], ah["reason"])
                for ah in raw.get("alternative_hypotheses", [])
            ],
            confidence_score=float(raw.get("confidence_score", 0.5)),
            unknowns=raw.get("unknowns", []),
            needs_human_review=bool(raw.get("needs_human_review", True)),
            recommended_fix_constraints=raw.get("recommended_fix_constraints", []),
            security_invariant=raw.get("security_invariant"),
            guardrail=raw.get("guardrail"),
            broken_mechanism=raw.get("broken_mechanism", []),
            exploitability_note=raw.get("exploitability_note"),
        )

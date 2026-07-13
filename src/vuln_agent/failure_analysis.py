"""FailureAnalysisAgent — 诊断补丁验证失败根因。

继承 BaseAgent，拥有 read_file / run_shell 工具，
能读失败日志、运行测试、诊断问题根因。
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from .agent import BaseAgent, create_default_tools
from .models import (
    FailureAnalysisResult,
    FailureCategory,
    FailureFinding,
    FailureSeverity,
    PatchCandidate,
    PatchValidationStatus,
    RemediationFeedbackTarget,
    RemediationPlan,
    ValidationLayer,
    ValidationToolchainResult,
)

if TYPE_CHECKING:
    from .llm import LLMBackend

FAILURE_AGENT_PROMPT = """你是一位 CI/CD 安全验证专家，负责诊断补丁验证失败的根本原因。

## 你的任务
分析验证失败的原因，分类为：
- build_failure: 编译/构建失败
- business_regression: 业务回归（原有功能被破坏）
- security_not_fixed: 安全验证（漏洞未修复）
- scanner_still_reports: 扫描器仍报告
- differential_risk: 补丁范围过大或有风险
- patch_policy_violation: 补丁策略违规
- tooling_gap: 验证工具缺失

## 可用工具
- read_file: 读取失败的测试文件或日志
- run_shell: 重新运行测试验证失败原因

## 工作方式
1. 分析每层验证失败的具体原因
2. 必要时用 run_shell 复现问题（控制在 3 次以内）
3. 给出具体可执行的修复建议
4. 分析完成后**必须立即**调用 submit_final_result 提交诊断结果

确认诊断完毕后，调用 submit_final_result 工具提交最终结果。"""


class FailureAnalysisAgent(BaseAgent):
    """诊断验证失败 — 读日志、跑命令、定位根因。"""

    def __init__(
        self,
        llm: LLMBackend | None = None,
        workspace: Path | None = None,
    ):
        ws = workspace or Path.cwd()
        super().__init__(
            name="FailureAnalysis",
            system_prompt=FAILURE_AGENT_PROMPT,
            tools=create_default_tools(ws, include_shell=True),
            llm=llm,
            max_turns=12,
            workspace=ws,
        )

    def analyze(
        self,
        validation: ValidationToolchainResult,
        candidate: PatchCandidate,
        remediation_plan: RemediationPlan,
    ) -> FailureAnalysisResult:
        """运行 Failure Analysis Agent。"""
        if validation.status != PatchValidationStatus.FAILED:
            return FailureAnalysisResult(
                patch_id=candidate.patch_id,
                finding_id=candidate.finding_id,
                primary_category=FailureCategory.UNKNOWN,
                summary="validation passed; no failure analysis required",
                findings=[], route_to=RemediationFeedbackTarget.HUMAN_REVIEW,
                remediation_feedback=[], patch_generation_feedback=[],
                validation_feedback=[], requires_root_cause_recheck=False,
                needs_human_review=False,
            )

        from .llm import FAILURE_ANALYSIS_SCHEMA
        self.output_schema = FAILURE_ANALYSIS_SCHEMA

        task = self._build_task(validation, candidate, remediation_plan)
        raw = self.run(task)

        if "_raw_output" in raw:
            return self._dict_to_analysis(candidate, {"summary": raw["_raw_output"]})
        return self._dict_to_analysis(candidate, raw)

    @staticmethod
    def _build_task(
        validation: ValidationToolchainResult,
        candidate: PatchCandidate,
        remediation_plan: RemediationPlan,
    ) -> str:
        layers_detail = []
        for layer in validation.layers:
            status = layer.status.value
            layers_detail.append(f"- {layer.layer.value}: {status} — {layer.summary}")
            for tool in layer.tool_results:
                layers_detail.append(f"  - {tool.tool_name}: {tool.status.value} ({tool.summary})")

        return f"""补丁验证失败，请诊断原因：

## 补丁信息
- patch_id: {candidate.patch_id}
- finding_id: {candidate.finding_id}
- 摘要: {candidate.summary}

## 验证层结果
{chr(10).join(layers_detail)}

## 修复方案
- 目标: {remediation_plan.remediation_goal}

## 要求
分析每层失败的原因，分类并给出具体可执行的修复建议。
如果可能，用 run_shell 重新运行相关命令来确认失败原因。"""

    @staticmethod
    def _dict_to_analysis(
        candidate: PatchCandidate,
        raw: dict,
    ) -> FailureAnalysisResult:
        findings = [
            FailureFinding(
                category=FailureCategory(f.get("category", "unknown")),
                severity=FailureSeverity(f.get("severity", "high")),
                failed_layer=ValidationLayer(f["failed_layer"]) if f.get("failed_layer") else None,
                summary=f.get("summary", ""),
                evidence=f.get("evidence", []),
                suspected_reason=f.get("suspected_reason", ""),
                suggested_adjustment=f.get("suggested_adjustment", ""),
            )
            for f in raw.get("findings", [])
        ]
        primary = findings[0].category if findings else FailureCategory.UNKNOWN
        return FailureAnalysisResult(
            patch_id=candidate.patch_id,
            finding_id=candidate.finding_id,
            primary_category=primary,
            summary=raw.get("summary", ""),
            findings=findings,
            route_to=RemediationFeedbackTarget.REMEDIATION_PLAN_AGENT,
            remediation_feedback=raw.get("remediation_feedback", []),
            patch_generation_feedback=raw.get("patch_generation_feedback", []),
            validation_feedback=raw.get("validation_feedback", []),
            requires_root_cause_recheck=bool(raw.get("requires_root_cause_recheck", False)),
            needs_human_review=bool(raw.get("needs_human_review", True)),
        )

"""RemediationPlanAgent — 制定修复方案。

继承 BaseAgent，拥有 read_file / search_code / list_dir 工具，
能自己探索项目结构，选择最优修复策略（代码修改/依赖升级/配置变更）。
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from .agent import BaseAgent, create_default_tools
from .models import (
    CompatibilityAssessment,
    DependencyUpgradePlan,
    EngineeringContext,
    FailureAnalysisResult,
    ImpactAssessment,
    NormalizedVulnerability,
    PatchBoundaries,
    PlannedChange,
    RejectedAlternative,
    RemediationPlan,
    RemediationPlanStatus,
    RemediationStrategy,
    RemediationStrategyType,
    RollbackPlan,
    RootCauseAssessment,
    Severity,
    TestPlanItem,
)

if TYPE_CHECKING:
    from .llm import LLMBackend

REMEDIATION_AGENT_PROMPT = """你是一位资深安全修复工程师，负责为漏洞设计最优修复方案。

## 你的任务
根据根因分析和影响面评估，制定修复方案：
1. 选择修复策略（code_change / dependency_upgrade / configuration_change）
2. 列出计划变更的文件和原因
3. 评估风险和兼容性
4. 定义必需的回归测试
5. 制定回滚方案

## 可用工具
- read_file: 读取源码或配置文件
- search_code: 搜索相关代码模式
- list_dir: 了解项目结构（构建文件、测试目录等）

## 工作方式
1. 了解项目的构建系统和测试框架
2. 评估不同修复策略的优劣
3. 选择最优策略并给出具体步骤
4. 考虑向后兼容性和回滚

确认分析完成后，直接输出 JSON 结果。"""


class RemediationPlanAgent(BaseAgent):
    """制定修复方案 — 自主选择最优策略。"""

    def __init__(
        self,
        llm: LLMBackend | None = None,
        workspace: Path | None = None,
    ):
        ws = workspace or Path.cwd()
        super().__init__(
            name="RemediationPlan",
            system_prompt=REMEDIATION_AGENT_PROMPT,
            tools=create_default_tools(ws),
            llm=llm,
            max_turns=8,
            workspace=ws,
        )

    def plan(
        self,
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
        root_cause: RootCauseAssessment,
        engineering: EngineeringContext | None = None,
        failure_analysis: FailureAnalysisResult | None = None,
    ) -> RemediationPlan:
        """运行 Remediation Plan Agent。"""
        from .llm import REMEDIATION_PLAN_SCHEMA
        self.output_schema = REMEDIATION_PLAN_SCHEMA

        engineering = engineering or EngineeringContext()
        task = self._build_task(finding, impact, root_cause, engineering, failure_analysis)
        raw = self.run(task)

        if "_raw_output" in raw:
            return self._dict_to_plan(finding, impact, root_cause, engineering, {"remediation_goal": raw["_raw_output"]}, failure_analysis)
        return self._dict_to_plan(finding, impact, root_cause, engineering, raw, failure_analysis)

    @staticmethod
    def _build_task(
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
        root_cause: RootCauseAssessment,
        engineering: EngineeringContext,
        failure_analysis: FailureAnalysisResult | None,
    ) -> str:
        constraints = "\n".join(
            f"- {c}" for c in root_cause.recommended_fix_constraints
        ) if root_cause.recommended_fix_constraints else "无"

        fb = ""
        if failure_analysis:
            fb = (
                f"\n## 上次失败反馈\n"
                f"- 原因: {failure_analysis.summary}\n"
                f"- 建议: {'; '.join(failure_analysis.remediation_feedback)}\n"
            )

        return f"""为以下漏洞设计修复方案：

## 漏洞
- ID: {finding.finding_id}
- 类型: {finding.vulnerability_type}
- 根因: {root_cause.root_cause.summary}
- 缺失控制: {root_cause.root_cause.missing_control}
- 根因分类: {root_cause.root_cause_category.value}

## 修复约束
{constraints}

## 影响面
- 服务: {impact.affected_services}
- 入口: {[(e.route, e.method) for e in impact.entry_points]}
- 数据分类: {impact.data_classification}

## 工程上下文
- 语言: {engineering.language or 'unknown'}
- 框架: {engineering.framework or 'unknown'}
- 包管理器: {engineering.package_manager or 'unknown'}
- 测试命令: {engineering.available_test_commands or 'none'}
{fb}
请先了解项目结构，然后选择最优修复策略并给出具体步骤。"""

    @staticmethod
    def _dict_to_plan(
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
        root_cause: RootCauseAssessment,
        engineering: EngineeringContext,
        raw: dict,
        failure_analysis: FailureAnalysisResult | None,
    ) -> RemediationPlan:
        """将 LLM 输出转为 RemediationPlan。"""
        status = RemediationPlanStatus(raw.get("status", "ready"))
        strategies = [
            RemediationStrategy(
                strategy_type=RemediationStrategyType(s["strategy_type"]),
                summary=s["summary"],
                steps=s.get("steps", []),
                preferred=s.get("preferred", True),
            )
            for s in raw.get("strategies", [])
        ]
        planned_changes = [
            PlannedChange(
                file=pc["file"], change_type=pc["change_type"],
                description=pc["description"], reason=pc["reason"],
                risk_level=Severity(pc.get("risk_level", "medium")),
            )
            for pc in raw.get("planned_changes", [])
        ]
        required_tests = [
            TestPlanItem(name=t["name"], test_type=t["test_type"],
                        target=t["target"], assertion=t["assertion"])
            for t in raw.get("required_tests", [])
        ]
        rejected = [
            RejectedAlternative(ra["alternative"], ra["reason"])
            for ra in raw.get("rejected_alternatives", [])
        ]
        boundaries = PatchBoundaries(
            allowed_files=[pc.file for pc in planned_changes],
            forbidden_changes=["不得绕过或削弱现有安全校验", "不得删除失败测试"],
            maximum_changed_files=8, maximum_diff_lines=400,
        )
        unknowns = list(dict.fromkeys(raw.get("unknowns", [])))
        plan = RemediationPlan(
            finding_id=finding.finding_id,
            status=status,
            remediation_goal=raw.get("remediation_goal", ""),
            strategies=strategies,
            planned_changes=planned_changes,
            dependency_upgrade=None,
            compatibility=CompatibilityAssessment(
                summary="Agent 生成的修复方案",
                risks=raw.get("risk_points", []),
                required_checks=engineering.available_test_commands if engineering else [],
            ),
            risk_points=raw.get("risk_points", []),
            required_tests=required_tests,
            rejected_alternatives=rejected,
            rollback=RollbackPlan(summary="回滚修复变更", steps=["revert changes", "重新运行回归测试"]),
            patch_boundaries=boundaries,
            assumptions=raw.get("assumptions", []),
            unknowns=unknowns,
            confidence_score=float(raw.get("confidence_score", 0.5)),
            needs_human_review=bool(raw.get("needs_human_review", True)),
        )
        if failure_analysis:
            plan = RemediationPlanAgent._apply_failure_feedback(plan, failure_analysis)
        return plan

    @staticmethod
    def _apply_failure_feedback(
        plan: RemediationPlan,
        failure_analysis: FailureAnalysisResult,
    ) -> RemediationPlan:
        """将失败反馈融入修复方案。"""
        from .models import FailureCategory

        plan.assumptions.append(f"replanned_after_failure: {failure_analysis.patch_id}")
        plan.risk_points.extend(failure_analysis.remediation_feedback)
        plan.compatibility.risks.extend(failure_analysis.remediation_feedback)
        plan.compatibility.required_checks.extend(failure_analysis.validation_feedback)
        plan.unknowns.extend(
            f"previous_failure:{f.category.value}"
            for f in failure_analysis.findings
            if f.category in {FailureCategory.TOOLING_GAP, FailureCategory.UNKNOWN}
        )

        if failure_analysis.requires_root_cause_recheck:
            plan.needs_human_review = True
            plan.risk_points.append("previous validation suggests root cause may be incomplete")

        categories = {f.category for f in failure_analysis.findings}
        if FailureCategory.SECURITY_NOT_FIXED in categories:
            plan.required_tests.append(TestPlanItem(
                name="reproduced exploit regression from failed validation",
                test_type="security_regression",
                target=plan.finding_id,
                assertion="the exact payload from the failed validation no longer succeeds",
            ))
        if FailureCategory.BUSINESS_REGRESSION in categories:
            plan.required_tests.append(TestPlanItem(
                name="business contract regression from failed validation",
                test_type="business_regression",
                target=plan.finding_id,
                assertion="existing API response shape and semantics remain unchanged",
            ))
        if FailureCategory.BUILD_FAILURE in categories:
            plan.compatibility.required_checks.append("re-run failed build command before security validation")

        plan.risk_points = list(dict.fromkeys(plan.risk_points))
        plan.compatibility.risks = list(dict.fromkeys(plan.compatibility.risks))
        plan.compatibility.required_checks = list(dict.fromkeys(plan.compatibility.required_checks))
        plan.assumptions = list(dict.fromkeys(plan.assumptions))
        plan.unknowns = list(dict.fromkeys(plan.unknowns))
        return plan

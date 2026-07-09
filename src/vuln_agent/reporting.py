from __future__ import annotations

from dataclasses import dataclass

from .models import (
    ImpactAssessment,
    NormalizedVulnerability,
    PatchCandidate,
    PatchValidationStatus,
    RemediationPlan,
    RemediationReport,
    RemediationReportStatus,
    ReportSection,
    RootCauseAssessment,
    ToolExecutionStatus,
    ValidationLayer,
    ValidationToolchainResult,
)


LAYER_NAMES = {
    ValidationLayer.BUILD: "构建验证",
    ValidationLayer.BUSINESS_REGRESSION: "业务回归验证",
    ValidationLayer.SECURITY_REGRESSION: "安全回归验证",
    ValidationLayer.SCANNER_RESCAN: "扫描复验",
    ValidationLayer.DIFFERENTIAL_RISK: "差异风险验证",
}


STATUS_NAMES = {
    ToolExecutionStatus.PASSED: "通过",
    ToolExecutionStatus.FAILED: "失败",
    ToolExecutionStatus.SKIPPED: "跳过",
    ToolExecutionStatus.NOT_CONFIGURED: "未配置",
}


@dataclass(slots=True)
class RemediationReportAgent:
    def generate(
        self,
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
        root_cause: RootCauseAssessment,
        remediation_plan: RemediationPlan,
        patch_candidate: PatchCandidate,
        validation: ValidationToolchainResult,
    ) -> RemediationReport:
        if validation.status != PatchValidationStatus.PASSED or not validation.report_ready:
            return self._blocked_report(finding, patch_candidate, validation)

        changed_files = self._changed_files(patch_candidate)
        validation_summary = self._validation_summary(validation)
        test_results = self._test_results(validation)
        security_validation_results = self._security_validation_results(validation)
        risk_summary = self._risk_summary(remediation_plan, patch_candidate)
        title = f"修复 {finding.vulnerability_type}（{finding.finding_id}）"
        executive = (
            f"候选补丁 {patch_candidate.patch_id} 已针对 {finding.vulnerability_type} 完成修复，"
            "并通过构建、业务回归、安全回归、扫描复验和差异风险验证。"
        )
        root_cause_summary = self._root_cause_summary(root_cause, remediation_plan)
        remediation_summary = self._remediation_summary(remediation_plan)
        rollback_summary = self._rollback_summary(remediation_plan)
        human_review_focus = self._human_review_focus(finding, impact, remediation_plan, patch_candidate)
        sections = [
            ReportSection("修改摘要", executive),
            ReportSection("漏洞根因", root_cause_summary),
            ReportSection("修复方案", remediation_summary),
            ReportSection("修改文件列表", "\n".join(f"- {file}" for file in changed_files)),
            ReportSection("测试结果", "\n".join(f"- {item}" for item in test_results)),
            ReportSection("安全验证结果", "\n".join(f"- {item}" for item in security_validation_results)),
            ReportSection("风险说明", "\n".join(f"- {risk}" for risk in risk_summary) or "未发现额外风险。"),
            ReportSection("回滚方案", self._rollback_markdown(remediation_plan)),
            ReportSection("人工审查重点", "\n".join(f"- {item}" for item in human_review_focus)),
        ]
        pr_markdown = self._pr_markdown(
            title,
            executive,
            finding,
            impact,
            remediation_plan,
            root_cause_summary,
            remediation_summary,
            rollback_summary,
            changed_files,
            test_results,
            security_validation_results,
            validation_summary,
            risk_summary,
            human_review_focus,
        )
        ticket_markdown = self._ticket_markdown(
            finding,
            executive,
            test_results,
            security_validation_results,
            validation_summary,
            rollback_summary,
            human_review_focus,
        )
        return RemediationReport(
            report_id=f"report-{finding.finding_id}-{patch_candidate.patch_id}",
            finding_id=finding.finding_id,
            patch_id=patch_candidate.patch_id,
            status=RemediationReportStatus.READY,
            title=title,
            executive_summary=executive,
            root_cause_summary=root_cause_summary,
            remediation_summary=remediation_summary,
            changed_files=changed_files,
            test_results=test_results,
            security_validation_results=security_validation_results,
            validation_summary=validation_summary,
            risk_summary=risk_summary,
            rollback_summary=rollback_summary,
            human_review_focus=human_review_focus,
            pr_description_markdown=pr_markdown,
            ticket_comment_markdown=ticket_markdown,
            sections=sections,
            blocked_reason=None,
            needs_human_review=True,
        )

    @staticmethod
    def _blocked_report(
        finding: NormalizedVulnerability,
        patch_candidate: PatchCandidate,
        validation: ValidationToolchainResult,
    ) -> RemediationReport:
        reason = validation.feedback_for_failure_analysis or "验证未通过"
        markdown = (
            f"# {finding.finding_id} 修复报告生成被阻断\n\n"
            f"补丁 `{patch_candidate.patch_id}` 未通过验证，因此不能生成正式修复报告。\n\n"
            f"阻断原因：{reason}\n"
        )
        return RemediationReport(
            report_id=f"report-{finding.finding_id}-blocked",
            finding_id=finding.finding_id,
            patch_id=patch_candidate.patch_id,
            status=RemediationReportStatus.BLOCKED,
            title=f"{finding.finding_id} 修复报告生成被阻断",
            executive_summary="最终修复报告被阻断，因为验证未通过。",
            root_cause_summary="",
            remediation_summary="",
            changed_files=[],
            test_results=[],
            security_validation_results=[],
            validation_summary=[],
            risk_summary=[],
            rollback_summary="",
            human_review_focus=["请先处理验证失败原因，再生成正式修复报告。"],
            pr_description_markdown=markdown,
            ticket_comment_markdown=markdown,
            sections=[],
            blocked_reason=reason,
            needs_human_review=True,
        )

    @staticmethod
    def _changed_files(patch_candidate: PatchCandidate) -> list[str]:
        files = [item.file for item in patch_candidate.changed_files]
        files.extend(artifact.target for artifact in patch_candidate.artifacts)
        return list(dict.fromkeys(file for file in files if file))

    @staticmethod
    def _root_cause_summary(root_cause: RootCauseAssessment, remediation_plan: RemediationPlan) -> str:
        upgrade = remediation_plan.dependency_upgrade
        if upgrade:
            return (
                f"**安全不变量**：运行时制品不得引入已确认受影响的依赖版本。\n\n"
                f"**破坏机制**：应用中引入了存在已知漏洞的依赖组件 `{upgrade.component}`，"
                f"当前版本为 `{upgrade.current_version or '未知'}`，未升级到安全版本。\n\n"
                f"**修复约束**：优先升级到最小安全版本 `{upgrade.minimum_safe_version or '未知'}`，"
                "并通过依赖兼容性、业务回归和扫描复验。"
            )

        lines = []
        if root_cause.security_invariant:
            lines.append(f"**安全不变量**：{root_cause.security_invariant}")
        if root_cause.guardrail:
            lines.append(f"**守卫/缺失控制**：`{root_cause.guardrail}` 是本路径必须执行的安全守卫。")
        lines.append(f"**根因摘要**：{root_cause.root_cause.summary}")
        if root_cause.broken_mechanism:
            mechanism = "\n".join(f"{index}. {item}" for index, item in enumerate(root_cause.broken_mechanism, 1))
            lines.append(f"**破坏机制**：\n\n{mechanism}")
        if root_cause.causal_chain:
            chain = " → ".join(root_cause.causal_chain)
            lines.append(f"**因果链路**：{chain}")
        if root_cause.exploitability_note:
            lines.append(f"**可利用性说明**：{root_cause.exploitability_note}")
        if root_cause.recommended_fix_constraints:
            constraints = "\n".join(f"- {item}" for item in root_cause.recommended_fix_constraints)
            lines.append(f"**修复约束**：\n{constraints}")
        return "\n\n".join(lines)

    @staticmethod
    def _remediation_summary(remediation_plan: RemediationPlan) -> str:
        upgrade = remediation_plan.dependency_upgrade
        if upgrade:
            recommended = (
                f"；如兼容性评估通过，可升级到推荐稳定版本 `{upgrade.recommended_stable_version}`"
                if upgrade.recommended_stable_version
                else ""
            )
            return (
                f"**修复目标**：将 `{upgrade.component}` 升级到最小安全版本 "
                f"`{upgrade.minimum_safe_version or '未知'}`{recommended}。\n\n"
                "**修改策略**：更新依赖声明/锁文件，重新构建制品，并执行依赖兼容性、业务回归和 SCA 复扫。"
            )

        strategy = remediation_plan.strategies[0] if remediation_plan.strategies else None
        changes = "\n".join(
            f"- `{item.file}`：{item.description}（原因：{item.reason}）"
            for item in remediation_plan.planned_changes
        ) or "- 暂无代码修改项"
        steps = "\n".join(f"{index}. {step}" for index, step in enumerate(strategy.steps, 1)) if strategy else "1. 按根因补齐缺失安全控制"
        tests = "\n".join(
            f"- {item.name}：{item.assertion}"
            for item in remediation_plan.required_tests
        ) or "- 暂无测试计划"
        alternatives = "\n".join(
            f"- 不采用 `{item.alternative}`：{item.reason}"
            for item in remediation_plan.rejected_alternatives
        ) or "- 暂无替代方案记录"
        return (
            f"**修复目标**：{remediation_plan.remediation_goal}\n\n"
            f"**修改文件**：\n{changes}\n\n"
            f"**修改策略**：{strategy.summary if strategy else '按根因补齐缺失安全控制'}\n\n"
            f"**实施步骤**：\n{steps}\n\n"
            f"**需要新增/保留的测试**：\n{tests}\n\n"
            f"**替代方案取舍**：\n{alternatives}"
        )

    @staticmethod
    def _rollback_summary(remediation_plan: RemediationPlan) -> str:
        if remediation_plan.dependency_upgrade:
            return "回滚依赖声明和锁文件变更，重新构建上一版本制品，并保持漏洞工单继续跟踪。"
        return remediation_plan.rollback.summary

    @staticmethod
    def _risk_summary(remediation_plan: RemediationPlan, patch_candidate: PatchCandidate) -> list[str]:
        if remediation_plan.dependency_upgrade:
            return [
                "依赖升级可能引入 API 行为变化或传递依赖冲突。",
                "依赖声明、锁文件和重新构建的制品需要一起验证。",
                "合入前需要重点审查业务回归和 SCA 复扫结果。",
            ]
        return list(dict.fromkeys([*remediation_plan.risk_points, *patch_candidate.risks]))

    @staticmethod
    def _validation_summary(validation: ValidationToolchainResult) -> list[str]:
        summary = []
        for layer in validation.layers:
            layer_name = LAYER_NAMES.get(layer.layer, layer.layer.value)
            status = STATUS_NAMES.get(layer.status, layer.status.value)
            summary.append(f"{layer_name}：{status}" if layer.status == ToolExecutionStatus.PASSED else f"{layer_name}：{status} - {layer.summary}")
            for tool in layer.tool_results:
                tool_status = STATUS_NAMES.get(tool.status, tool.status.value)
                summary.append(f"  - {tool.tool_name}：{tool_status}（{tool.summary}）")
        return summary

    @staticmethod
    def _test_results(validation: ValidationToolchainResult) -> list[str]:
        return RemediationReportAgent._layer_summaries(validation, {ValidationLayer.BUILD, ValidationLayer.BUSINESS_REGRESSION})

    @staticmethod
    def _security_validation_results(validation: ValidationToolchainResult) -> list[str]:
        return RemediationReportAgent._layer_summaries(
            validation,
            {ValidationLayer.SECURITY_REGRESSION, ValidationLayer.SCANNER_RESCAN, ValidationLayer.DIFFERENTIAL_RISK},
        )

    @staticmethod
    def _layer_summaries(validation: ValidationToolchainResult, layers: set[ValidationLayer]) -> list[str]:
        summary = []
        for layer in validation.layers:
            if layer.layer not in layers:
                continue
            layer_name = LAYER_NAMES.get(layer.layer, layer.layer.value)
            status = STATUS_NAMES.get(layer.status, layer.status.value)
            summary.append(f"{layer_name}：{status} - {layer.summary}")
            for tool in layer.tool_results:
                tool_status = STATUS_NAMES.get(tool.status, tool.status.value)
                summary.append(f"  - {tool.tool_name}：{tool_status}（{tool.summary}）")
        return summary

    @staticmethod
    def _human_review_focus(
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
        remediation_plan: RemediationPlan,
        patch_candidate: PatchCandidate,
    ) -> list[str]:
        focus = [
            "确认补丁与修复目标一致，且没有绕过验证或削弱安全控制。",
            "确认验证过程运行在授权的非生产环境中。",
        ]
        if finding.severity.value in {"critical", "high"}:
            focus.append("高危漏洞：需要重点审查根因说明和漏洞回归验证证据。")
        if impact.entry_points:
            focus.append("检查受影响的公网入口或需认证 API 路径是否被完整覆盖。")
        if remediation_plan.dependency_upgrade:
            focus.append("检查依赖版本选择、锁文件变化和兼容性风险。")
        if patch_candidate.policy_check.estimated_diff_lines:
            focus.append("检查变更范围，确认未引入无关业务行为变化。")
        return list(dict.fromkeys(focus))

    @staticmethod
    def _rollback_markdown(remediation_plan: RemediationPlan) -> str:
        steps = "\n".join(f"- {step}" for step in RemediationReportAgent._rollback_steps(remediation_plan))
        return f"{RemediationReportAgent._rollback_summary(remediation_plan)}\n{steps}"

    @staticmethod
    def _rollback_steps(remediation_plan: RemediationPlan) -> list[str]:
        if remediation_plan.dependency_upgrade:
            return [
                "回滚依赖声明和锁文件变更。",
                "重新构建上一版本应用制品。",
                "确认回滚后漏洞风险仍保留在安全工单中继续跟踪。",
            ]
        return remediation_plan.rollback.steps

    def _pr_markdown(
        self,
        title: str,
        executive: str,
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
        remediation_plan: RemediationPlan,
        root_cause_summary: str,
        remediation_summary: str,
        rollback_summary: str,
        changed_files: list[str],
        test_results: list[str],
        security_validation_results: list[str],
        validation_summary: list[str],
        risk_summary: list[str],
        human_review_focus: list[str],
    ) -> str:
        affected_services = ", ".join(impact.affected_services) or "未知"
        changed = "\n".join(f"- {file}" for file in changed_files) or "- 无文件列表"
        tests = "\n".join(f"- {item}" for item in test_results) or "- 无测试结果"
        security = "\n".join(f"- {item}" for item in security_validation_results) or "- 无安全验证结果"
        validation = "\n".join(f"- {item}" for item in validation_summary)
        risks = "\n".join(f"- {risk}" for risk in risk_summary) or "- 未发现额外风险"
        review = "\n".join(f"- {item}" for item in human_review_focus)
        rollback_steps = "\n".join(f"- {step}" for step in self._rollback_steps(remediation_plan))
        rollback = f"{rollback_summary}\n{rollback_steps}"
        return (
            f"# {title}\n\n"
            f"## 修改摘要\n{executive}\n\n"
            f"## 漏洞信息\n"
            f"- 漏洞 ID：{finding.finding_id}\n"
            f"- 漏洞类型：{finding.vulnerability_type}\n"
            f"- 严重性：{finding.severity.value}\n"
            f"- 来源工具：{finding.scanner}\n"
            f"- 受影响服务：{affected_services}\n\n"
            f"## 漏洞根因\n{root_cause_summary}\n\n"
            f"## 修复方案\n{remediation_summary}\n\n"
            f"## 修改文件列表\n{changed}\n\n"
            f"## 测试结果\n{tests}\n\n"
            f"## 安全验证结果\n{security}\n\n"
            f"## 完整验证结果\n{validation}\n\n"
            f"## 风险说明\n{risks}\n\n"
            f"## 回滚方案\n{rollback}\n\n"
            f"## 人工审查重点\n{review}\n"
        )

    @staticmethod
    def _ticket_markdown(
        finding: NormalizedVulnerability,
        executive: str,
        test_results: list[str],
        security_validation_results: list[str],
        validation_summary: list[str],
        rollback_summary: str,
        human_review_focus: list[str],
    ) -> str:
        tests = "\n".join(f"- {item}" for item in test_results)
        security = "\n".join(f"- {item}" for item in security_validation_results)
        validation = "\n".join(f"- {item}" for item in validation_summary)
        review = "\n".join(f"- {item}" for item in human_review_focus)
        return (
            f"修复报告已生成：{finding.finding_id}\n\n"
            f"{executive}\n\n"
            f"测试结果：\n{tests}\n\n"
            f"安全验证结果：\n{security}\n\n"
            f"完整验证结果：\n{validation}\n\n"
            f"回滚建议：{rollback_summary}\n\n"
            f"人工审查重点：\n{review}\n"
        )

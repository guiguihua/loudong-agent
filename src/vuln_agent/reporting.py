from __future__ import annotations

from dataclasses import dataclass

from .models import (
    ImpactAssessment,
    NormalizedVulnerability,
    PatchCandidate,
    PatchCandidateStatus,
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
        if validation.status == PatchValidationStatus.FAILED or not validation.report_ready:
            return self._blocked_report(finding, patch_candidate, validation)

        changed_files = self._changed_files(patch_candidate)
        validation_summary = self._validation_summary(validation)
        test_results = self._test_results(validation)
        security_validation_results = self._security_validation_results(validation)
        risk_summary = self._risk_summary(
            remediation_plan, patch_candidate, validation, impact, root_cause
        )
        title = f"修复 {finding.vulnerability_type}（{finding.finding_id}）"
        fully_validated = validation.status == PatchValidationStatus.PASSED
        if fully_validated:
            executive = (
                f"候选补丁 {patch_candidate.patch_id} 已针对 {finding.vulnerability_type} 生成，"
                "并在隔离的临时工作区通过全部适用验证。"
                "补丁未写入或合并到原始代码仓库，需由人工审查后决定是否采用。"
            )
        else:
            executive = (
                f"候选补丁 {patch_candidate.patch_id} 已针对 {finding.vulnerability_type} 生成并在隔离工作区执行验证。"
                "部分验证尚未配置或未完成，报告保留已执行证据和待验证项；补丁未写入原始仓库，"
                "当前仅供人工审查，不能视为完整验证通过。"
            )
        root_cause_summary = self._root_cause_summary(finding, root_cause, remediation_plan)
        remediation_summary = self._remediation_summary(finding, remediation_plan)
        impact_summary = self._impact_summary(finding, impact)
        patch_markdown = self._patch_markdown(patch_candidate)
        rollback_summary = self._rollback_summary(remediation_plan)
        human_review_focus = self._human_review_focus(finding, impact, remediation_plan, patch_candidate)
        sections = [
            ReportSection("修改摘要", executive),
            ReportSection("影响面", impact_summary),
            ReportSection("漏洞根因", root_cause_summary),
            ReportSection("修复方案", remediation_summary),
            ReportSection("修改文件列表", "\n".join(f"- {file}" for file in changed_files)),
            ReportSection("候选补丁", patch_markdown),
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
            impact_summary,
            rollback_summary,
            changed_files,
            patch_markdown,
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
            status=RemediationReportStatus.READY if fully_validated else RemediationReportStatus.CANDIDATE,
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
        generation_blocked = (
            patch_candidate.status == PatchCandidateStatus.BLOCKED
            or not patch_candidate.artifacts
        )
        if generation_blocked:
            title = f"{finding.finding_id} 候选补丁生成被阻断"
            executive = "候选补丁未形成可审查的结构化 diff，外部构建、测试和安全验证尚未开始。"
            summary = (
                f"候选补丁 `{patch_candidate.patch_id}` 未成功生成，因此静态预检已停止后续验证。"
            )
            review = "请先修复补丁生成或修复计划路径问题，再执行外部验证。"
        else:
            title = f"{finding.finding_id} 修复报告生成被阻断"
            executive = "候选补丁已经生成，但已执行的必要验证未通过。"
            summary = f"候选补丁 `{patch_candidate.patch_id}` 未通过必要验证。"
            review = "请先处理验证失败原因，再生成正式修复报告。"
        markdown = (
            f"# {title}\n\n"
            f"{summary}\n\n"
            f"阻断原因：{reason}\n\n"
            f"## 未验证的候选补丁\n\n"
            f"{RemediationReportAgent._patch_markdown(patch_candidate)}\n"
        )
        return RemediationReport(
            report_id=f"report-{finding.finding_id}-blocked",
            finding_id=finding.finding_id,
            patch_id=patch_candidate.patch_id,
            status=RemediationReportStatus.BLOCKED,
            title=title,
            executive_summary=executive,
            root_cause_summary="",
            remediation_summary="",
            changed_files=[],
            test_results=[],
            security_validation_results=[],
            validation_summary=[],
            risk_summary=[],
            rollback_summary="",
            human_review_focus=[review],
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
    def _root_cause_summary(
        finding: NormalizedVulnerability,
        root_cause: RootCauseAssessment,
        remediation_plan: RemediationPlan,
    ) -> str:
        upgrade = remediation_plan.dependency_upgrade
        if upgrade:
            return (
                f"**安全不变量**：运行时制品不得引入已确认受影响的依赖版本。\n\n"
                f"**破坏机制**：应用中引入了存在已知漏洞的依赖组件 `{upgrade.component}`，"
                f"当前版本为 `{upgrade.current_version or '未知'}`，未升级到安全版本。\n\n"
                f"**修复约束**：优先升级到最小安全版本 `{upgrade.minimum_safe_version or '未知'}`，"
                "并通过依赖兼容性、业务回归和扫描复验。"
            )

        rc = root_cause.root_cause
        is_placeholder_summary = RemediationReportAgent._is_placeholder_summary(rc.summary)

        lines = []
        if root_cause.security_invariant:
            lines.append(f"**安全不变量**：{root_cause.security_invariant}")
        if root_cause.guardrail:
            lines.append(f"**守卫/缺失控制**：`{root_cause.guardrail}` 是本路径必须执行的安全守卫。")

        if is_placeholder_summary:
            # 根因分析未产出有效结构化结果 → 生成有意义的降级内容
            lines.append(RemediationReportAgent._build_fallback_root_cause(finding, root_cause))
        else:
            lines.append(f"**根因摘要**：{rc.summary}")
            if root_cause.broken_mechanism:
                mechanism = "\n".join(
                    f"{index}. {item}"
                    for index, item in enumerate(root_cause.broken_mechanism, 1)
                )
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
    def _is_placeholder_summary(summary: str | None) -> bool:
        """判断根因摘要是否为占位符文本（LLM 未产出有效分析）。"""
        if not summary:
            return True
        summary_lower = summary.lower().strip()
        placeholder_markers = [
            "static fallback could not fully confirm",
            "could not fully confirm root cause",
            "manual review is required",
            "could not fully confirm",
            "fast mode uses a generic",
            "无法完全确认",
            "需人工审查",
        ]
        return any(marker in summary_lower for marker in placeholder_markers)

    @staticmethod
    def _build_fallback_root_cause(
        finding: NormalizedVulnerability,
        root_cause: RootCauseAssessment,
    ) -> str:
        """当根因分析为占位符时，基于漏洞报告本身构建有意义的根因描述。"""
        vuln_type = finding.vulnerability_type or "未知漏洞类型"
        severity = finding.severity.value if finding.severity else "unknown"
        cwe = f" ({finding.cwe})" if finding.cwe else ""
        evidence = "; ".join(e for e in (finding.evidence or []) if e.strip())
        recommendation = finding.recommendation or ""
        locs = [f"{loc.file}:{loc.line}" for loc in finding.locations if loc.line]
        affected_loc = locs[0] if locs else "unknown"

        parts = [
            f"**根因摘要**：{finding.finding_id} — {vuln_type}{cwe}，严重性 {severity}。"
            f"漏洞位于 `{affected_loc}`。"
            f"{' 证据: ' + evidence if evidence else ''}"
            f"{' 修复建议: ' + recommendation if recommendation else ''}",
            "",
            "**⚠️ 重要提示**：LLM 根因分析 Agent 未产出完整的结构化分析结果。"
            "以下信息基于漏洞报告中的原始数据推断，而非代码级数据流追踪。",
        ]

        if root_cause.root_cause.missing_control and str(root_cause.root_cause.missing_control).strip().lower() not in (
            "missing_control", "missing_security_control", "missing control", "",
        ):
            parts.append(f"**可能缺失的控制**：{root_cause.root_cause.missing_control}")

        if locs:
            parts.append(f"**受影响位置**：{', '.join(locs)}")

        parts.extend([
            "",
            "**建议操作**：",
            "- 人工审查受影响代码的 source-to-sink 数据流",
            f"- 确认 {vuln_type} 的具体触发条件和利用路径",
            "- 验证补丁是否在正确的位置施加了正确的安全控制",
        ])
        return "\n".join(parts)

    @staticmethod
    def _remediation_summary(
        finding: NormalizedVulnerability,
        remediation_plan: RemediationPlan,
    ) -> str:
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
        goal = remediation_plan.remediation_goal or f"修复 {finding.vulnerability_type or '未知漏洞'}"

        changes = "\n".join(
            f"- `{item.file}`：{item.description}（原因：{item.reason}）"
            for item in remediation_plan.planned_changes
        ) or "- 暂无代码修改项（需人工审查后补充）"

        steps = "\n".join(
            f"{index}. {step}" for index, step in enumerate(strategy.steps, 1)
        ) if strategy and strategy.steps else (
            "1. 人工审查受影响代码，定位漏洞触发路径\n"
            "2. 补全缺失的安全控制\n"
            "3. 运行回归测试确认修复有效且无副作用"
        )

        tests = "\n".join(
            f"- {item.name}：{item.assertion}"
            for item in remediation_plan.required_tests
        ) or "- 暂无测试计划（需人工补充）"

        alternatives = "\n".join(
            f"- 不采用 `{item.alternative}`：{item.reason}"
            for item in remediation_plan.rejected_alternatives
        ) or "- 暂无替代方案记录"

        strategy_summary = strategy.summary if strategy else f"针对 {finding.vulnerability_type or '未知漏洞'} 的最小化安全修复"

        return (
            f"**修复目标**：{goal}\n\n"
            f"**修改文件**：\n{changes}\n\n"
            f"**修改策略**：{strategy_summary}\n\n"
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
    def _risk_summary(
        remediation_plan: RemediationPlan,
        patch_candidate: PatchCandidate,
        validation: ValidationToolchainResult,
        impact: ImpactAssessment,
        root_cause: RootCauseAssessment,
    ) -> list[str]:
        risks = [*remediation_plan.risk_points, *patch_candidate.risks]
        if remediation_plan.dependency_upgrade:
            risks.extend([
                "依赖升级可能引入 API 行为变化或传递依赖冲突。",
                "依赖声明、锁文件和重新构建的制品需要一起验证。",
                "合入前需要重点审查业务回归和 SCA 复扫结果。",
            ])
        for layer in validation.layers:
            if layer.status in {ToolExecutionStatus.NOT_CONFIGURED, ToolExecutionStatus.SKIPPED}:
                layer_name = LAYER_NAMES.get(layer.layer, layer.layer.value)
                risks.append(f"{layer_name}未形成可审计的执行证据，候选补丁不能视为完整验证通过。")
        if impact.confidence_score < 0.7:
            risks.append(
                f"影响面置信度仅为 {impact.confidence_score:.2f}；未确认的服务、入口和调用路径仍需人工核实。"
            )
        if root_cause.confidence_score < 0.7:
            risks.append(
                f"根因置信度仅为 {root_cause.confidence_score:.2f}；补丁位置和安全不变量仍需人工复核。"
            )
        if not any(artifact.patch_type.value == "test" for artifact in patch_candidate.artifacts):
            risks.append("候选补丁没有测试 artifact，无法证明漏洞被阻断且合法行为保持兼容。")
        return list(dict.fromkeys(risks))

    @staticmethod
    def _validation_summary(validation: ValidationToolchainResult) -> list[str]:
        summary = []
        for layer in validation.layers:
            layer_name = LAYER_NAMES.get(layer.layer, layer.layer.value)
            status = STATUS_NAMES.get(layer.status, layer.status.value)
            summary.append(f"{layer_name}：{status}" if layer.status == ToolExecutionStatus.PASSED else f"{layer_name}：{status} - {layer.summary}")
            for tool in layer.tool_results:
                tool_status = STATUS_NAMES.get(tool.status, tool.status.value)
                details = RemediationReportAgent._tool_evidence(tool)
                summary.append(f"  - {tool.tool_name}：{tool_status}（{tool.summary}）{details}")
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
                details = RemediationReportAgent._tool_evidence(tool)
                summary.append(f"  - {tool.tool_name}：{tool_status}（{tool.summary}）{details}")
        return summary

    @staticmethod
    def _tool_evidence(tool) -> str:
        parts = []
        if tool.command:
            parts.append(f"命令: `{tool.command}`")
        if tool.exit_code is not None:
            parts.append(f"退出码: {tool.exit_code}")
        if tool.duration_ms is not None:
            parts.append(f"耗时: {tool.duration_ms} ms")
        if tool.evidence:
            evidence = "\n".join(str(item) for item in tool.evidence[:10])
            parts.append(f"证据:\n```text\n{evidence}\n```")
        return "\n    " + "；".join(parts) if parts else ""

    @staticmethod
    def _patch_markdown(patch_candidate: PatchCandidate) -> str:
        if not patch_candidate.artifacts:
            return "未生成可审查的补丁 artifact。"
        blocks = []
        for artifact in patch_candidate.artifacts:
            language = "diff" if "--- " in artifact.content and "+++ " in artifact.content else "text"
            blocks.append(
                f"### `{artifact.target}`\n\n"
                f"{artifact.description}\n\n"
                f"```{language}\n{artifact.content.rstrip()}\n```"
            )
        return "\n\n".join(blocks)

    @staticmethod
    def _impact_summary(
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
    ) -> str:
        """渲染影响面评估为报告可用的 markdown 文本。"""
        has_data = bool(impact.affected_services or impact.entry_points or impact.call_paths)

        lines = [
            f"**证据等级**：状态 `{impact.status.value}`，置信度 {impact.confidence_score:.2f}。"
            "以下列表仅应包含已由当前仓库、资产或运行时上下文支持的项目；潜在范围列在不确定项中。"
        ]
        if impact.affected_services:
            services = "\n".join(f"- {s}" for s in impact.affected_services)
            lines.append(f"**受影响服务/组件**：\n{services}")

        if impact.entry_points:
            entries = []
            for ep in impact.entry_points:
                auth = f"，认证: {ep.authentication}" if ep.authentication and ep.authentication != "unknown" else ""
                exposed = "，公网可达" if ep.internet_exposed else ""
                entries.append(f"- `{ep.method} {ep.route}`{auth}{exposed}")
            lines.append(f"**API 入口点**：\n{chr(10).join(entries)}")

        if impact.call_paths:
            paths = []
            for i, path in enumerate(impact.call_paths, 1):
                paths.append(f"{i}. {' → '.join(path)}")
            lines.append(f"**调用路径**：\n{chr(10).join(paths)}")

        if impact.data_classification:
            data = "\n".join(f"- {d}" for d in impact.data_classification)
            lines.append(f"**受影响数据**：\n{data}")

        if impact.affected_assets:
            assets = "\n".join(f"- {a}" for a in impact.affected_assets)
            lines.append(f"**受影响资产**：\n{assets}")

        if impact.suggested_tests:
            tests = "\n".join(f"- {t}" for t in impact.suggested_tests)
            lines.append(f"**建议回归测试**：\n{tests}")

        if not has_data:
            # 从 finding 中生成有意义的降级内容
            locs = [f"{loc.file}:{loc.line}" for loc in finding.locations if loc.line]
            evidence = "; ".join(e for e in (finding.evidence or []) if e.strip())
            lines.append(
                f"**受影响服务**：受 {finding.vulnerability_type} 影响的认证/授权服务组件。\n"
                f"受影响位置: {', '.join(locs) if locs else 'unknown'}。\n"
                f"{'证据: ' + evidence if evidence else ''}"
                f"\n\n⚠️ 影响面分析 Agent 未产出完整结构化结果，以上为基于漏洞报告的推断。"
                f"建议人工确认实际的受影响范围和服务边界。"
            )

        if impact.unknowns:
            unknown_list = "\n".join(f"- {u}" for u in impact.unknowns)
            lines.append(f"**不确定项**：\n{unknown_list}")

        return "\n\n".join(lines)

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
        impact_summary: str,
        rollback_summary: str,
        changed_files: list[str],
        patch_markdown: str,
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
            f"## 影响面\n{impact_summary}\n\n"
            f"## 漏洞根因\n{root_cause_summary}\n\n"
            f"## 修复方案\n{remediation_summary}\n\n"
            f"## 修改文件列表\n{changed}\n\n"
            f"## 候选补丁\n{patch_markdown}\n\n"
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

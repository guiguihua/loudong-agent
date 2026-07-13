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

## 修复范围原则（必须遵守）
- 目标是“因果完整且尽可能小”，不是追求固定文件数。修复必须覆盖恢复安全不变量所需的全部代码、配置、依赖声明和回归测试。
- planned_changes 中的每个文件都必须说明它与已确认根因、受影响调用路径、兼容性要求或必要验证之间的直接关系。
- 不得仅因为文件较多或 diff 较大而截断必要修复；多模块、共享底层组件、生成代码、配置与锁文件联动等场景可以合理修改多个文件。
- 仅属一般性加固、日志、清理或无关架构优化的内容，通常放入 rejected_alternatives 或后续建议；如果它是恢复安全不变量不可缺少的一部分，可以进入候选补丁，但必须给出源码证据和不可替代性说明。
- 修复决策只能依据当前漏洞报告、当前源码、配置、依赖和测试证据；不得依赖尚不存在的上游/官方补丁，也不得照搬外部参考实现。
- 如果评测数据中附带官方修复或参考答案，它们只允许在流水线完成后的离线评分阶段使用，不能进入修复规划或补丁生成上下文。
- 文件数和 diff 行数只用于风险分级和人工审查提示，不作为自动截断或拒绝修复的硬阈值。
- 不得把“可能更安全”当成扩大范围的充分理由；每项变更都要有可追溯证据，同时保证补丁可审查、可回滚、可验证。

确认分析完成后，调用 submit_final_result 工具提交最终结果。"""


class RemediationPlanAgent(BaseAgent):
    """制定修复方案 — 自主选择最优策略。"""

    def __init__(
        self,
        llm: LLMBackend | None = None,
        workspace: Path | None = None,
        prefer_static: bool = False,
        max_turns: int = 12,
    ):
        ws = workspace or Path.cwd()
        super().__init__(
            name="RemediationPlan",
            system_prompt=REMEDIATION_AGENT_PROMPT,
            tools=create_default_tools(ws),
            llm=llm,
            max_turns=max_turns,
            workspace=ws,
        )
        self.prefer_static = prefer_static

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
        if self.prefer_static:
            static_plan = self._static_plan(finding, impact, root_cause, engineering, failure_analysis)
            if static_plan is not None:
                return static_plan

        task = self._build_task(finding, impact, root_cause, engineering, failure_analysis)
        raw = self.run(task)

        if "_raw_output" in raw:
            # 主分析未输出结构化 JSON → 尝试二次提取
            extracted = self._extract_plan_from_raw(
                raw["_raw_output"], finding, root_cause
            )
            return self._dict_to_plan(finding, impact, root_cause, engineering, extracted, failure_analysis)
        return self._dict_to_plan(finding, impact, root_cause, engineering, raw, failure_analysis)

    def _extract_plan_from_raw(
        self,
        raw_text: str,
        finding: NormalizedVulnerability,
        root_cause: RootCauseAssessment,
    ) -> dict:
        """从非结构化的修复方案文本中二次提取结构化字段。"""
        if not self.llm:
            return RemediationPlanAgent._fallback_plan_extraction(raw_text, finding, root_cause)

        from .llm import REMEDIATION_PLAN_SCHEMA

        extraction_prompt = f"""以下是一段修复方案的原始分析文本。请从中提取关键信息，填入指定 JSON 结构。

## 漏洞信息
- ID: {finding.finding_id}
- 类型: {finding.vulnerability_type}
- 根因摘要: {root_cause.root_cause.summary[:500] if root_cause.root_cause.summary else '无'}

## 原始分析文本
{raw_text[:8000]}

## 要求
请仔细阅读上面的分析文本，尽量提取所有你能找到的结构化信息。
如果某个字段找不到对应信息，使用合理的默认值，不要编造。"""

        try:
            structured = self.llm.reason(
                user_prompt=extraction_prompt,
                system_prompt="你是一个结构化数据提取器。从安全修复分析文本中提取关键信息。只输出 JSON。",
                output_schema={
                    "type": "object",
                    "description": "从原始分析文本中提取的修复方案",
                    "properties": {
                        k: v for k, v in REMEDIATION_PLAN_SCHEMA.get("properties", {}).items()
                        if k not in ("reasoning",)
                    },
                    "required": ["status", "remediation_goal", "strategies", "planned_changes", "required_tests", "risk_points", "needs_human_review"],
                },
                temperature=0.1,
            )
            if isinstance(structured, dict) and structured.get("remediation_goal"):
                return structured
        except Exception:
            pass

        return RemediationPlanAgent._fallback_plan_extraction(raw_text, finding, root_cause)

    @staticmethod
    def _fallback_plan_extraction(
        raw_text: str,
        finding: NormalizedVulnerability,
        root_cause: RootCauseAssessment,
    ) -> dict:
        """LLM 不可用时的纯文本回退提取。"""
        import re

        # 尝试找到 JSON 块
        json_match = re.search(r'\{[^{}]*"remediation_goal"[^{}]*\}', raw_text, re.DOTALL)
        if not json_match:
            json_match = re.search(r'\{[^{}]*"strategies"[^{}]*\}', raw_text, re.DOTALL)
        if json_match:
            import json as _json
            try:
                return _json.loads(json_match.group(0))
            except (_json.JSONDecodeError, ValueError):
                pass

        # 从文本提取修复目标
        goal_match = re.search(
            r'(?:修复目标|remediation.goal|目标)[：:\s]*(.+?)(?:\n|$)',
            raw_text, re.IGNORECASE,
        )
        goal = goal_match.group(1).strip()[:300] if goal_match else (
            f"修复 {finding.vulnerability_type} 漏洞，具体方案需人工审查确定。"
        )

        vuln_type = finding.vulnerability_type or "unknown vulnerability"
        return {
            "status": "ready",
            "remediation_goal": goal,
            "strategies": [{
                "strategy_type": "code_change",
                "summary": f"针对 {vuln_type} 的最小化安全修复",
                "steps": [
                    "读取受影响文件并定位漏洞触发路径",
                    "在关键位置补全缺失的安全控制",
                    "保持 API 与现有行为不变",
                ],
                "preferred": True,
            }],
            "planned_changes": [],
            "risk_points": [
                "修复方案从非结构化文本中提取，信息可能不完整",
                "需要人工审查确认修复精准度",
            ],
            "required_tests": [
                {
                    "name": f"{finding.finding_id} 安全回归",
                    "test_type": "security_regression",
                    "target": finding.finding_id,
                    "assertion": "漏洞利用条件在补丁后被阻断",
                },
            ],
            "rejected_alternatives": [],
            "assumptions": ["从非结构化 LLM 输出中尽力提取"],
            "unknowns": ["修复方案的具体实施细节需要人工补充"],
            "confidence_score": 0.3,
            "needs_human_review": True,
        }

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

        # 判断根因分析是否稀疏（LLM 未产出结构化结果）
        rc = root_cause.root_cause
        sparse_root_cause = (
            not rc.summary
            or "static fallback" in (rc.summary or "").lower()
            or "could not fully confirm" in (rc.summary or "").lower()
            or not rc.missing_control
            or str(rc.missing_control).strip().lower() in ("missing_control", "missing_security_control", "missing control", "")
        )

        independence_note = ""
        if sparse_root_cause:
            independence_note = """
## ⚠️ 根因分析不完整 — 请独立分析
根因分析 Agent 未产出足够的结构化信息。**你必须自己读取相关源码文件**，
独立判断漏洞的触发路径和缺失的安全控制，然后再制定修复方案。
不要依赖上面不完整的根因信息——它可能只是占位符。"""

        locs = [f"{loc.file}:{loc.line}" for loc in finding.locations if loc.line]
        evidence_lines = "\n".join(f"- {e}" for e in (finding.evidence or []) if e.strip()) or "无"

        return f"""为以下漏洞设计修复方案：

## 漏洞
- ID: {finding.finding_id}
- 类型: {finding.vulnerability_type}
- 严重性: {finding.severity.value}
- 受影响文件: {', '.join(locs) if locs else 'unknown'}
- 证据:
{evidence_lines}
- 建议: {finding.recommendation or '未提供'}
- 根因: {rc.summary or '（根因分析未产出有效结果）'}
- 缺失控制: {rc.missing_control or '（未识别）'}
- 根因分类: {root_cause.root_cause_category.value}
{independence_note}
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
请先了解项目结构和读取相关源码，然后选择最优修复策略并给出具体步骤。"""

    @staticmethod
    def _static_plan(
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
        root_cause: RootCauseAssessment,
        engineering: EngineeringContext,
        failure_analysis: FailureAnalysisResult | None,
    ) -> RemediationPlan | None:
        vuln_type = (finding.vulnerability_type or "").lower()
        cwe = (finding.cwe or "").lower()
        is_sqli = "sql injection" in vuln_type or "sqli" in vuln_type or cwe == "cwe-89"
        is_dependency = finding.dependency is not None or "depend" in vuln_type

        target_files = [item.file for item in root_cause.affected_code] or [loc.file for loc in finding.locations]
        if is_dependency and finding.dependency is not None:
            target_files = target_files or [finding.dependency.component]
        # 从 finding.locations 兜底，避免 "unknown" 占位符
        if not target_files or target_files == ["unknown"]:
            target_files = [loc.file for loc in finding.locations if loc.file]
        if not target_files:
            target_files = ["unknown"]
        # 去重保留顺序
        seen: set[str] = set()
        target_files = [f for f in target_files if f not in seen and not seen.add(f)]

        if is_sqli:
            goal = "Replace SQL string construction with parameterized queries while preserving existing query semantics."
            strategy = RemediationStrategy(
                strategy_type=RemediationStrategyType.CODE_CHANGE,
                summary="Use bound SQL parameters for every user-controlled value.",
                steps=[
                    "Locate the vulnerable SQL execution path.",
                    "Move user-controlled values into driver placeholders instead of SQL text.",
                    "Preserve existing filters, result shape, and error behavior.",
                    "Add or run a SQL injection regression check before merging.",
                ],
                preferred=True,
            )
            planned_changes = [
                PlannedChange(
                    file=target,
                    change_type="code",
                    description="Replace SQL concatenation/interpolation with parameterized query execution.",
                    reason=root_cause.root_cause.missing_control or "parameterized query is required",
                    risk_level=Severity.MEDIUM,
                )
                for target in target_files[:5]
            ]
            tests = [
                TestPlanItem(
                    name=f"{finding.finding_id} SQL injection regression",
                    test_type="security_regression",
                    target=finding.finding_id,
                    assertion="malicious SQL payload is treated as data and cannot change query structure",
                ),
                TestPlanItem(
                    name=f"{finding.finding_id} search behavior regression",
                    test_type="business_regression",
                    target=target_files[0],
                    assertion="normal queries keep the previous response shape and matching behavior",
                ),
            ]
            rejected = [
                RejectedAlternative(
                    "input blacklist only",
                    "blacklists are bypass-prone and do not enforce the SQL parameterization invariant",
                )
            ]
            risk_points = [
                "LIKE wildcard semantics must remain compatible after parameter binding",
                "existing tests may be absent, so generated patch still needs human review",
            ]
            confidence = 0.72
        elif is_dependency:
            component = finding.dependency.component if finding.dependency else target_files[0]
            fixed = finding.dependency.fixed_versions if finding.dependency else []
            version = fixed[0] if fixed else "a fixed version"
            goal = f"Upgrade or mitigate vulnerable dependency {component} to {version}."
            strategy = RemediationStrategy(
                strategy_type=RemediationStrategyType.DEPENDENCY_UPGRADE,
                summary="Update the dependency declaration to a fixed version and run compatibility checks.",
                steps=[
                    "Find the package manifest or lockfile that declares the vulnerable dependency.",
                    "Raise the dependency to the minimum fixed version or a compatible stable version.",
                    "Refresh lockfiles only when the project uses them.",
                    "Run build and dependency compatibility checks before merging.",
                ],
                preferred=True,
            )
            planned_changes = [
                PlannedChange(
                    file=target,
                    change_type="dependency",
                    description=f"Update dependency declaration for {component}.",
                    reason=f"reported vulnerable dependency requires {version}",
                    risk_level=Severity.MEDIUM,
                )
                for target in target_files[:5]
            ]
            tests = [
                TestPlanItem(
                    name=f"{finding.finding_id} dependency compatibility",
                    test_type="business_regression",
                    target=component,
                    assertion="application builds and dependency consumers remain compatible",
                ),
                TestPlanItem(
                    name=f"{finding.finding_id} dependency rescan",
                    test_type="security_scan",
                    target=component,
                    assertion="scanner no longer reports the vulnerable version",
                ),
            ]
            rejected = [
                RejectedAlternative(
                    "ignore vulnerable dependency",
                    "the vulnerable component remains present without an upgrade or mitigation",
                )
            ]
            risk_points = [
                "dependency upgrade may introduce API or transitive dependency changes",
                "lockfile updates should match the project's package manager",
            ]
            confidence = 0.66
        else:
            # 未匹配到专用模板的漏洞类型 → 尽量利用已有的根因信息构建方案
            rc = root_cause.root_cause
            has_meaningful_root_cause = bool(
                rc.summary
                and "static fallback" not in rc.summary.lower()
                and "could not fully confirm" not in rc.summary.lower()
            )
            has_meaningful_missing_control = bool(
                rc.missing_control
                and rc.missing_control not in ("missing_control", "missing_security_control", "missing control")
                and len(str(rc.missing_control)) > 10
            )
            has_evidence = bool(finding.evidence and any(e.strip() for e in finding.evidence))

            # 从漏洞报告本身提取有用描述
            evidence_text = "; ".join(e for e in (finding.evidence or []) if e.strip())
            rec_text = finding.recommendation or ""
            vuln_desc = finding.vulnerability_type or "unknown vulnerability"

            # 尝试从根因中获取更有意义的缺失控制描述
            if has_meaningful_missing_control:
                control_label = rc.missing_control
            elif finding.cwe:
                control_label = f"针对 {finding.cwe} 的必要安全控制（{vuln_desc}）"
            elif rec_text:
                control_label = f"安全控制（修复建议: {rec_text[:150]}）"
            elif has_evidence:
                control_label = f"安全控制（漏洞证据: {evidence_text[:150]}）"
            else:
                control_label = f"针对 {vuln_desc} 的必要安全防护"

            if has_meaningful_root_cause:
                cause_detail = rc.summary
            elif finding.recommendation:
                cause_detail = f"{vuln_desc}: {finding.recommendation[:200]}"
            elif has_evidence:
                cause_detail = f"{vuln_desc}: {evidence_text[:200]}"
            else:
                cause_detail = f"根因分析未产出结构化结果，需人工审查 {vuln_desc} 的具体触发路径"

            goal = f"修复 {vuln_desc}，阻断漏洞利用路径，同时保持现有业务行为不变。"
            strategy = RemediationStrategy(
                strategy_type=RemediationStrategyType.CODE_CHANGE,
                summary=f"针对 {vuln_desc} 的最小化安全修复，补全缺失的安全控制。",
                steps=[
                    f"读取受影响文件并定位 {vuln_desc} 的触发代码路径。",
                    f"补全缺失的安全控制: {control_label}。",
                    "保持公开 API 和现有业务行为不变，除非漏洞本身要求拒绝请求。",
                    "优先做最小聚焦的 diff，避免大范围重构。",
                ],
                preferred=True,
            )
            # 构建 planned_changes（已去重 target_files）
            seen_files: set[str] = set()
            planned_changes = []
            for target in target_files[:5]:
                if target.lower() not in seen_files:
                    seen_files.add(target.lower())
                    planned_changes.append(PlannedChange(
                        file=target,
                        change_type="code",
                        description=f"在漏洞代码路径中添加或恢复 {vuln_desc} 的安全控制。",
                        reason=cause_detail,
                        risk_level=Severity.MEDIUM,
                    ))
            tests = [
                TestPlanItem(
                    name=f"{finding.finding_id} 安全回归",
                    test_type="security_regression",
                    target=finding.finding_id,
                    assertion=f"{vuln_desc} 的利用条件在补丁后被阻断",
                ),
                TestPlanItem(
                    name=f"{finding.finding_id} 兼容性回归",
                    test_type="business_regression",
                    target=target_files[0] if target_files else finding.finding_id,
                    assertion="现有受支持的业务行为在安全修复后保持不变",
                ),
            ]
            rejected = [
                RejectedAlternative(
                    "安全修复前做大范围重构",
                    "无关的大范围变更会增加差异风险，减缓审查速度",
                )
            ]
            risk_points = [
                f"通用修复方案用于 {vuln_desc}，未匹配到专用模板",
                "生成的补丁需人工审查确认修复精准度",
            ]
            if not has_meaningful_root_cause:
                risk_points.append("根因分析不完整，修复可能遗漏边缘情况")
            confidence = 0.55 if has_meaningful_root_cause else 0.40

        plan = RemediationPlan(
            finding_id=finding.finding_id,
            status=RemediationPlanStatus.READY,
            remediation_goal=goal,
            strategies=[strategy],
            planned_changes=planned_changes,
            dependency_upgrade=None,
            compatibility=CompatibilityAssessment(
                summary="静态模板化修复方案（LLM 分析不可用时的回退）。",
                risks=list(risk_points),
                required_checks=engineering.available_test_commands if engineering else [],
            ),
            risk_points=list(risk_points),
            required_tests=tests,
            rejected_alternatives=rejected,
            rollback=RollbackPlan(
                summary="Revert the generated code or manifest changes and rerun validation.",
                steps=["revert patch", "rerun build and security checks"],
            ),
            patch_boundaries=PatchBoundaries(
                allowed_files=[change.file for change in planned_changes],
                forbidden_changes=[
                    "do not weaken authentication, authorization, validation, or cryptographic checks",
                    "do not remove failing tests to make validation pass",
                ],
                maximum_changed_files=5,
                maximum_diff_lines=250,
            ),
            assumptions=["static_remediation_plan_from_template"],
            unknowns=[],
            confidence_score=confidence,
            needs_human_review=True,
        )
        if failure_analysis:
            plan = RemediationPlanAgent._apply_failure_feedback(plan, failure_analysis)
        return plan

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
                file=str(pc.get("file") or pc.get("target") or "unknown"),
                change_type=RemediationPlanAgent._normalize_change_type(pc),
                description=str(pc.get("description") or pc.get("summary") or "Apply required remediation change."),
                reason=str(pc.get("reason") or pc.get("rationale") or raw.get("remediation_goal", "")),
                risk_level=RemediationPlanAgent._normalize_severity(pc.get("risk_level", "medium")),
            )
            for pc in raw.get("planned_changes", [])
            if isinstance(pc, dict)
        ]
        if not planned_changes:
            target_files = [item.file for item in root_cause.affected_code] or [loc.file for loc in finding.locations]
            planned_changes = [
                PlannedChange(
                    file=target or "unknown",
                    change_type="code",
                    description="Apply the minimal code change required by the remediation goal.",
                    reason=raw.get("remediation_goal", root_cause.root_cause.summary),
                    risk_level=Severity.MEDIUM,
                )
                for target in target_files[:5]
            ]
        # Preserve every causally justified change.  De-duplication is safe;
        # truncating by a global file-count limit is not, because some fixes
        # legitimately span shared code, callers, configuration and tests.
        deduped_changes = []
        seen_files: set[str] = set()
        for change in planned_changes:
            if change.file in seen_files:
                continue
            seen_files.add(change.file)
            deduped_changes.append(change)
        planned_changes = deduped_changes
        required_tests = [
            TestPlanItem(name=t["name"], test_type=t["test_type"],
                        target=t["target"], assertion=t["assertion"])
            for t in raw.get("required_tests", [])
        ]
        rejected = [
            RejectedAlternative(ra["alternative"], ra["reason"])
            for ra in raw.get("rejected_alternatives", [])
        ]
        boundary_data = raw.get("patch_boundaries") if isinstance(raw.get("patch_boundaries"), dict) else {}
        default_diff_budget = max(250, 150 * max(1, len(planned_changes)))
        boundaries = PatchBoundaries(
            allowed_files=[pc.file for pc in planned_changes],
            forbidden_changes=["不得绕过或削弱现有安全校验", "不得删除失败测试"],
            maximum_changed_files=max(
                len(planned_changes), int(boundary_data.get("maximum_changed_files", len(planned_changes) or 1))
            ),
            maximum_diff_lines=int(boundary_data.get("maximum_diff_lines", default_diff_budget)),
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
    def _normalize_change_type(change: dict) -> str:
        value = str(
            change.get("change_type")
            or change.get("type")
            or change.get("operation")
            or ""
        ).strip().lower()
        aliases = {
            "": "code",
            "add": "code",
            "addition": "code",
            "create": "code",
            "modify": "code",
            "modification": "code",
            "update": "code",
            "edit": "code",
            "source": "code",
            "config": "configuration",
            "configuration_change": "configuration",
            "dependency_upgrade": "dependency",
            "package": "dependency",
            "tests": "test",
            "test_only": "test",
            "doc": "documentation",
            "docs": "documentation",
        }
        return aliases.get(value, value)

    @staticmethod
    def _normalize_severity(value: object) -> Severity:
        try:
            return Severity(str(value or "medium").strip().lower())
        except ValueError:
            return Severity.MEDIUM

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

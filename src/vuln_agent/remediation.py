from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .models import (
    AssessmentStatus,
    CompatibilityAssessment,
    DependencyUpgradePlan,
    EngineeringContext,
    FailureAnalysisResult,
    FailureCategory,
    ImpactAssessment,
    NormalizedVulnerability,
    PatchBoundaries,
    PlannedChange,
    RejectedAlternative,
    RemediationPlan,
    RemediationPlanStatus,
    RemediationPolicy,
    RemediationStrategy,
    RemediationStrategyType,
    RollbackPlan,
    RootCauseAssessment,
    RootCauseCategory,
    Severity,
    TestPlanItem,
)

if TYPE_CHECKING:
    from .llm import LLMBackend


@dataclass(slots=True)
class RemediationPlanAgent:
    policy: RemediationPolicy
    llm: "LLMBackend | None" = None

    def plan(
        self,
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
        root_cause: RootCauseAssessment,
        engineering: EngineeringContext | None = None,
        failure_analysis: FailureAnalysisResult | None = None,
    ) -> RemediationPlan:
        if self.llm:
            return self._llm_plan(finding, impact, root_cause, engineering, failure_analysis)
        return self._deterministic_plan(finding, impact, root_cause, engineering, failure_analysis)

    def _llm_plan(
        self,
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
        root_cause: RootCauseAssessment,
        engineering: EngineeringContext | None = None,
        failure_analysis: FailureAnalysisResult | None = None,
    ) -> RemediationPlan:
        """使用 LLM 推理最优修复策略。"""
        from .llm import REMEDIATION_PLAN_SCHEMA

        engineering = engineering or EngineeringContext()
        prompt = self._build_plan_prompt(finding, impact, root_cause, engineering, failure_analysis)
        raw = self.llm.reason(  # type: ignore[union-attr]
            prompt,
            system_prompt="你是资深安全修复工程师。为漏洞设计最优修复方案，包含策略选择、变更计划、风险点和测试要求。",
            output_schema=REMEDIATION_PLAN_SCHEMA,
        )
        if isinstance(raw, str):
            return self._deterministic_plan(finding, impact, root_cause, engineering, failure_analysis)
        return self._dict_to_remediation_plan(finding, impact, root_cause, engineering, raw, failure_analysis)

    def _deterministic_plan(
        self,
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
        root_cause: RootCauseAssessment,
        engineering: EngineeringContext | None = None,
        failure_analysis: FailureAnalysisResult | None = None,
    ) -> RemediationPlan:
        engineering = engineering or EngineeringContext()
        if not self._root_cause_is_actionable(root_cause):
            return self._apply_failure_feedback(
                self._investigation_plan(finding, impact, root_cause, engineering),
                failure_analysis,
            )

        if root_cause.root_cause_category == RootCauseCategory.VULNERABLE_DEPENDENCY:
            return self._apply_failure_feedback(
                self._dependency_plan(finding, impact, root_cause, engineering),
                failure_analysis,
            )
        if root_cause.root_cause_category == RootCauseCategory.INSECURE_CONFIGURATION:
            return self._apply_failure_feedback(
                self._configuration_plan(finding, impact, root_cause, engineering),
                failure_analysis,
            )
        return self._apply_failure_feedback(
            self._code_plan(finding, impact, root_cause, engineering),
            failure_analysis,
        )

    def _code_plan(
        self,
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
        root_cause: RootCauseAssessment,
        engineering: EngineeringContext,
    ) -> RemediationPlan:
        pattern = self._code_strategy(finding, root_cause)
        changes = [
            PlannedChange(
                file=item.file,
                change_type="code",
                description=pattern["change"],
                reason=root_cause.root_cause.summary,
                risk_level=Severity.MEDIUM,
            )
            for item in root_cause.affected_code
        ]
        if not changes:
            changes = [
                PlannedChange(
                    file=location.file,
                    change_type="code",
                    description=pattern["change"],
                    reason="scanner reported primary affected location",
                    risk_level=Severity.MEDIUM,
                )
                for location in finding.locations
            ]

        tests = self._base_tests(finding, impact, engineering)
        tests.append(TestPlanItem(
            name=f"{finding.vulnerability_type} security regression",
            test_type="security_regression",
            target=finding.locations[0].file if finding.locations else finding.finding_id,
            assertion=pattern["security_assertion"],
        ))

        risks = [
            "修复可能改变输入处理、输出格式或错误返回行为",
            "如果仅在局部位置修复，其他同类调用点仍可能残留风险",
        ]
        compatibility = CompatibilityAssessment(
            summary="代码级安全控制变更，需要验证原业务语义保持不变",
            risks=risks,
            required_checks=self._required_checks(impact, engineering),
        )

        return self._build_plan(
            finding=finding,
            impact=impact,
            root_cause=root_cause,
            engineering=engineering,
            status=RemediationPlanStatus.READY,
            goal=pattern["goal"],
            strategies=[RemediationStrategy(
                RemediationStrategyType.CODE_CHANGE,
                pattern["strategy"],
                pattern["steps"],
            )],
            planned_changes=changes,
            dependency_upgrade=None,
            compatibility=compatibility,
            risk_points=risks,
            required_tests=tests,
            rejected_alternatives=[
                RejectedAlternative(pattern["bad_alternative"], pattern["bad_alternative_reason"])
            ],
            rollback=RollbackPlan(
                summary="回滚本次代码和测试变更，恢复到修复前提交",
                steps=["revert remediation commit", "重新运行构建与核心回归测试", "确认漏洞工单恢复为待修复状态"],
            ),
        )

    def _dependency_plan(
        self,
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
        root_cause: RootCauseAssessment,
        engineering: EngineeringContext,
    ) -> RemediationPlan:
        dependency = finding.dependency
        component = dependency.component if dependency else root_cause.causal_chain[-1]
        fixed_versions = dependency.fixed_versions if dependency else []
        minimum_safe = fixed_versions[0] if fixed_versions else None
        recommended = fixed_versions[-1] if fixed_versions else minimum_safe
        breaking = "unknown"
        if dependency and dependency.breaking_upgrade is True:
            breaking = "high"
        elif dependency and dependency.breaking_upgrade is False:
            breaking = "low"

        upgrade = DependencyUpgradePlan(
            component=component,
            current_version=dependency.current_version if dependency else None,
            minimum_safe_version=minimum_safe,
            recommended_stable_version=recommended,
            breaking_upgrade_risk=breaking,
            code_adaptation_required=dependency.breaking_upgrade if dependency else None,
            temporary_mitigation="如短期无法升级，可在网关/WAF/配置层临时禁用受影响功能或限制高危输入，但仍需保留升级任务",
        )
        status = RemediationPlanStatus.READY if self.policy.allow_dependency_upgrade and minimum_safe else RemediationPlanStatus.NEEDS_HUMAN_REVIEW
        risks = [
            "依赖升级可能引入 API 行为变化或传递依赖冲突",
            "锁文件和制品构建结果需要一起验证",
        ]
        if not minimum_safe:
            risks.append("缺少明确安全版本，不能自动规划升级目标")
        if not self.policy.allow_dependency_upgrade:
            risks.append("当前策略禁止自动规划依赖升级")

        changes = self._dependency_change_files(finding, engineering)
        tests = self._base_tests(finding, impact, engineering)
        tests.append(TestPlanItem(
            name=f"{component} dependency compatibility regression",
            test_type="compatibility",
            target=component,
            assertion="依赖升级后构建、核心业务回归和漏洞复扫均通过",
        ))

        return self._build_plan(
            finding=finding,
            impact=impact,
            root_cause=root_cause,
            engineering=engineering,
            status=status,
            goal=f"将 {component} 从受影响版本升级到安全版本，并验证业务兼容性",
            strategies=[
                RemediationStrategy(
                    RemediationStrategyType.DEPENDENCY_UPGRADE,
                    "优先选择最小安全版本；若已有稳定推荐版本，再评估升级到推荐稳定版本",
                    [
                        "确认当前版本、传递依赖路径和运行时使用情况",
                        "比较最小安全版本、推荐稳定版本和破坏性升级风险",
                        "更新依赖声明与锁文件",
                        "运行构建、依赖兼容性测试、业务回归和 SCA 复扫",
                    ],
                )
            ],
            planned_changes=changes,
            dependency_upgrade=upgrade,
            compatibility=CompatibilityAssessment(
                summary="依赖升级需要重点验证传递依赖、运行时行为和制品构建一致性",
                risks=risks,
                required_checks=self._required_checks(impact, engineering) + ["SCA rescan", "dependency lockfile verification"],
            ),
            risk_points=risks,
            required_tests=tests,
            rejected_alternatives=[
                RejectedAlternative("直接升级到最新版", "最新版可能包含未评估的破坏性变更，企业修复应优先选择最小安全版本或推荐稳定版本"),
                RejectedAlternative("只在扫描器中标记忽略", "不能消除真实受影响组件，且无法通过后续安全验证"),
            ],
            rollback=RollbackPlan(
                summary="回滚依赖声明和锁文件，恢复旧制品并重新触发漏洞工单",
                steps=["revert dependency manifest and lockfile changes", "重新构建旧版本制品", "确认回滚版本对应风险仍被跟踪"],
            ),
        )

    def _configuration_plan(
        self,
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
        root_cause: RootCauseAssessment,
        engineering: EngineeringContext,
    ) -> RemediationPlan:
        config_files = [location.file for location in finding.locations] or ["configuration source"]
        risks = [
            "配置收紧可能影响历史客户端、跨域调用或部署环境差异",
            "需要确认不同环境的配置覆盖优先级",
        ]
        tests = self._base_tests(finding, impact, engineering)
        tests.append(TestPlanItem(
            name=f"{finding.vulnerability_type} configuration regression",
            test_type="security_regression",
            target=", ".join(config_files),
            assertion="不安全配置项在有效运行配置中不再生效",
        ))
        return self._build_plan(
            finding=finding,
            impact=impact,
            root_cause=root_cause,
            engineering=engineering,
            status=RemediationPlanStatus.READY,
            goal="将不安全配置调整为安全基线，并验证各环境有效配置一致",
            strategies=[
                RemediationStrategy(
                    RemediationStrategyType.CONFIGURATION_CHANGE,
                    "修改配置源中的不安全值，并补充配置有效性验证",
                    ["定位最终生效配置", "调整为安全基线值", "验证开发、测试、生产等环境覆盖关系"],
                )
            ],
            planned_changes=[
                PlannedChange(file=file, change_type="configuration", description="replace unsafe configuration with secure baseline", reason=root_cause.root_cause.summary)
                for file in config_files
            ],
            dependency_upgrade=None,
            compatibility=CompatibilityAssessment(
                summary="配置变更需要验证部署环境覆盖顺序和兼容客户端",
                risks=risks,
                required_checks=self._required_checks(impact, engineering) + ["effective configuration verification"],
            ),
            risk_points=risks,
            required_tests=tests,
            rejected_alternatives=[
                RejectedAlternative("只修改文档不修改有效配置", "无法保证运行时风险被消除")
            ],
            rollback=RollbackPlan(
                summary="恢复配置变更，并在工单中记录回滚原因",
                steps=["revert configuration change", "重新加载或重新部署服务", "验证服务恢复到回滚前行为"],
            ),
        )

    def _investigation_plan(
        self,
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
        root_cause: RootCauseAssessment,
        engineering: EngineeringContext,
    ) -> RemediationPlan:
        unknowns = list(dict.fromkeys([*impact.unknowns, *root_cause.unknowns]))
        risks = ["根因证据不足，直接生成补丁可能造成误修或业务破坏"]
        return self._build_plan(
            finding=finding,
            impact=impact,
            root_cause=root_cause,
            engineering=engineering,
            status=RemediationPlanStatus.NEEDS_CONTEXT,
            goal="补齐影响面和根因证据后再进入补丁生成",
            strategies=[
                RemediationStrategy(
                    RemediationStrategyType.INVESTIGATION_REQUIRED,
                    "暂停自动补丁生成，先收集可证明的 source-to-sink、运行时或依赖证据",
                    [
                        "补充代码调用链和数据流证据",
                        "确认受影响服务、入口、认证要求和资产暴露情况",
                        "确认缺失或失效的安全控制",
                    ],
                )
            ],
            planned_changes=[],
            dependency_upgrade=None,
            compatibility=CompatibilityAssessment(
                summary="当前不建议评估代码兼容性，需先补齐上下文",
                risks=risks,
                required_checks=["manual security review", "context collection"],
            ),
            risk_points=risks,
            required_tests=[],
            rejected_alternatives=[
                RejectedAlternative("在根因未确认时直接让 Coding Agent 修改代码", "缺少可验证目标，容易只堵症状或引入业务回归")
            ],
            rollback=RollbackPlan(
                summary="未生成代码变更，无需代码回滚",
                steps=["关闭本轮自动补丁尝试", "将缺失证据写入工单", "补齐证据后重新运行根因定位和修复方案 Agent"],
            ),
            extra_unknowns=unknowns,
        )

    def _build_plan(
        self,
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
        root_cause: RootCauseAssessment,
        engineering: EngineeringContext,
        status: RemediationPlanStatus,
        goal: str,
        strategies: list[RemediationStrategy],
        planned_changes: list[PlannedChange],
        dependency_upgrade: DependencyUpgradePlan | None,
        compatibility: CompatibilityAssessment,
        risk_points: list[str],
        required_tests: list[TestPlanItem],
        rejected_alternatives: list[RejectedAlternative],
        rollback: RollbackPlan,
        extra_unknowns: list[str] | None = None,
    ) -> RemediationPlan:
        unknowns = list(dict.fromkeys([*(extra_unknowns or []), *root_cause.unknowns]))
        assumptions = self._assumptions(impact, engineering)
        boundaries = PatchBoundaries(
            allowed_files=self._allowed_files(finding, root_cause, engineering),
            forbidden_changes=[
                "不得绕过或削弱现有安全校验",
                "不得删除失败测试来换取验证通过",
                "不得修改 CI/CD 安全门禁来规避扫描",
                "不得访问生产密钥、生产数据库或真实用户数据",
            ],
            maximum_changed_files=self.policy.maximum_changed_files,
            maximum_diff_lines=self.policy.maximum_diff_lines,
        )
        needs_review = (
            status != RemediationPlanStatus.READY
            or root_cause.needs_human_review
            or impact.needs_human_review
            or len(planned_changes) > self.policy.maximum_changed_files
        )
        confidence = self._score(status, impact.confidence_score, root_cause.confidence_score, len(unknowns))
        return RemediationPlan(
            finding_id=finding.finding_id,
            status=status,
            remediation_goal=goal,
            strategies=strategies,
            planned_changes=planned_changes,
            dependency_upgrade=dependency_upgrade,
            compatibility=compatibility,
            risk_points=risk_points,
            required_tests=required_tests,
            rejected_alternatives=rejected_alternatives,
            rollback=rollback,
            patch_boundaries=boundaries,
            assumptions=assumptions,
            unknowns=unknowns,
            confidence_score=confidence,
            needs_human_review=needs_review,
        )

    def _base_tests(
        self,
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
        engineering: EngineeringContext,
    ) -> list[TestPlanItem]:
        tests: list[TestPlanItem] = []
        for target in list(dict.fromkeys([*impact.regression_targets, *engineering.related_tests])):
            tests.append(TestPlanItem(
                name=f"business regression for {target}",
                test_type="business_regression",
                target=target,
                assertion="原有业务流程和接口契约保持不变",
            ))
        for suggested in impact.suggested_tests:
            tests.append(TestPlanItem(
                name=suggested,
                test_type="impact_regression",
                target=finding.finding_id,
                assertion="影响面相关安全或业务假设得到验证",
            ))
        if self.policy.require_security_regression_test:
            tests.append(TestPlanItem(
                name="scanner rescan",
                test_type="security_scan",
                target=finding.scanner,
                assertion="原始漏洞规则或同类规则不再命中",
            ))
        return tests

    def _code_strategy(self, finding: NormalizedVulnerability, root_cause: RootCauseAssessment) -> dict[str, object]:
        vuln = finding.vulnerability_type.lower()
        category = root_cause.root_cause_category
        if root_cause.root_cause.missing_control == "check_alias_validation":
            return {
                "goal": "确保所有进入 SQL 列别名（AS alias）的字段名先经过 check_alias() 校验，阻断分号、引号、空白和 SQL 注释标记类 payload",
                "strategy": "在 Query.set_values() 的 fields 入口统一执行 check_alias()，覆盖 values() 与 values_list() 共享路径",
                "change": "add check_alias validation before values_select stores field names",
                "steps": [
                    "在 set_values() 的 if fields: 分支开头遍历 fields",
                    "对每个 field 调用 self.check_alias(field)",
                    "保留后续 field_names、extra_names、annotation_names 的原有解析逻辑",
                    "新增 values()/values_list() 恶意 alias 回归测试",
                ],
                "security_assertion": "包含空白、引号、分号或 SQL 注释标记的 alias payload 会在进入 SQL 编译前被拒绝",
                "bad_alternative": "只依赖 SQL compiler 的 quote_name() 包裹 alias",
                "bad_alternative_reason": "quote_name() 只能做名称引用，不能替代安全不变量校验；分号、引号和注释标记仍可能破坏 SQL 语义边界",
            }
        if "sql injection" in vuln or root_cause.root_cause.missing_control == "parameterized_query":
            return {
                "goal": "阻断不可信输入进入 SQL 拼接执行路径，同时保持原查询语义",
                "strategy": "使用参数化查询或等价安全 ORM API 替换字符串拼接 SQL",
                "change": "replace SQL string concatenation with parameterized query",
                "steps": ["保留原查询条件语义", "将用户输入作为绑定参数传入", "覆盖恶意 SQL payload 和正常查询用例"],
                "security_assertion": "恶意 SQL payload 不会改变查询结构或执行额外语句",
                "bad_alternative": "只对输入做 SQL 关键字黑名单过滤",
                "bad_alternative_reason": "黑名单容易被编码、注释、大小写和数据库方言绕过",
            }
        if "xss" in vuln or category == RootCauseCategory.MISSING_OUTPUT_ENCODING:
            return {
                "goal": "在正确输出上下文中编码不可信数据，防止脚本执行",
                "strategy": "使用模板/框架提供的上下文感知输出编码或安全富文本白名单",
                "change": "apply context-aware output encoding",
                "steps": ["识别输出上下文", "使用框架安全 API 编码", "覆盖 HTML/属性/脚本上下文测试"],
                "security_assertion": "恶意脚本作为文本显示或被安全过滤，不会执行",
                "bad_alternative": "仅删除少量特殊字符",
                "bad_alternative_reason": "字符删除会破坏业务内容且无法覆盖所有输出上下文",
            }
        if "path traversal" in vuln or category == RootCauseCategory.PATH_BOUNDARY_VIOLATION:
            return {
                "goal": "确保文件访问被限制在授权目录边界内",
                "strategy": "路径归一化后执行目录边界校验，并拒绝符号链接或编码绕过",
                "change": "add canonical path boundary validation",
                "steps": ["对目标路径做 canonical/realpath 解析", "校验解析后路径位于允许目录", "补充 ../、编码和符号链接绕过测试"],
                "security_assertion": "目录穿越 payload 无法读取或写入授权目录外资源",
                "bad_alternative": "只检查输入字符串是否包含 ../",
                "bad_alternative_reason": "字符串检查无法覆盖编码、路径分隔符差异和符号链接绕过",
            }
        if category in {RootCauseCategory.MISSING_AUTHORIZATION, RootCauseCategory.INCORRECT_AUTHORIZATION_SCOPE}:
            return {
                "goal": "恢复服务端对象级权限校验和租户隔离",
                "strategy": "在受影响入口或服务层增加服务端授权检查",
                "change": "add server-side object authorization check",
                "steps": ["识别资源归属", "校验当前主体是否可访问目标对象", "补充跨用户/跨租户拒绝测试"],
                "security_assertion": "未授权主体无法访问其他用户或租户资源",
                "bad_alternative": "只在前端隐藏入口",
                "bad_alternative_reason": "前端控制不能作为服务端安全边界",
            }
        return {
            "goal": f"修复 {finding.vulnerability_type} 的已确认根因",
            "strategy": "按根因约束补充缺失安全控制",
            "change": "add missing security control",
            "steps": ["根据根因摘要定位缺失控制", "补充最小范围修复", "新增安全回归测试"],
            "security_assertion": "原始漏洞触发样例不再成立",
            "bad_alternative": "只修改扫描器告警位置",
            "bad_alternative_reason": "可能未覆盖真实触发路径和同类风险点",
        }

    def _allowed_files(
        self,
        finding: NormalizedVulnerability,
        root_cause: RootCauseAssessment,
        engineering: EngineeringContext,
    ) -> list[str]:
        files = [item.file for item in root_cause.affected_code]
        files.extend(location.file for location in finding.locations)
        files.extend(engineering.related_tests)
        return list(dict.fromkeys(file for file in files if file))

    def _dependency_change_files(self, finding: NormalizedVulnerability, engineering: EngineeringContext) -> list[PlannedChange]:
        candidates: list[str] = []
        for location in finding.locations:
            candidates.append(location.file)
        if engineering.package_manager == "pip":
            candidates.extend(["requirements.txt", "pyproject.toml"])
        elif engineering.package_manager == "npm":
            candidates.extend(["package.json", "package-lock.json"])
        elif engineering.package_manager == "maven":
            candidates.append("pom.xml")
        elif engineering.package_manager == "gradle":
            candidates.extend(["build.gradle", "gradle.lockfile"])
        else:
            candidates.append("dependency manifest and lockfile")
        return [
            PlannedChange(file=file, change_type="dependency", description="upgrade vulnerable dependency to safe version", reason="component version matches vulnerability intelligence")
            for file in list(dict.fromkeys(candidates))
        ]

    @staticmethod
    def _apply_failure_feedback(
        plan: RemediationPlan,
        failure_analysis: FailureAnalysisResult | None,
    ) -> RemediationPlan:
        if failure_analysis is None:
            return plan

        plan.assumptions.append(f"replanned_after_failure: {failure_analysis.patch_id}")
        plan.risk_points.extend(failure_analysis.remediation_feedback)
        plan.compatibility.risks.extend(failure_analysis.remediation_feedback)
        plan.compatibility.required_checks.extend(failure_analysis.validation_feedback)
        plan.unknowns.extend(
            f"previous_failure:{finding.category.value}"
            for finding in failure_analysis.findings
            if finding.category in {FailureCategory.TOOLING_GAP, FailureCategory.UNKNOWN}
        )

        if failure_analysis.requires_root_cause_recheck:
            plan.needs_human_review = True
            plan.risk_points.append("previous validation suggests the root cause or affected path may still be incomplete")

        categories = {finding.category for finding in failure_analysis.findings}
        if FailureCategory.SECURITY_NOT_FIXED in categories:
            plan.required_tests.append(TestPlanItem(
                name="reproduced exploit regression from failed validation",
                test_type="security_regression",
                target=plan.finding_id,
                assertion="the exact payload or exploit condition from the failed validation no longer succeeds",
            ))
        if FailureCategory.BUSINESS_REGRESSION in categories:
            plan.required_tests.append(TestPlanItem(
                name="business contract regression from failed validation",
                test_type="business_regression",
                target=plan.finding_id,
                assertion="existing API response shape, status code, and core business semantics remain unchanged",
            ))
        if FailureCategory.BUILD_FAILURE in categories:
            plan.compatibility.required_checks.append("re-run failed build command before security validation")
        if FailureCategory.PATCH_POLICY_VIOLATION in categories or FailureCategory.DIFFERENTIAL_RISK in categories:
            plan.patch_boundaries.forbidden_changes.append("do not introduce unrelated behavior changes while addressing validation feedback")

        plan.risk_points = list(dict.fromkeys(plan.risk_points))
        plan.compatibility.risks = list(dict.fromkeys(plan.compatibility.risks))
        plan.compatibility.required_checks = list(dict.fromkeys(plan.compatibility.required_checks))
        plan.assumptions = list(dict.fromkeys(plan.assumptions))
        plan.unknowns = list(dict.fromkeys(plan.unknowns))
        return plan

    @staticmethod
    def _required_checks(impact: ImpactAssessment, engineering: EngineeringContext) -> list[str]:
        checks = list(engineering.available_test_commands)
        checks.extend(["build", "unit tests"])
        if impact.entry_points:
            checks.append("API smoke tests")
        if impact.affected_assets:
            checks.append("artifact rebuild verification")
        return list(dict.fromkeys(checks))

    @staticmethod
    def _assumptions(impact: ImpactAssessment, engineering: EngineeringContext) -> list[str]:
        assumptions = []
        if engineering.language:
            assumptions.append(f"代码语言为 {engineering.language}")
        if engineering.framework:
            assumptions.append(f"框架为 {engineering.framework}")
        if impact.entry_points:
            assumptions.append("影响面分析给出的入口路径是当前修复验证范围")
        return assumptions

    @staticmethod
    def _root_cause_is_actionable(root_cause: RootCauseAssessment) -> bool:
        return (
            root_cause.status in {AssessmentStatus.CONFIRMED, AssessmentStatus.PROBABLE}
            and root_cause.root_cause_category != RootCauseCategory.UNKNOWN
        )

    @staticmethod
    def _score(status: RemediationPlanStatus, impact_score: float, root_cause_score: float, unknown_count: int) -> float:
        base = 0.2 if status == RemediationPlanStatus.READY else 0.05
        score = base + impact_score * 0.3 + root_cause_score * 0.5
        score -= min(0.25, unknown_count * 0.05)
        return round(max(0.0, min(1.0, score)), 2)

    # ── LLM 推理方法 ──────────────────────────────────────────────────

    @staticmethod
    def _build_plan_prompt(finding, impact, root_cause, engineering, failure_analysis) -> str:
        constraints = "\n".join(f"- {c}" for c in root_cause.recommended_fix_constraints) if root_cause.recommended_fix_constraints else "无"
        fb = ""
        if failure_analysis:
            fb = f"\n上次失败分析:\n- 原因: {failure_analysis.summary}\n- 建议: {'; '.join(failure_analysis.remediation_feedback)}"

        return f"""为以下漏洞生成修复方案：

漏洞: {finding.finding_id} ({finding.vulnerability_type})
根因: {root_cause.root_cause.summary}
缺失控制: {root_cause.root_cause.missing_control}
根因分类: {root_cause.root_cause_category.value}
修复约束:
{constraints}

影响面:
- 服务: {impact.affected_services}
- 入口: {[(e.route, e.method) for e in impact.entry_points]}
- 数据分类: {impact.data_classification}

工程上下文:
- 语言: {engineering.language or 'unknown'}
- 框架: {engineering.framework or 'unknown'}
- 包管理器: {engineering.package_manager or 'unknown'}
- 测试命令: {engineering.available_test_commands or 'none'}
{fb}

请设计修复方案，选择最优策略(code_change / dependency_upgrade / configuration_change)并给出具体步骤。"""

    @staticmethod
    def _dict_to_remediation_plan(finding, impact, root_cause, engineering, raw: dict, failure_analysis) -> RemediationPlan:
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
            TestPlanItem(name=t["name"], test_type=t["test_type"], target=t["target"], assertion=t["assertion"])
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
                summary="LLM 生成修复方案",
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

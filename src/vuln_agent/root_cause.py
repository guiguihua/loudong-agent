from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

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
from .tools import RootCauseCodeContext, RootCauseEvidenceTool

if TYPE_CHECKING:
    from .llm import LLMBackend


@dataclass(frozen=True, slots=True)
class RootCausePattern:
    category: RootCauseCategory
    missing_control: str
    fix_constraints: tuple[str, ...]


PATTERNS: dict[str, RootCausePattern] = {
    "sql injection": RootCausePattern(
        RootCauseCategory.MISSING_SECURITY_CONTROL,
        "parameterized_query",
        ("必须使用参数化查询或等价安全 API", "不得仅使用 SQL 字符黑名单", "必须保留原查询业务语义"),
    ),
    "cross-site scripting": RootCausePattern(
        RootCauseCategory.MISSING_OUTPUT_ENCODING,
        "context_aware_output_encoding",
        ("必须按 HTML/属性/JavaScript 上下文编码", "不得通过删除输入字符替代输出编码"),
    ),
    "path traversal": RootCausePattern(
        RootCauseCategory.PATH_BOUNDARY_VIOLATION,
        "canonical_path_boundary_check",
        ("必须进行路径归一化和目录边界校验", "必须覆盖编码和符号链接绕过测试"),
    ),
    "unsafe deserialization": RootCausePattern(
        RootCauseCategory.UNSAFE_DESERIALIZATION,
        "deserialization_type_allowlist",
        ("必须限制可反序列化类型", "不得反序列化不可信输入中的任意对象"),
    ),
    "authorization bypass": RootCausePattern(
        RootCauseCategory.MISSING_AUTHORIZATION,
        "server_side_object_authorization",
        ("必须在服务端执行对象级权限校验", "必须验证租户及资源归属"),
    ),
}


PATTERNS["sql alias injection"] = RootCausePattern(
    RootCauseCategory.MISSING_SECURITY_CONTROL,
    "check_alias_validation",
    (
        "任何最终进入 SQL 列别名的字符串都必须经过别名安全校验",
        "不得只依赖 quote_name() 的引号包裹来阻断分号、注释或引号类 payload",
        "必须覆盖 values() 和 values_list() 共享入口",
    ),
)


@dataclass(slots=True)
class RootCauseAnalysisAgent:
    evidence_tool: RootCauseEvidenceTool
    llm: "LLMBackend | None" = None

    def analyze(
        self,
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
    ) -> RootCauseAssessment:
        if self.llm:
            return self._llm_analyze(finding, impact)
        return self._deterministic_analyze(finding, impact)

    def _llm_analyze(
        self,
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
    ) -> RootCauseAssessment:
        """使用 LLM 推理根因，不依赖硬编码模式匹配。"""
        from .llm import ROOT_CAUSE_SCHEMA

        code = self.evidence_tool.collect_code_evidence(finding)
        prompt = self._build_root_cause_prompt(finding, impact, code)
        raw = self.llm.reason(  # type: ignore[union-attr]
            prompt,
            system_prompt="你是资深安全研究员。分析漏洞的完整根因：从不可信输入进入点(source)到危险操作(sink)的完整数据流，识别缺失的安全控制。",
            output_schema=ROOT_CAUSE_SCHEMA,
        )
        if isinstance(raw, str):
            return self._deterministic_analyze(finding, impact)
        return self._dict_to_root_cause(finding, raw)

    def _deterministic_analyze(
        self,
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
    ) -> RootCauseAssessment:
        code = self.evidence_tool.collect_code_evidence(finding)
        configurations = self.evidence_tool.collect_configuration_evidence(finding)
        dependency = self.evidence_tool.collect_dependency_evidence(finding)

        if finding.dependency or dependency:
            return self._analyze_dependency(finding, impact, dependency)
        unsafe_configs = [item for item in configurations if item.unsafe]
        if unsafe_configs:
            return self._analyze_configuration(finding, impact, unsafe_configs)
        return self._analyze_code(finding, impact, code)

    def _analyze_code(
        self,
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
        code: RootCauseCodeContext,
    ) -> RootCauseAssessment:
        pattern = PATTERNS.get(finding.vulnerability_type.lower())
        unknowns: list[str] = []
        if not code.source:
            unknowns.append("untrusted_source")
        if not code.sink:
            unknowns.append("dangerous_sink")
        if not code.evidence_available:
            unknowns.append("source_to_sink_evidence")
        if impact.needs_human_review:
            unknowns.append("confirmed_impact_scope")

        causal_chain: list[str] = []
        if code.source:
            causal_chain.append(f"不可信输入来自 {code.source.symbol}")
        causal_chain.extend(f"{step.symbol}: {step.operation}" for step in code.propagation)
        if code.sink:
            causal_chain.append(f"数据进入危险操作 {code.sink.symbol}")

        confirmed_chain = bool(code.source and code.sink and code.evidence_available)
        if confirmed_chain and not impact.needs_human_review:
            status = AssessmentStatus.CONFIRMED
        elif confirmed_chain:
            status = AssessmentStatus.PROBABLE
        elif code.source or code.sink:
            status = AssessmentStatus.POSSIBLE
        else:
            status = AssessmentStatus.UNKNOWN

        evidence: list[Evidence] = []
        if code.evidence_available:
            evidence.append(Evidence(
                "root-cause-dataflow",
                "ast_dataflow",
                "untrusted_source_reaches_dangerous_sink",
                {"source": code.source.symbol if code.source else None, "sink": code.sink.symbol if code.sink else None},
                Confidence.HIGH if confirmed_chain else Confidence.MEDIUM,
            ))
        if code.guards:
            evidence.append(Evidence("existing-guards", "code_analysis", "security_guards_present", code.guards, Confidence.MEDIUM))

        category = pattern.category if pattern else RootCauseCategory.UNKNOWN
        missing_control = pattern.missing_control if pattern else None
        constraints = list(pattern.fix_constraints if pattern else ())
        constraints.append(f"必须新增 {finding.vulnerability_type} 安全回归测试")
        affected_code = self._affected_code(finding, code)
        score = self._score(confirmed_chain, bool(code.failed_controls), impact.confidence_score, len(unknowns))
        needs_review = status != AssessmentStatus.CONFIRMED or category == RootCauseCategory.UNKNOWN
        summary = self._summary(finding, code, missing_control)

        return RootCauseAssessment(
            finding_id=finding.finding_id,
            status=status,
            root_cause_category=category,
            root_cause=RootCause(
                summary=summary,
                source=code.source,
                propagation=code.propagation,
                sink=code.sink,
                missing_control=missing_control,
                failed_existing_controls=code.failed_controls,
                trigger_conditions=code.trigger_conditions,
            ),
            contributing_factors=self._contributing_factors(code),
            causal_chain=causal_chain,
            affected_code=affected_code,
            evidence=evidence,
            alternative_hypotheses=self._alternatives(code),
            confidence_score=score,
            unknowns=list(dict.fromkeys(unknowns)),
            needs_human_review=needs_review,
            recommended_fix_constraints=constraints,
            security_invariant=self._security_invariant(finding, missing_control),
            guardrail=missing_control,
            broken_mechanism=self._broken_mechanism(code),
            exploitability_note=self._exploitability_note(missing_control),
        )

    def _analyze_dependency(self, finding, impact, dependency) -> RootCauseAssessment:
        confirmed = bool(dependency and dependency.cve_match_confirmed)
        unknowns = [] if confirmed else ["confirmed_component_cve_match"]
        if dependency and dependency.runtime_used is None:
            unknowns.append("runtime_component_usage")
        if impact.needs_human_review:
            unknowns.append("confirmed_impact_scope")
        component = dependency.component if dependency else finding.dependency.component
        path = dependency.dependency_path if dependency else []
        evidence = []
        if confirmed:
            evidence.append(Evidence("dependency-cve", "sbom", "component_version_matches_cve", component, Confidence.HIGH))
        return RootCauseAssessment(
            finding_id=finding.finding_id,
            status=AssessmentStatus.CONFIRMED if confirmed else AssessmentStatus.POSSIBLE,
            root_cause_category=RootCauseCategory.VULNERABLE_DEPENDENCY,
            root_cause=RootCause(
                summary=f"制品通过依赖路径引入存在已知漏洞的组件 {component}",
                source=None,
                propagation=[],
                sink=None,
                missing_control="safe_dependency_version",
                failed_existing_controls=[],
                trigger_conditions=["受影响组件被打包或部署"],
            ),
            contributing_factors=["依赖版本未升级到安全版本"],
            causal_chain=[*path, component] if path else [component],
            affected_code=[],
            evidence=evidence,
            alternative_hypotheses=[],
            confidence_score=round(min(1.0, 0.45 + (0.35 if confirmed else 0) + impact.confidence_score * 0.2), 2),
            unknowns=unknowns,
            needs_human_review=not confirmed or impact.needs_human_review,
            recommended_fix_constraints=["优先选择最小安全版本", "必须验证传递依赖和构建锁文件", "必须执行依赖兼容性回归测试"],
        )

    def _analyze_configuration(self, finding, impact, configurations) -> RootCauseAssessment:
        config = configurations[0]
        evidence = [Evidence("unsafe-config", "configuration", "effective_configuration_is_unsafe", {config.key: config.effective_value}, Confidence.HIGH)]
        return RootCauseAssessment(
            finding_id=finding.finding_id,
            status=AssessmentStatus.CONFIRMED,
            root_cause_category=RootCauseCategory.INSECURE_CONFIGURATION,
            root_cause=RootCause(
                summary=f"有效配置 {config.key} 使用了不安全值 {config.effective_value}",
                source=None,
                propagation=[],
                sink=None,
                missing_control="secure_configuration_value",
                failed_existing_controls=[],
                trigger_conditions=[f"运行环境加载 {config.key}={config.effective_value}"],
            ),
            contributing_factors=["部署时未覆盖不安全默认配置"],
            causal_chain=[f"配置来源 {config.source_file or 'unknown'}", f"生效值 {config.effective_value}"],
            affected_code=[],
            evidence=evidence,
            alternative_hypotheses=[],
            confidence_score=round(0.8 + impact.confidence_score * 0.2, 2),
            unknowns=["confirmed_impact_scope"] if impact.needs_human_review else [],
            needs_human_review=impact.needs_human_review,
            recommended_fix_constraints=[f"将 {config.key} 调整为安全值 {config.secure_value or '由安全基线指定'}", "验证所有环境的配置覆盖关系"],
        )

    @staticmethod
    def _summary(finding, code, missing_control):
        if code.source and code.sink:
            return f"{code.source.symbol} 的不可信数据未经 {missing_control or '充分安全控制'} 到达 {code.sink.symbol}"
        return f"尚无足够证据确认 {finding.vulnerability_type} 的完整根因链"

    @staticmethod
    def _security_invariant(finding, missing_control):
        if missing_control == "parameterized_query":
            return "任何最终进入 SQL 执行 API 的不可信输入，都必须作为绑定参数传入，不得参与 SQL 语句字符串拼接。"
        if missing_control == "check_alias_validation":
            return (
                "任何最终进入 SQL 列别名（AS alias）的字符串，都必须先通过别名安全校验；"
                "别名中不得包含空白、引号、分号或 SQL 注释标记。"
            )
        return f"{finding.vulnerability_type} 的触发输入必须经过对应安全控制后才能进入危险操作。"

    @staticmethod
    def _broken_mechanism(code):
        mechanism = []
        if code.source:
            mechanism.append(f"入口：{code.source.symbol} 接收或保留不可信输入。")
        for step in code.propagation:
            mechanism.append(f"传播：{step.symbol} 发生 {step.operation}。")
        if code.failed_controls:
            for control in code.failed_controls:
                mechanism.append(f"缺失/失效安检：{control.control}，原因：{control.reason}。")
        elif not code.guards:
            mechanism.append("缺失安检：数据流中未识别到有效安全守卫。")
        if code.sink:
            mechanism.append(f"危险汇点：数据最终进入 {code.sink.symbol}。")
        for condition in code.trigger_conditions:
            mechanism.append(f"触发条件：{condition}。")
        return mechanism

    @staticmethod
    def _exploitability_note(missing_control):
        if missing_control == "parameterized_query":
            return "攻击者可通过构造 SQL 片段改变查询结构；修复应确保 payload 只作为参数值处理。"
        if missing_control == "check_alias_validation":
            return "即使 SQL 编译器对别名做 quote_name() 包裹，分号、引号或注释标记仍可能破坏 SQL 语义边界。"
        return None

    @staticmethod
    def _affected_code(finding, code):
        values = []
        for location in finding.locations:
            lines = [line for line in [location.line] if line is not None]
            values.append(AffectedCode(location.file, location.function, lines, "primary_cause"))
        return values

    @staticmethod
    def _contributing_factors(code):
        factors = []
        if not code.guards:
            factors.append("调用路径中未识别到有效安全控制")
        if not code.failed_controls:
            factors.append("缺少针对该漏洞的安全回归证据")
        return factors

    @staticmethod
    def _alternatives(code):
        if not code.guards:
            return []
        return [AlternativeHypothesis(
            hypothesis="现有安全控制已经阻断漏洞路径",
            result="rejected" if code.failed_controls else "unresolved",
            reason="检测到控制但存在失效证据" if code.failed_controls else "尚未取得控制有效性证据",
        )]

    @staticmethod
    def _score(confirmed_chain, failed_control, impact_score, unknown_count):
        score = 0.2 + (0.45 if confirmed_chain else 0) + (0.1 if failed_control else 0) + 0.25 * impact_score
        score -= min(0.3, unknown_count * 0.05)
        return round(max(0.0, min(1.0, score)), 2)

    # ── LLM 推理方法 ──────────────────────────────────────────────────

    @staticmethod
    def _build_root_cause_prompt(finding, impact, code) -> str:
        locs = [f"{loc.file}:{loc.line}" for loc in finding.locations if loc.line]
        return f"""分析以下漏洞的根因：

漏洞信息：
- ID: {finding.finding_id}
- 类型: {finding.vulnerability_type}
- 严重性: {finding.severity.value}
- 文件: {', '.join(locs) if locs else 'unknown'}
- 函数: {finding.locations[0].function if finding.locations and finding.locations[0].function else 'unknown'}
- 证据: {'; '.join(finding.evidence) if finding.evidence else '无'}
- 建议: {finding.recommendation or '未提供'}

影响面：
- 服务: {impact.affected_services}
- 入口点: {[(e.route, e.method) for e in impact.entry_points]}
- 调用路径: {impact.call_paths}

代码证据：
- Source: {code.source.symbol + ' @ ' + code.source.file if code.source else 'unknown'}
- Sink: {code.sink.symbol + ' @ ' + code.sink.file if code.sink else 'unknown'}
- 传播步骤: {[(s.symbol, s.operation) for s in code.propagation] if code.propagation else 'unknown'}
- 已有守卫: {code.guards or 'none'}
- 失效控制: {[(c.control, c.reason) for c in code.failed_controls] if code.failed_controls else 'none'}
- 触发条件: {code.trigger_conditions or 'unknown'}
- 语言: {code.language or 'unknown'}
- 框架: {code.framework or 'unknown'}

请推理完整的 source-to-sink 数据流，识别缺失的安全控制，给出安全不变量和修复约束。"""

    @staticmethod
    def _dict_to_root_cause(finding, raw: dict) -> RootCauseAssessment:
        source_raw = raw.get("source", {}) or {}
        sink_raw = raw.get("sink", {}) or {}
        evidence = [
            Evidence("llm-root-cause", "llm_reasoning", "LLM 推理的根因分析",
                     raw.get("reasoning", ""), Confidence.MEDIUM)
        ]
        return RootCauseAssessment(
            finding_id=finding.finding_id,
            status=AssessmentStatus(raw.get("status", "probable")),
            root_cause_category=RootCauseCategory(raw.get("root_cause_category", "unknown")),
            root_cause=RootCause(
                summary=raw.get("summary", ""),
                source=CodePoint(source_raw.get("symbol", ""), source_raw.get("file"), source_raw.get("line")) if source_raw else None,
                propagation=[PropagationStep(p["symbol"], p["operation"]) for p in raw.get("propagation", [])],
                sink=CodePoint(sink_raw.get("symbol", ""), sink_raw.get("file"), sink_raw.get("line")) if sink_raw else None,
                missing_control=raw.get("missing_control"),
                failed_existing_controls=[
                    FailedControl(fc["control"], fc["reason"]) for fc in raw.get("failed_existing_controls", [])
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

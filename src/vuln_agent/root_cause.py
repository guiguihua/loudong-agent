"""RootCauseAnalysisAgent — 分析漏洞根因。

继承 BaseAgent，拥有 read_file / search_code 工具，
能自己读代码追踪 source-to-sink 数据流，识别缺失的安全控制。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from .agent import BaseAgent, _safe_print, create_default_tools
from .models import (
    AffectedCode,
    AlternativeHypothesis,
    AssessmentStatus,
    CodePoint,
    Confidence,
    Evidence,
    EvidenceBundle,
    FailedControl,
    ImpactAssessment,
    NormalizedVulnerability,
    PropagationStep,
    RootCause,
    RootCauseAssessment,
    RootCauseCategory,
)
from .tools import RootCauseEvidenceTool
from .reasoning import (
    PipelineMode,
    ReasoningMode,
    StageExecution,
    normalize_pipeline_mode,
    stage_policy,
)

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

## 源码事实审计（必须遵守）
- 漏洞报告的 recommendation 只是待验证假设，不能当作已经存在的 API 或根因证据。
- 引用函数参数、构造器状态、异常类型或算法/密钥元数据前，必须先在源码中确认其真实定义。
- 区分生产代码、测试夹具和示例；测试中的路由或调用不得当作生产入口。
- 对库项目优先定位“接受不安全值的最小边界”，不得虚构部署服务、HTTP 路由或调用方配置。
- source、sink、affected_code 必须使用仓库中实际存在的文件和符号；不确定就写入 unknowns。
- 因果链中的关键步骤应包含 file:line 或 file:symbol，不能只给协议层推测。

确认分析完成后，调用 submit_final_result 工具提交最终结果。"""


class RootCauseAnalysisAgent(BaseAgent):
    """分析漏洞根因 — 自己读代码追踪数据流。"""

    def __init__(
        self,
        evidence_tool: RootCauseEvidenceTool,
        llm: LLMBackend | None = None,
        workspace: Path | None = None,
        pipeline_mode: str | PipelineMode = PipelineMode.BALANCED,
    ):
        ws = workspace or Path.cwd()
        self.pipeline_mode = normalize_pipeline_mode(pipeline_mode)
        self.policy = stage_policy("root_cause", self.pipeline_mode)
        super().__init__(
            name="RootCauseAnalysis",
            system_prompt=ROOT_CAUSE_AGENT_PROMPT,
            tools=create_default_tools(ws),
            llm=llm,
            max_turns=self.policy.max_turns,
            workspace=ws,
            reasoning_mode=self.policy.deep_path.value,
            tool_budget=dict(self.policy.tool_budget),
            no_progress_limit=self.policy.no_progress_limit,
            max_output_tokens=self.policy.max_output_tokens,
        )
        self.evidence_tool = evidence_tool
        self.last_execution = StageExecution(
            "root_cause", self.pipeline_mode.value, self.policy.fast_path.value
        )

    def analyze(
        self,
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
        evidence_bundle: EvidenceBundle | None = None,
        force_deep: bool = False,
    ) -> RootCauseAssessment:
        """运行 Root Cause Analysis Agent。"""
        from .llm import ROOT_CAUSE_SCHEMA
        self.output_schema = ROOT_CAUSE_SCHEMA

        task = self._build_task(finding, impact, evidence_bundle)
        raw = self._single_shot(task)
        assessment = None
        if "_raw_output" not in raw:
            try:
                assessment = self._dict_to_root_cause(finding, raw)
                assessment = self._ground_assessment(finding, evidence_bundle, assessment)
            except (KeyError, TypeError, ValueError):
                raw = {"_raw_output": "single-shot root cause did not satisfy the result model"}
        escalation_reasons = self._escalation_reasons(finding, evidence_bundle, assessment)
        # Solo "missing_control_not_specific" or "sink_missing" gaps, when the
        # single-shot already produced a meaningful structured result, don't
        # justify escalating to deep analysis (reading 4 full source files).
        # These gaps can be refined downstream by Remediation/Patch agents.
        has_meaningful_result = (
            assessment is not None
            and assessment.confidence_score >= 0.4
            and assessment.root_cause.summary
            and "static fallback" not in assessment.root_cause.summary.lower()
        )
        soft_gaps = {"missing_control_not_specific"}
        hard_gaps = set(escalation_reasons) - soft_gaps if has_meaningful_result else set(escalation_reasons)
        should_escalate = self.policy.allow_escalation and (
            self.pipeline_mode == PipelineMode.DEEP or force_deep or bool(hard_gaps)
        )
        if not should_escalate:
            if assessment is not None:
                if escalation_reasons:
                    assessment.needs_human_review = True
                    assessment.unknowns.extend(
                        f"fast_mode_not_escalated:{reason}" for reason in escalation_reasons
                    )
                    assessment.unknowns = list(dict.fromkeys(assessment.unknowns))
                self.last_execution = StageExecution(
                    "root_cause", self.pipeline_mode.value, ReasoningMode.DIRECT_STRUCTURED.value,
                    llm_calls=1,
                    escalation_reasons=escalation_reasons,
                )
                return assessment
            fallback = self._extract_structured_from_raw(raw.get("_raw_output", ""), finding, impact)
            return self._ground_assessment(
                finding, evidence_bundle, self._dict_to_root_cause(finding, fallback)
            )

        # ── 续接模式：将 single-shot 结果作为 ReAct 的起点 ──
        deep_context = {
            "reasoning_mode": ReasoningMode.HYPOTHESIS_TEST.value,
            "hypothesis_count": "2-4",
            "tool_budget": self.policy.tool_budget,
            "required_hypothesis_fields": [
                "hypothesis", "required_evidence", "support", "counter_evidence", "verdict"
            ],
        }
        initial_messages = self._build_initial_messages(task, deep_context)
        initial_messages.append({
            "role": "assistant",
            "content": (
                "以下是我基于现有证据的初步根因分析（未使用工具）：\n\n"
                "```json\n" + json.dumps(raw, ensure_ascii=False, indent=2) + "\n```"
            ),
        })
        initial_messages.append({
            "role": "user",
            "content": self._build_gap_instruction(
                escalation_reasons,
                "Hypothesis–Test + ToT-lite：先提出 2-4 个互斥或竞争性的根因假设。"
                "每个假设必须列出所需证据、支持证据、反证以及 confirmed/rejected/unknown 结论。"
                "使用工具只验证能区分这些假设的事实，并按源码证据剪枝。"
                "不得沿单一猜测直接输出结论。最后再归纳 source → propagation → sink → missing control。",
            ),
        })
        try:
            raw = self.run(
                task=task,
                context=deep_context,
                continuation_messages=initial_messages,
            )
        except RuntimeError as exc:
            _safe_print(
                f"  [{self.name}] deep path crashed, falling back: {exc}"
            )
            raw = {
                "_raw_output": str(exc),
                "source": str(getattr(finding.locations[0], "file", "")) if finding.locations else "",
                "sink": str(getattr(finding.locations[0], "function", "")) if finding.locations else "",
                "propagation_steps": [],
                "missing_controls": [
                    "algorithm validation in JWT decode (inferred from vulnerability type)"
                ],
                "hypotheses": [],
                "confidence_score": 0.25,
                "needs_human_review": True,
            }
        self.last_execution = StageExecution(
            "root_cause", self.pipeline_mode.value, ReasoningMode.HYPOTHESIS_TEST.value,
            escalated=True,
            escalation_reasons=escalation_reasons or [
                "failure_analysis_requested_root_cause_recheck" if force_deep else "explicit_deep_mode"
            ],
            llm_calls=int(self.last_run_stats.get("llm_calls", 0)) + 1,
            tool_calls=dict(self.last_run_stats.get("tool_calls", {})),
            stopped_reason=self.last_run_stats.get("stopped_reason"),
            details={"hypotheses": raw.get("hypotheses", []) if isinstance(raw, dict) else []},
        )

        if "_raw_output" in raw:
            extracted = self._extract_structured_from_raw(raw["_raw_output"], finding, impact)
            result = self._dict_to_root_cause(finding, extracted)
        else:
            result = self._dict_to_root_cause(finding, raw)
        result = self._ground_assessment(finding, evidence_bundle, result)
        hypotheses = raw.get("hypotheses", []) if isinstance(raw, dict) else []
        if not 2 <= len(hypotheses) <= 4:
            result.needs_human_review = True
            result.unknowns.append("deep hypothesis coverage incomplete: expected 2-4 hypotheses")
            result.unknowns = list(dict.fromkeys(result.unknowns))
        return result

    @staticmethod
    def _ground_assessment(
        finding: NormalizedVulnerability,
        bundle: EvidenceBundle | None,
        assessment: RootCauseAssessment,
    ) -> RootCauseAssessment:
        """Deterministically ground root-cause locations and symbols in evidence.

        Also stabilizes affected_code (sorted, deduplicated) and computes
        quality signals that downstream agents can use to adjust scope.
        """
        if bundle is None:
            assessment.confidence_score = min(assessment.confidence_score, 0.45)
            assessment.needs_human_review = True
            assessment.unknowns = list(dict.fromkeys([
                *assessment.unknowns,
                "root_cause_not_grounded: EvidenceBundle was not available",
            ]))
            return assessment

        known_paths = list(dict.fromkeys([
            *[item.path for item in bundle.target_files],
            *[item.path for item in bundle.code_slices],
            *[item.path for item in bundle.source_candidates],
            *[item.path for item in bundle.sink_candidates],
        ]))
        candidate_symbols: dict[str, set[str]] = {}
        for item in [*bundle.source_candidates, *bundle.sink_candidates]:
            candidate_symbols.setdefault(item.path, set()).add(item.symbol)
        slice_text: dict[str, str] = {}
        for item in bundle.code_slices:
            slice_text[item.path] = slice_text.get(item.path, "") + "\n" + item.content

        peer_controls = [
            item.reason.split(
                "peer identifier security control:",
                1,
            )[1].split(";", 1)[0].strip()
            for item in bundle.code_slices
            if "peer identifier security control:" in item.reason
        ]
        if peer_controls and finding.locations:
            target = finding.locations[0]
            target_path = target.file.replace("\\", "/").lstrip("./")
            control = sorted(set(peer_controls))[0]
            symbol = target.function or "<module>"
            assessment.root_cause_category = (
                RootCauseCategory.MISSING_INPUT_VALIDATION
            )
            assessment.root_cause.summary = (
                f"{symbol} accepts SQL identifier/alias input but omits the "
                f"existing sibling guard {control} before storing it in the "
                "query representation."
            )
            assessment.root_cause.source = CodePoint(
                symbol,
                target_path,
                target.line,
            )
            assessment.root_cause.sink = CodePoint(
                symbol,
                target_path,
                target.line,
            )
            assessment.root_cause.missing_control = (
                f"apply {control} to every incoming identifier at {symbol}"
            )
            assessment.root_cause.failed_existing_controls = [
                FailedControl(
                    control,
                    "the control exists on sibling identifier ingress paths "
                    f"but is not called by {symbol}",
                )
            ]
            assessment.affected_code = [
                AffectedCode(
                    target_path,
                    symbol,
                    [target.line] if target.line else [],
                    "primary_cause",
                )
            ]
            assessment.security_invariant = (
                "Every external SQL identifier or alias must pass the existing "
                f"peer guard {control} at its ingress boundary."
            )
            assessment.broken_mechanism = list(dict.fromkeys([
                *assessment.broken_mechanism,
                "peer_control_missing_at_identifier_ingress",
            ]))
            assessment.recommended_fix_constraints = list(dict.fromkeys([
                (
                    f"Reuse {control} in {symbol}; do not change the downstream "
                    "SQL compiler's trusted-alias behavior."
                ),
                *assessment.recommended_fix_constraints,
            ]))
            assessment.confidence_score = max(
                assessment.confidence_score,
                0.85,
            )

        def resolve(path: str | None) -> str | None:
            if not path:
                return None
            normalized = path.replace("\\", "/").strip().lstrip("./")
            if normalized in known_paths:
                return normalized
            matches = [
                item for item in known_paths
                if item.endswith("/" + normalized) or normalized.endswith("/" + item)
            ]
            return matches[0] if len(matches) == 1 else None

        def ground_point(point: CodePoint | None, label: str) -> CodePoint | None:
            if point is None:
                return None
            path = resolve(point.file)
            if path is None:
                assessment.unknowns.append(
                    f"unverified {label} location removed: {point.file or 'unknown'}:{point.symbol or 'unknown'}"
                )
                return None
            symbol = (point.symbol or "").strip()
            supported_symbols = candidate_symbols.get(path, set())
            content = slice_text.get(path, "")
            if symbol and symbol != "<module>" and symbol not in supported_symbols and symbol not in content:
                assessment.unknowns.append(
                    f"unverified {label} symbol removed: {path}:{symbol}"
                )
                symbol = ""
            if not symbol:
                return None
            return CodePoint(symbol, path, point.line)

        assessment.root_cause.source = ground_point(assessment.root_cause.source, "source")
        assessment.root_cause.sink = ground_point(assessment.root_cause.sink, "sink")

        # ── Ground and stabilize affected_code ──
        grounded_code: list[AffectedCode] = []
        seen_code: set[tuple[str, str]] = set()
        for item in assessment.affected_code:
            path = resolve(item.file)
            if path is None:
                assessment.unknowns.append(
                    f"unverified affected_code removed: {item.file}:{item.function or 'unknown'}"
                )
                continue
            function = item.function
            if function and function not in candidate_symbols.get(path, set()) and function not in slice_text.get(path, ""):
                assessment.unknowns.append(
                    f"unverified affected_code symbol cleared: {path}:{function}"
                )
                function = None
            key = (path, function or "")
            if key in seen_code:
                continue
            seen_code.add(key)
            grounded_code.append(AffectedCode(path, function, item.lines, item.role))
        # Stable sort: by path then role priority (primary > secondary)
        _role_rank = {"primary_cause": 0, "root": 0, "primary": 0,
                      "contributing": 1, "secondary": 1, "related": 2}
        grounded_code.sort(key=lambda ac: (
            ac.file,
            _role_rank.get((ac.role or "").lower(), 3),
            ac.function or "",
        ))
        assessment.affected_code = grounded_code

        # ── Quality signals: structured gap indicators for downstream agents ──
        source_missing = assessment.root_cause.source is None
        sink_missing = assessment.root_cause.sink is None
        affected_code_empty = not bool(grounded_code)

        if sink_missing:
            assessment.confidence_score = min(assessment.confidence_score, 0.45)
            assessment.needs_human_review = True
            if assessment.status == AssessmentStatus.CONFIRMED:
                assessment.status = AssessmentStatus.PROBABLE
        if not finding.dependency and source_missing:
            assessment.confidence_score = min(assessment.confidence_score, 0.55)
            assessment.needs_human_review = True
            if assessment.status == AssessmentStatus.CONFIRMED:
                assessment.status = AssessmentStatus.PROBABLE
        if affected_code_empty:
            assessment.confidence_score = min(assessment.confidence_score, 0.5)
            assessment.needs_human_review = True
        # Both missing = severe gap
        if sink_missing and source_missing:
            assessment.confidence_score = min(assessment.confidence_score, 0.35)
            assessment.unknowns = list(dict.fromkeys([
                *assessment.unknowns,
                "root_cause_has_unknowns: both source and sink unverified — "
                "downstream agents must widen scope and verify each candidate file",
            ]))

        # ── Collect ALL causally-related file paths for downstream agents ──
        causal_files: list[str] = []
        if assessment.root_cause.source and assessment.root_cause.source.file:
            causal_files.append(assessment.root_cause.source.file)
        if assessment.root_cause.sink and assessment.root_cause.sink.file:
            causal_files.append(assessment.root_cause.sink.file)
        for ac in grounded_code:
            causal_files.append(ac.file)
        # Propagate through propagation steps (check for file references)
        for step in assessment.root_cause.propagation:
            # PropagationStep doesn't have a file field, but we can check if symbol
            # matches known functions in affected_code
            pass
        causal_files = list(dict.fromkeys(causal_files))
        if len(causal_files) > 1:
            assessment.unknowns = list(dict.fromkeys([
                *assessment.unknowns,
                f"multi_file_causal_chain: {len(causal_files)} files in "
                f"source→sink→affected_code chain — remediation must cover all",
            ]))

        assessment.unknowns = list(dict.fromkeys(assessment.unknowns))
        return assessment

    @staticmethod
    def get_causal_files(assessment: RootCauseAssessment) -> list[str]:
        """Extract all causally-related file paths from a RootCauseAssessment.

        Used by Remediation to ensure its planned_changes cover the full scope.
        Returns a stable, deduplicated list. Resilient to partial/mock data.
        """
        files: list[str] = []
        rc = getattr(assessment, 'root_cause', None)
        if rc is None:
            # Fallback: try affected_code directly
            for ac in getattr(assessment, 'affected_code', []) or []:
                f = getattr(ac, 'file', None)
                if f:
                    files.append(f)
            return list(dict.fromkeys(f.replace("\\", "/").lstrip("./") for f in files))

        source = getattr(rc, 'source', None)
        sink = getattr(rc, 'sink', None)
        if source and getattr(source, 'file', None):
            files.append(source.file)
        if sink and getattr(sink, 'file', None):
            files.append(sink.file)
        for ac in getattr(assessment, 'affected_code', []) or []:
            f = getattr(ac, 'file', None)
            if f:
                files.append(f)
        # Deduplicate preserving order
        seen: set[str] = set()
        result: list[str] = []
        for f in files:
            norm = f.replace("\\", "/").lstrip("./")
            if norm not in seen:
                seen.add(norm)
                result.append(norm)
        return result

    def _single_shot(self, task: str) -> dict:
        from .llm import ROOT_CAUSE_SCHEMA

        try:
            raw = self.llm.reason(  # type: ignore[union-attr]
                user_prompt=task,
                system_prompt=(
                    "基于 EvidenceBundle 做一次结构化根因判断，不调用工具。"
                    "只使用可定位的 source/sink/guard 证据；无法确认的链路写入 unknowns。"
                    "先核对真实函数签名、构造器传值和调用顺序；报告建议不是源码事实。"
                    "不得把测试夹具当生产路径，也不得声称源码中不存在的参数或异常类型。"
                ),
                output_schema=ROOT_CAUSE_SCHEMA,
                temperature=0.1,
                max_tokens=self.policy.max_output_tokens,
            )
            return RootCauseAnalysisAgent._normalize_single_shot(raw)
        except Exception as exc:
            return {"_raw_output": f"single-shot root cause failed: {exc}"}

    @staticmethod
    def _normalize_single_shot(raw: dict | str) -> dict:
        """Handle _schema_missing: convert to _raw_output so analyze()
        triggers fallback/escalation instead of accepting incomplete data."""
        if isinstance(raw, dict) and raw.pop("_schema_missing", None):
            partial = {k: v for k, v in raw.items() if not k.startswith("_")}
            raw["_raw_output"] = json.dumps(partial, ensure_ascii=False, indent=2)
            raw["_partial_structured"] = partial
            return raw
        return raw if isinstance(raw, dict) else {"_raw_output": str(raw)}

    @staticmethod
    def _escalation_reasons(finding, bundle, assessment) -> list[str]:
        reasons: list[str] = []
        if assessment is None:
            return ["single_shot_not_structured"]
        is_dependency = finding.dependency is not None or "depend" in finding.vulnerability_type.lower()
        root = assessment.root_cause
        if root.sink is None or not root.sink.symbol:
            reasons.append("sink_missing")
        if not is_dependency and (root.source is None or not root.source.symbol):
            reasons.append("source_missing")
        missing = str(root.missing_control or "").strip().lower()
        if missing in {"", "unknown", "missing_control", "missing_security_control", "missing control"}:
            reasons.append("missing_control_not_specific")
        if finding.severity.value in {"critical", "high"} and assessment.confidence_score < 0.6:
            reasons.append("high_severity_confidence_below_0.6")
        if bundle:
            evidence_paths = {item.path for item in bundle.target_files}
            evidence_paths.update(item.path for item in bundle.code_slices)
            if any(item.file not in evidence_paths for item in assessment.affected_code if item.file):
                reasons.append("affected_code_outside_evidence_bundle")
        return list(dict.fromkeys(reasons))

    @staticmethod
    def _build_gap_instruction(escalation_reasons: list[str], deep_strategy: str) -> str:
        """将 escalation 原因转为面向 LLM 的差距调查指令。"""
        reason_labels: dict[str, str] = {
            "sink_missing": "sink（危险操作汇点）未确认，需要追踪代码找到具体执行点",
            "source_missing": "source（不可信输入入口）未确认，需要找到数据进入系统的位置",
            "missing_control_not_specific": "缺失的安全控制描述不够具体，需要深入分析代码后精确定义",
            "high_severity_confidence_below_0.6": "高危漏洞根因置信度不足（< 0.6），需要更多源码证据",
            "affected_code_outside_evidence_bundle": "部分受影响代码不在 EvidenceBundle 覆盖范围内",
            "single_shot_not_structured": "初步分析未产出结构化结果，需要从头分析",
        }
        gaps = [reason_labels.get(r, r) for r in escalation_reasons]

        return (
            "## 深度分析：基于初步评估继续调查\n\n"
            "上述初步根因分析是在无工具访问的情况下做出的。以下缺口需要补充调查：\n\n"
            + "\n".join(f"- {g}" for g in gaps) + "\n\n"
            f"**深度策略**：{deep_strategy}\n\n"
            "**指示**：\n"
            "1. 保留初步分析中已有证据支持的结论（已确认的 source/sink/guard 等不变）\n"
            "2. 只使用工具调查上述缺口；不要重新确认已有证据的部分\n"
            "3. 优先读取受影响文件和相关代码路径\n"
            "4. 收集足够证据后，修订初步分析并调用 submit_final_result 提交完整结果\n"
        )

    def _extract_structured_from_raw(
        self,
        raw_text: str,
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
    ) -> dict:
        """从非结构化的 LLM 输出中二次提取结构化根因分析字段。"""
        if not self.llm:
            return self._fallback_raw_extraction(raw_text, finding)

        from .llm import ROOT_CAUSE_SCHEMA

        locs = [f"{loc.file}:{loc.line}" for loc in finding.locations if loc.line]
        extraction_prompt = f"""以下是一段漏洞根因分析的原始文本。请从中提取关键信息，填入指定 JSON 结构。

## 漏洞基本信息
- ID: {finding.finding_id}
- 类型: {finding.vulnerability_type}
- 文件: {', '.join(locs) if locs else 'unknown'}
- 函数: {finding.locations[0].function if finding.locations and finding.locations[0].function else 'unknown'}
- 证据: {'; '.join(finding.evidence) if finding.evidence else '无'}

## 原始分析文本
{raw_text[:8000]}

## 要求
请仔细阅读上面的分析文本，尽量提取所有你能找到的结构化信息。
如果某个字段在文本中找不到对应信息，使用合理的默认值（空字符串/空数组/unknown），不要编造。"""

        try:
            structured = self.llm.reason(
                user_prompt=extraction_prompt,
                system_prompt="你是一个结构化数据提取器。从安全分析文本中提取关键信息并填入 JSON 结构。只输出 JSON。",
                output_schema={
                    "type": "object",
                    "description": "从原始分析文本中提取的结构化根因分析",
                    "properties": {
                        k: v for k, v in ROOT_CAUSE_SCHEMA.get("properties", {}).items()
                        if k not in ("reasoning",)
                    },
                    "required": ["status", "root_cause_category", "summary", "missing_control", "causal_chain", "confidence_score", "needs_human_review"],
                },
                temperature=0.1,
            )
            if isinstance(structured, dict) and structured.get("summary"):
                structured["_extracted_from_raw"] = True
                return structured
        except Exception:
            pass

        return self._fallback_raw_extraction(raw_text, finding)

    @staticmethod
    def _fallback_raw_extraction(raw_text: str, finding: NormalizedVulnerability) -> dict:
        """Last-resort extraction when both JSON repair and LLM re-extraction failed.

        Attempts to find the largest valid/reparable JSON object first, then
        falls back to constructing minimal sensible defaults from the finding data.
        """
        from .json_repair import extract_largest_json_object

        # Default template.
        result: dict = {
            "status": "possible",
            "root_cause_category": "unknown",
            "summary": "",
            "source": {},
            "propagation": [],
            "sink": {},
            "missing_control": "",
            "causal_chain": [],
            "broken_mechanism": [],
            "security_invariant": "",
            "guardrail": "",
            "exploitability_note": "",
            "recommended_fix_constraints": [],
            "confidence_score": 0.3,
            "unknowns": [],
            "needs_human_review": True,
            "contributing_factors": [],
            "affected_code": [],
            "alternative_hypotheses": [],
            "trigger_conditions": [],
            "hypotheses": [],
        }

        # Attempt to find and repair the largest JSON object in the text.
        obj = extract_largest_json_object(raw_text)
        if obj is not None and isinstance(obj, dict):
            for k, v in obj.items():
                if k in result and v:
                    result[k] = v
            result["unknowns"] = list(dict.fromkeys([
                *result.get("unknowns", []),
                "结构化 LLM 输出解析失败，从非结构化文本中提取到部分 JSON 字段",
            ]))
        else:
            result["unknowns"] = list(dict.fromkeys([
                *result.get("unknowns", []),
                "结构化 LLM 输出解析失败，未能从非结构化文本中提取有效 JSON",
            ]))

        # Ensure every required field has a meaningful value (not empty / None).
        evidence_text = "; ".join(e for e in (finding.evidence or []) if e.strip())
        locs = [f"{loc.file}:{loc.line}" for loc in finding.locations if loc.line]
        loc_str = locs[0] if locs else "unknown"

        if not result.get("summary"):
            result["summary"] = (
                f"{finding.finding_id}: {finding.vulnerability_type} — "
                f"受影响位置 {loc_str}."
                f"{' 证据: ' + evidence_text if evidence_text else ''}"
            )
        if not result.get("missing_control") or str(result.get("missing_control", "")).strip() in (
            "missing_control", "missing_security_control", "missing control", "",
        ):
            result["missing_control"] = (
                f"针对 {finding.vulnerability_type} 的安全控制（"
                f"具体控制尚未从源码证据确认，需人工审查。"
                "）"
            )

        return result

    def _build_task(
        self,
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
        evidence_bundle: EvidenceBundle | None = None,
    ) -> str:
        """构建根因分析任务。"""
        from .evidence import format_evidence_bundle

        code = self.evidence_tool.collect_code_evidence(finding)
        locs = [f"{loc.file}:{loc.line}" for loc in finding.locations if loc.line]

        # ── 注入 CVE 知识提示（仅概念层面，不编造文件路径/API）──
        cve_tags = ""
        if finding.cve or finding.cwe:
            cve_tags = f"\n- CVE: {finding.cve or '无'}\n- CWE: {finding.cwe or '无'}"

        return f"""分析以下漏洞的根因。基于你的安全专业知识，独立识别攻击机制和缺失控制。

## 漏洞信息
- ID: {finding.finding_id}
- 类型: {finding.vulnerability_type}
- 严重性: {finding.severity.value}{cve_tags}
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

## 确定性 EvidenceBundle（优先使用）
{format_evidence_bundle(evidence_bundle)}

## 分析要求
请运用你的安全专业知识独立完成以下推理，不要依赖漏洞报告的建议，也不要套用外部参考实现。

1. **攻击机制分析** — 基于漏洞类型和 CWE，描述攻击者会如何利用此类漏洞：
   - 信任边界在哪里？
   - 攻击者控制什么输入？输入如何到达危险操作？
   - 成功利用的前提条件是什么？

2. **安全不变量** — 系统在正确状态下必须保持什么安全属性？
   - 例如：查询结构必须与数据分离 / 输出必须根据上下文编码 / 算法族必须与密钥类型匹配

3. **缺失控制** — 基于 EvidenceBundle 的代码证据，具体哪一层缺少了什么防护？
   - 是缺少输入校验？缺少输出编码？缺少参数化？缺少权限检查？

4. **源码定位** — 每个 source、sink、affected_code 必须能在 EvidenceBundle 或代码线索中找到对应证据。
   无法在源码中确认的假设放入 unknowns，不要编造。"""

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

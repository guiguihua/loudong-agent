"""ImpactAnalysisAgent — 分析漏洞影响面。

继承 BaseAgent，拥有 read_file / search_code / list_dir 工具，
能自己探索代码库来确定受影响服务、API 入口和攻击面。
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING

from .agent import BaseAgent, create_default_tools
from .models import (
    ApiEntryPoint,
    AssessmentStatus,
    Confidence,
    Evidence,
    EvidenceBundle,
    ImpactAssessment,
    NormalizedVulnerability,
)
from .tools import AssetInventoryTool, CodeContextTool, RuntimeEvidenceTool
from .reasoning import (
    PipelineMode,
    ReasoningMode,
    StageExecution,
    normalize_pipeline_mode,
    stage_policy,
)

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

## 证据纪律（必须遵守）
- 只有在源码、配置、资产清单或运行时证据中直接找到的服务、入口和调用路径，才能写入确认项。
- 不得把框架常见入口、CVE 可能影响的下游集成或猜测的公网路由写成已确认影响面。
- 对仅由漏洞类型/CVE 描述推导的范围，放入 unknowns，并明确写成“潜在影响，未在当前仓库确认”。
- 每条调用路径必须包含可定位的文件、符号或已提供的运行时路径；否则不要输出该路径。
- internet_exposed、authentication 没有配置或运行时证据时必须分别使用 null、unknown。
- confidence_score 必须与证据匹配；只有代码路径、资产和运行时证据同时存在时才可使用 confirmed。

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
        pipeline_mode: str | PipelineMode = PipelineMode.BALANCED,
    ):
        ws = workspace or Path.cwd()
        self.pipeline_mode = normalize_pipeline_mode(pipeline_mode)
        self.policy = stage_policy("impact", self.pipeline_mode)
        super().__init__(
            name="ImpactAnalysis",
            system_prompt=IMPACT_AGENT_PROMPT,
            tools=create_default_tools(ws),
            llm=llm,
            max_turns=self.policy.max_turns,
            workspace=ws,
            reasoning_mode=self.policy.deep_path.value,
            tool_budget=dict(self.policy.tool_budget),
            no_progress_limit=self.policy.no_progress_limit,
            max_output_tokens=self.policy.max_output_tokens,
        )
        self.code_tool = code_tool
        self.asset_tool = asset_tool
        self.runtime_tool = runtime_tool
        self.last_execution = StageExecution(
            "impact", self.pipeline_mode.value, self.policy.fast_path.value
        )

    def analyze(
        self,
        finding: NormalizedVulnerability,
        evidence_bundle: EvidenceBundle | None = None,
    ) -> ImpactAssessment:
        """运行 Impact Analysis Agent。"""
        from .llm import IMPACT_SCHEMA
        self.output_schema = IMPACT_SCHEMA

        task = self._build_task(finding, evidence_bundle)
        raw = self._single_shot(task)
        assessment = self._dict_to_assessment(finding, raw) if "_raw_output" not in raw else None
        if assessment is not None:
            assessment = self._ground_assessment(finding, evidence_bundle, assessment)
        escalation_reasons = self._escalation_reasons(finding, evidence_bundle, assessment)
        should_escalate = self.policy.allow_escalation and (
            self.pipeline_mode == PipelineMode.DEEP or bool(escalation_reasons)
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
                    "impact", self.pipeline_mode.value, ReasoningMode.DIRECT_STRUCTURED.value,
                    llm_calls=1,
                    escalation_reasons=escalation_reasons,
                )
                return assessment
            return self._ground_assessment(
                finding,
                evidence_bundle,
                self._dict_to_assessment(
                    finding, self._extract_impact_from_raw(raw.get("_raw_output", ""), finding)
                ),
            )

        # ── 续接模式：将 single-shot 结果作为 ReAct 的起点 ──
        deep_context = {
            "reasoning_mode": ReasoningMode.BOUNDED_REACT.value,
            "tool_budget": self.policy.tool_budget,
            "stop_conditions": [
                "target located", "entry confirmed or explicitly unknown",
                "path confirmed or evidence gap recorded", "two searches without new evidence",
            ],
        }
        initial_messages = self._build_initial_messages(task, deep_context)
        initial_messages.append({
            "role": "assistant",
            "content": (
                "以下是我基于现有证据的初步影响面评估（未使用工具）：\n\n"
                "```json\n" + json.dumps(raw, ensure_ascii=False, indent=2) + "\n```"
            ),
        })
        initial_messages.append({
            "role": "user",
            "content": self._build_gap_instruction(
                escalation_reasons,
                "Evidence-driven Bounded ReAct：建立待确认问题列表，只搜索尚未被 EvidenceBundle 回答的问题。"
                "每次工具调用后更新影响证据图。停止条件：目标文件已定位；API 入口已确认或明确未知；"
                "至少一条入口到受影响点的路径已确认，或已明确证据不足；所有确认项都有 file:line/symbol。"
                "连续两次搜索没有新证据必须停止。",
            ),
        })
        raw = self.run(
            task=task,
            context=deep_context,
            continuation_messages=initial_messages,
        )
        self.last_execution = StageExecution(
            "impact", self.pipeline_mode.value, ReasoningMode.BOUNDED_REACT.value,
            escalated=True,
            escalation_reasons=escalation_reasons or ["explicit_deep_mode"],
            llm_calls=int(self.last_run_stats.get("llm_calls", 0)) + 1,
            tool_calls=dict(self.last_run_stats.get("tool_calls", {})),
            stopped_reason=self.last_run_stats.get("stopped_reason"),
        )

        if "_raw_output" in raw:
            extracted = self._extract_impact_from_raw(raw["_raw_output"], finding)
            result = self._dict_to_assessment(finding, extracted)
        else:
            result = self._dict_to_assessment(finding, raw)
        return self._ground_assessment(finding, evidence_bundle, result)

    @staticmethod
    def _ground_assessment(
        finding: NormalizedVulnerability,
        bundle: EvidenceBundle | None,
        assessment: ImpactAssessment,
    ) -> ImpactAssessment:
        """Remove production-impact claims that cannot be tied to collected evidence.

        LLM output remains useful for synthesis, but it is not allowed to promote test
        fixtures, CVE background knowledge, or framework conventions into confirmed
        repository impact. Unsupported claims are retained as explicit unknowns so the
        report stays informative without presenting guesses as facts.
        """
        if bundle is None:
            assessment.confidence_score = min(assessment.confidence_score, 0.5)
            assessment.needs_human_review = True
            assessment.unknowns = list(dict.fromkeys([
                *assessment.unknowns,
                "impact_not_grounded: EvidenceBundle was not available",
            ]))
            return assessment

        evidence_entries = {
            (item.method.upper(), item.route): item for item in bundle.entry_points
        }
        evidence_routes = {item.route for item in bundle.entry_points}
        source_text = "\n".join(item.content for item in bundle.code_slices).lower()
        grounded_entries: list[ApiEntryPoint] = []
        removed_claim = False
        for entry in assessment.entry_points:
            method = (entry.method or "ANY").upper()
            supported = (
                (method, entry.route) in evidence_entries
                or ("ANY", entry.route) in evidence_entries
                or entry.route in evidence_routes and method == "ANY"
            )
            if not supported and method in {"CALL", "API", "LIBRARY"}:
                symbol_match = re.findall(r"[A-Za-z_$][\w$]*", entry.route)
                symbol = symbol_match[-1].lower() if symbol_match else ""
                supported = bool(
                    symbol
                    and re.search(
                        rf"\b(?:def|class|function|func|fn)\s+{re.escape(symbol)}\b",
                        source_text,
                    )
                )
            if supported:
                grounded_entries.append(entry)
            else:
                removed_claim = True
                assessment.unknowns.append(
                    f"unverified entry point removed from confirmed impact: {method} {entry.route}"
                )
        assessment.entry_points = grounded_entries

        anchors: set[str] = set()
        for item in bundle.target_files:
            anchors.update({Path(item.path).name.lower(), Path(item.path).stem.lower()})
        for item in [*bundle.source_candidates, *bundle.sink_candidates]:
            if item.symbol and item.symbol != "<module>":
                anchors.add(item.symbol.lower())
            anchors.update({Path(item.path).name.lower(), Path(item.path).stem.lower()})
        grounded_routes = {*evidence_routes, *[entry.route for entry in grounded_entries]}
        anchors.update(route.lower() for route in grounded_routes if route)
        anchors = {item for item in anchors if len(item) >= 3}

        grounded_paths: list[list[str]] = []
        for path in assessment.call_paths:
            rendered = " ".join(str(step) for step in path).lower()
            matched = {anchor for anchor in anchors if anchor in rendered}
            if len(matched) >= 2:
                grounded_paths.append(path)
            else:
                removed_claim = True
                assessment.unknowns.append(
                    "unverified call path removed from confirmed impact: " + " -> ".join(path)
                )
        assessment.call_paths = grounded_paths

        known_services = {
            value.strip().lower()
            for value in (
                bundle.repository_summary.repository,
                finding.repository,
            )
            if value and value.strip()
        }
        if known_services:
            grounded_services: list[str] = []
            for service in assessment.affected_services:
                normalized = service.strip().lower()
                if any(normalized == known or normalized in known or known in normalized for known in known_services):
                    grounded_services.append(service)
                else:
                    removed_claim = True
                    assessment.unknowns.append(
                        f"potential affected service not confirmed by repository evidence: {service}"
                    )
            assessment.affected_services = grounded_services

        if not bundle.target_files and finding.dependency is None:
            assessment.confidence_score = min(assessment.confidence_score, 0.45)
            assessment.needs_human_review = True
        if not assessment.call_paths:
            assessment.confidence_score = min(assessment.confidence_score, 0.6)
            if assessment.status == AssessmentStatus.CONFIRMED:
                assessment.status = AssessmentStatus.PROBABLE
            assessment.needs_human_review = True
        elif removed_claim:
            assessment.confidence_score = min(assessment.confidence_score, 0.75)
            assessment.needs_human_review = True
        assessment.unknowns = list(dict.fromkeys(assessment.unknowns))
        return assessment

    def _single_shot(self, task: str) -> dict:
        from .llm import IMPACT_SCHEMA

        try:
            raw = self.llm.reason(  # type: ignore[union-attr]
                user_prompt=task,
                system_prompt=(
                    "基于给定 Finding 和 EvidenceBundle 做一次结构化影响判断。"
                    "不要调用工具，不要虚构入口或调用路径；证据不足写入 unknowns。"
                ),
                output_schema=IMPACT_SCHEMA,
                temperature=0.1,
                max_tokens=self.policy.max_output_tokens,
            )
            return ImpactAnalysisAgent._normalize_single_shot(raw)
        except Exception as exc:
            return {"_raw_output": f"single-shot impact failed: {exc}"}

    @staticmethod
    def _normalize_single_shot(raw: dict | str) -> dict:
        """Handle _schema_missing: convert to _raw_output so analyze()
        triggers fallback/escalation instead of accepting incomplete data."""
        if isinstance(raw, dict) and raw.pop("_schema_missing", None):
            partial = {k: v for k, v in raw.items() if not k.startswith("_")}
            raw["_raw_output"] = json.dumps(partial, ensure_ascii=False, indent=2)
            # Keep partial data for deep analysis context
            raw["_partial_structured"] = partial
            return raw
        return raw if isinstance(raw, dict) else {"_raw_output": str(raw)}

    @staticmethod
    def _escalation_reasons(finding, bundle, assessment) -> list[str]:
        reasons: list[str] = []
        if assessment is None:
            return ["single_shot_not_structured"]
        if assessment.confidence_score < 0.4:
            reasons.append("confidence_below_0.4")
        if bundle and not bundle.target_files:
            reasons.append("reported_target_not_collected")
        if finding.severity.value in {"critical", "high"} and not assessment.call_paths:
            reasons.append("high_severity_without_confirmed_call_path")
        evidence_routes = {item.route for item in bundle.entry_points} if bundle else set()
        assessed_routes = {item.route for item in assessment.entry_points}
        if evidence_routes and assessed_routes and not assessed_routes.issubset(evidence_routes):
            reasons.append("impact_entry_point_conflicts_with_evidence")
        return list(dict.fromkeys(reasons))

    @staticmethod
    def _build_gap_instruction(escalation_reasons: list[str], deep_strategy: str) -> str:
        """将 escalation 原因转为面向 LLM 的差距调查指令。"""
        reason_labels: dict[str, str] = {
            "confidence_below_0.4": "整体置信度不足（< 0.4），需要更多源码证据支持",
            "reported_target_not_collected": "漏洞报告中的目标文件未在 EvidenceBundle 中收集到",
            "high_severity_without_confirmed_call_path": "高危漏洞缺少确认的调用路径（call_paths 为空）",
            "impact_entry_point_conflicts_with_evidence": "影响面入口点与 EvidenceBundle 中的证据不一致",
            "single_shot_not_structured": "初步评估未产出结构化结果，需要从头分析",
        }
        gaps = [reason_labels.get(r, r) for r in escalation_reasons]

        return (
            "## 深度分析：基于初步评估继续调查\n\n"
            "上述初步评估是在无工具访问的情况下做出的。以下缺口需要补充调查：\n\n"
            + "\n".join(f"- {g}" for g in gaps) + "\n\n"
            f"**深度策略**：{deep_strategy}\n\n"
            "**指示**：\n"
            "1. 保留初步评估中已有证据支持的结论（affected_services、entry_points 等如已确认则不变）\n"
            "2. 只使用工具调查上述缺口；不要重新确认已有证据的字段\n"
            "3. 连续两次搜索无新证据时必须停止\n"
            "4. 收集足够证据后，修订初步评估并调用 submit_final_result 提交完整结果\n"
        )

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
        """Last-resort extraction when both JSON repair and LLM re-extraction failed.

        Attempts to find the largest valid/reparable JSON object first, then
        falls back to constructing minimal sensible defaults from the finding data.
        """
        import re
        from .json_repair import extract_largest_json_object

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

        # Attempt to find and repair the largest JSON object in the text.
        obj = extract_largest_json_object(raw_text)
        if obj is not None and isinstance(obj, dict):
            for k, v in obj.items():
                if k in result and v:
                    result[k] = v

        # Fill gaps with sensible defaults from the finding data.
        locs = [f"{loc.file}:{loc.line}" for loc in finding.locations if loc.line]
        evidence_text = "; ".join(e for e in (finding.evidence or []) if e.strip())

        if not result["affected_services"]:
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

    def _build_task(
        self,
        finding: NormalizedVulnerability,
        evidence_bundle: EvidenceBundle | None = None,
    ) -> str:
        """构建 Agent 任务描述。"""
        from .evidence import format_evidence_bundle

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

## 确定性 EvidenceBundle（优先使用）
{format_evidence_bundle(evidence_bundle)}

## 要求
先复用 EvidenceBundle 中已收集的文件切片、入口和候选点；只有 collection_warnings 明确指出关键证据缺失时，才使用工具补充探索。
只报告有证据支持的确认项。由 CVE 通用知识推导、但未在当前仓库确认的下游场景必须放入 unknowns，不能扩写成已确认服务、入口或调用路径。"""

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

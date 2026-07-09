from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .models import (
    ApiEntryPoint,
    AssessmentStatus,
    Confidence,
    Evidence,
    ImpactAssessment,
    NormalizedVulnerability,
)
from .tools import AssetInventoryTool, CodeContextTool, RuntimeEvidenceTool

if TYPE_CHECKING:
    from .llm import LLMBackend


@dataclass(slots=True)
class ImpactAnalysisAgent:
    code_tool: CodeContextTool
    asset_tool: AssetInventoryTool
    runtime_tool: RuntimeEvidenceTool
    llm: "LLMBackend | None" = None

    def analyze(self, finding: NormalizedVulnerability) -> ImpactAssessment:
        if self.llm:
            return self._llm_analyze(finding)
        return self._deterministic_analyze(finding)

    def _llm_analyze(self, finding: NormalizedVulnerability) -> ImpactAssessment:
        """使用 LLM 推理影响面，不依赖预填的 Tool 上下文。"""
        from .llm import IMPACT_SCHEMA

        code = self.code_tool.collect(finding)
        assets = self.asset_tool.collect(finding)
        runtime = self.runtime_tool.collect(finding)

        prompt = self._build_impact_prompt(finding, code, assets, runtime)
        raw = self.llm.reason(  # type: ignore[union-attr]
            prompt,
            system_prompt="你是一位应用安全工程师。分析漏洞的影响面，推断受影响的服务、攻击入口和调用路径。",
            output_schema=IMPACT_SCHEMA,
        )
        if isinstance(raw, str):
            return self._deterministic_analyze(finding)

        return self._dict_to_assessment(finding, raw)

    def _deterministic_analyze(self, finding: NormalizedVulnerability) -> ImpactAssessment:
        code = self.code_tool.collect(finding)
        assets = self.asset_tool.collect(finding)
        runtime = self.runtime_tool.collect(finding)
        evidence: list[Evidence] = []

        if code.call_paths:
            evidence.append(Evidence("code-call-path", "code_index", "reachable_call_path", code.call_paths, Confidence.HIGH))
        if code.entry_points:
            evidence.append(Evidence("api-entry", "route_index", "triggering_entry_points", [e.route for e in code.entry_points], Confidence.HIGH))
        if assets.deployed_assets:
            evidence.append(Evidence("deployed-assets", "asset_inventory", "deployed_affected_assets", assets.deployed_assets, Confidence.HIGH))
        if runtime.evidence_available:
            evidence.append(Evidence("runtime-observed", "runtime", "runtime_path_observed", runtime.observed_call_paths or runtime.observed_routes, Confidence.HIGH))

        unknowns: list[str] = []
        if not code.services:
            unknowns.append("affected_services")
        if not code.entry_points:
            unknowns.append("triggering_api_paths")
        if code.entry_points and any(e.internet_exposed is None for e in code.entry_points):
            unknowns.append("internet_exposure")
        if code.entry_points and any(e.authentication == "unknown" for e in code.entry_points):
            unknowns.append("authentication_requirement")
        if not assets.deployed_assets:
            unknowns.append("deployed_assets")
        if not runtime.evidence_available:
            unknowns.append("runtime_reachability")

        score = self._confidence_score(code.call_paths, assets.deployed_assets, runtime.evidence_available, unknowns)
        status = self._status(code.call_paths, assets.deployed_assets, runtime.evidence_available)
        regression_targets = list(dict.fromkeys(code.related_tests + self._business_targets(code.call_paths)))
        suggested_tests = self._suggest_tests(finding, code.data_classification, code.entry_points)
        affected_artifacts = list(assets.affected_artifacts)
        if finding.dependency:
            affected_artifacts = list(dict.fromkeys(affected_artifacts + finding.dependency.affected_artifacts))

        critical_unknowns = {"affected_services", "triggering_api_paths", "deployed_assets"}
        needs_review = status in {AssessmentStatus.UNKNOWN, AssessmentStatus.POSSIBLE} or bool(critical_unknowns & set(unknowns))
        return ImpactAssessment(
            finding_id=finding.finding_id,
            status=status,
            affected_services=code.services,
            entry_points=code.entry_points,
            call_paths=code.call_paths,
            affected_assets=assets.deployed_assets,
            affected_artifacts=affected_artifacts,
            data_classification=code.data_classification,
            upstream_dependencies=code.upstream_dependencies,
            downstream_dependencies=code.downstream_dependencies,
            regression_targets=regression_targets,
            suggested_tests=suggested_tests,
            evidence=evidence,
            unknowns=unknowns,
            confidence_score=score,
            needs_human_review=needs_review,
        )

    @staticmethod
    def _status(call_paths: list[list[str]], assets: list[str], runtime_observed: bool) -> AssessmentStatus:
        if call_paths and assets and runtime_observed:
            return AssessmentStatus.CONFIRMED
        if call_paths and assets:
            return AssessmentStatus.PROBABLE
        if call_paths or assets:
            return AssessmentStatus.POSSIBLE
        return AssessmentStatus.UNKNOWN

    @staticmethod
    def _confidence_score(call_paths: list[list[str]], assets: list[str], runtime_observed: bool, unknowns: list[str]) -> float:
        score = 0.15 + (0.35 if call_paths else 0) + (0.25 if assets else 0) + (0.25 if runtime_observed else 0)
        score -= min(0.3, 0.05 * len(unknowns))
        return round(max(0.0, min(1.0, score)), 2)

    @staticmethod
    def _business_targets(call_paths: list[list[str]]) -> list[str]:
        return [path[0] for path in call_paths if path]

    @staticmethod
    def _suggest_tests(finding: NormalizedVulnerability, classifications: list[str], entry_points: list) -> list[str]:
        tests = [f"{finding.vulnerability_type} security regression"]
        if entry_points:
            tests.append("API authorization and input compatibility")
        if classifications:
            tests.append("sensitive data access regression")
        if any("tenant" in item.lower() for item in classifications):
            tests.append("tenant isolation regression")
        return tests

    # ── LLM 推理方法 ──────────────────────────────────────────────────

    @staticmethod
    def _build_impact_prompt(finding, code, assets, runtime) -> str:
        locs = [f"{loc.file}:{loc.line}" for loc in finding.locations if loc.line] if finding.locations else ["unknown"]
        return f"""分析以下漏洞的影响面：

漏洞信息：
- ID: {finding.finding_id}
- 类型: {finding.vulnerability_type}
- 严重性: {finding.severity.value}
- 来源: {finding.scanner}
- 受影响文件: {', '.join(locs)}
- 证据: {'; '.join(finding.evidence) if finding.evidence else '无'}
- 建议: {finding.recommendation or '未提供'}
- 仓库: {finding.repository or 'unknown'}
{f'- 依赖组件: {finding.dependency.component} {finding.dependency.current_version}' if finding.dependency else ''}

已知上下文：
- 服务: {code.services or '未提供（请推断）'}
- 入口点: {[(e.route, e.method) for e in code.entry_points] or '未提供'}
- 调用路径: {code.call_paths or '未提供'}
- 资产: {assets.deployed_assets or '未提供'}
- 运行时路径: {runtime.observed_call_paths or runtime.observed_routes or '未提供'}

请基于以上信息推理影响面评估。你可以根据漏洞类型和常见模式做出合理推断。"""

    @staticmethod
    def _dict_to_assessment(finding, raw: dict) -> ImpactAssessment:
        from .models import Evidence as Ev
        evidence = [
            Ev("llm-impact", "llm_reasoning", "LLM 推理的影响面评估",
               raw.get("reasoning", ""), Confidence.MEDIUM)
        ]
        return ImpactAssessment(
            finding_id=finding.finding_id,
            status=AssessmentStatus(raw.get("status", "unknown")),
            affected_services=raw.get("affected_services", []),
            entry_points=[
                ApiEntryPoint(ep["route"], ep.get("method", "ANY"),
                              ep.get("authentication", "unknown"), ep.get("internet_exposed"))
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


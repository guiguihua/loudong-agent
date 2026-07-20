"""Reasoning strategies and deterministic stage policies."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class PipelineMode(StrEnum):
    FAST = "fast"
    BALANCED = "balanced"
    DEEP = "deep"


class ReasoningMode(StrEnum):
    DIRECT_STRUCTURED = "direct_structured"
    BOUNDED_REACT = "bounded_react"
    HYPOTHESIS_TEST = "hypothesis_test"
    PLAN_SELECT = "plan_select"
    PATCH_SYNTHESIS = "patch_synthesis"
    REFLEXION_DIAGNOSIS = "reflexion_diagnosis"


@dataclass(slots=True, frozen=True)
class StagePolicy:
    stage: str
    pipeline_mode: PipelineMode
    fast_path: ReasoningMode
    deep_path: ReasoningMode
    max_turns: int
    max_output_tokens: int
    tool_budget: dict[str, int] = field(default_factory=dict)
    no_progress_limit: int = 2
    allow_escalation: bool = True


@dataclass(slots=True)
class StageExecution:
    stage: str
    pipeline_mode: str
    reasoning_mode: str
    escalated: bool = False
    escalation_reasons: list[str] = field(default_factory=list)
    llm_calls: int = 0
    tool_calls: dict[str, int] = field(default_factory=dict)
    stopped_reason: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_POLICIES: dict[str, dict[PipelineMode, StagePolicy]] = {
    "impact": {
        PipelineMode.FAST: StagePolicy("impact", PipelineMode.FAST, ReasoningMode.DIRECT_STRUCTURED, ReasoningMode.BOUNDED_REACT, 4, 3072, {"read_file": 2, "search_code": 2, "list_dir": 1}, allow_escalation=False),
        PipelineMode.BALANCED: StagePolicy("impact", PipelineMode.BALANCED, ReasoningMode.DIRECT_STRUCTURED, ReasoningMode.BOUNDED_REACT, 8, 4096, {"read_file": 3, "search_code": 4, "list_dir": 1}),
        PipelineMode.DEEP: StagePolicy("impact", PipelineMode.DEEP, ReasoningMode.DIRECT_STRUCTURED, ReasoningMode.BOUNDED_REACT, 8, 4096, {"read_file": 3, "search_code": 4, "list_dir": 1}),
    },
    "root_cause": {
        PipelineMode.FAST: StagePolicy("root_cause", PipelineMode.FAST, ReasoningMode.DIRECT_STRUCTURED, ReasoningMode.HYPOTHESIS_TEST, 4, 4096, {"read_file": 2, "search_code": 2}, allow_escalation=False),
        PipelineMode.BALANCED: StagePolicy("root_cause", PipelineMode.BALANCED, ReasoningMode.DIRECT_STRUCTURED, ReasoningMode.HYPOTHESIS_TEST, 8, 5120, {"read_file": 4, "search_code": 4}),
        PipelineMode.DEEP: StagePolicy("root_cause", PipelineMode.DEEP, ReasoningMode.DIRECT_STRUCTURED, ReasoningMode.HYPOTHESIS_TEST, 10, 6144, {"read_file": 5, "search_code": 5}),
    },
    "remediation": {
        PipelineMode.FAST: StagePolicy("remediation", PipelineMode.FAST, ReasoningMode.PLAN_SELECT, ReasoningMode.BOUNDED_REACT, 1, 3072, {}, allow_escalation=False),
        PipelineMode.BALANCED: StagePolicy("remediation", PipelineMode.BALANCED, ReasoningMode.PLAN_SELECT, ReasoningMode.BOUNDED_REACT, 4, 4096, {"read_file": 2, "search_code": 2, "list_dir": 1}),
        PipelineMode.DEEP: StagePolicy("remediation", PipelineMode.DEEP, ReasoningMode.PLAN_SELECT, ReasoningMode.BOUNDED_REACT, 4, 5120, {"read_file": 2, "search_code": 2, "list_dir": 1}),
    },
    "patch": {
        PipelineMode.FAST: StagePolicy("patch", PipelineMode.FAST, ReasoningMode.PATCH_SYNTHESIS, ReasoningMode.PATCH_SYNTHESIS, 4, 8192, {"read_file": 2, "search_code": 1}),
        PipelineMode.BALANCED: StagePolicy("patch", PipelineMode.BALANCED, ReasoningMode.PATCH_SYNTHESIS, ReasoningMode.PATCH_SYNTHESIS, 6, 10000, {"read_file": 3, "search_code": 2}),
        PipelineMode.DEEP: StagePolicy("patch", PipelineMode.DEEP, ReasoningMode.PATCH_SYNTHESIS, ReasoningMode.PATCH_SYNTHESIS, 10, 12000, {"read_file": 5, "search_code": 3}),
    },
    "failure": {
        PipelineMode.FAST: StagePolicy("failure", PipelineMode.FAST, ReasoningMode.REFLEXION_DIAGNOSIS, ReasoningMode.REFLEXION_DIAGNOSIS, 1, 3072, {}, allow_escalation=False),
        PipelineMode.BALANCED: StagePolicy("failure", PipelineMode.BALANCED, ReasoningMode.REFLEXION_DIAGNOSIS, ReasoningMode.REFLEXION_DIAGNOSIS, 1, 4096, {}),
        PipelineMode.DEEP: StagePolicy("failure", PipelineMode.DEEP, ReasoningMode.REFLEXION_DIAGNOSIS, ReasoningMode.REFLEXION_DIAGNOSIS, 1, 4096, {}),
    },
}


def normalize_pipeline_mode(value: str | PipelineMode | None) -> PipelineMode:
    if isinstance(value, PipelineMode):
        return value
    try:
        return PipelineMode(str(value or PipelineMode.BALANCED.value).strip().lower())
    except ValueError:
        return PipelineMode.BALANCED


def stage_policy(stage: str, mode: str | PipelineMode | None) -> StagePolicy:
    normalized = normalize_pipeline_mode(mode)
    try:
        return _POLICIES[stage][normalized]
    except KeyError as exc:
        raise ValueError(f"unsupported reasoning stage: {stage}") from exc

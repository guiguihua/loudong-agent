"""Typed state shared by every specialist repair scenario."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class RepairMode(StrEnum):
    AUTOMATED = "automated"
    CANDIDATE_ONLY = "candidate_only"
    BLOCKED = "blocked"


class OracleCategory(StrEnum):
    BASELINE_BUILD = "baseline_build"
    REPRODUCTION = "reproduction"
    SECURITY = "security"
    BUSINESS = "business"
    SIDE_EFFECT = "side_effect"
    DIFF_RISK = "diff_risk"
    GENERATION = "generation"


class OracleStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    NOT_CONFIGURED = "not_configured"
    SKIPPED = "skipped"


@dataclass(frozen=True, slots=True)
class ReproductionContract:
    finding_id: str
    scenario: str
    build_commands: tuple[str, ...] = ()
    reproducer_ids: tuple[str, ...] = ()
    poc_commands: tuple[str, ...] = ()
    security_commands: tuple[str, ...] = ()
    business_commands: tuple[str, ...] = ()
    side_effect_checks: tuple[str, ...] = ()
    environment_hash: str = ""
    builtin_security_oracle: bool = False
    builtin_business_oracle: bool = False

    @property
    def missing_for_search(self) -> tuple[str, ...]:
        missing: list[str] = []
        if not self.build_commands:
            missing.append("baseline_build")
        if not self.reproducer_ids:
            missing.append("vulnerability_reproducer")
        return tuple(missing)

    @property
    def missing_for_automation(self) -> tuple[str, ...]:
        missing = list(self.missing_for_search)
        if not self.poc_commands and not self.reproducer_ids:
            missing.append("real_poc")
        if not self.security_commands and not self.builtin_security_oracle:
            missing.append("security_oracle")
        if not self.business_commands and not self.builtin_business_oracle:
            missing.append("business_oracle")
        if not self.side_effect_checks:
            missing.append("side_effect_oracle")
        return tuple(missing)

    @property
    def search_ready(self) -> bool:
        return not self.missing_for_search

    @property
    def automation_ready(self) -> bool:
        return not self.missing_for_automation

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["missing_for_search"] = list(self.missing_for_search)
        result["missing_for_automation"] = list(self.missing_for_automation)
        result["search_ready"] = self.search_ready
        result["automation_ready"] = self.automation_ready
        return result


@dataclass(frozen=True, slots=True)
class EditIR:
    file: str
    operation: str
    symbol: str | None
    expected_original_hash: str | None
    replacement: str
    rationale: str
    invariants: tuple[str, ...] = ()

    def semantic_payload(self) -> dict[str, Any]:
        return {
            "file": self.file.replace("\\", "/"),
            "operation": self.operation,
            "symbol": self.symbol,
            "replacement": "\n".join(
                line.rstrip() for line in self.replacement.strip().splitlines()
            ),
            "invariants": sorted(self.invariants),
        }


@dataclass(frozen=True, slots=True)
class OracleResult:
    oracle_id: str
    category: OracleCategory
    status: OracleStatus
    summary: str
    required: bool = True
    command: str | None = None
    exit_code: int | None = None
    evidence: tuple[str, ...] = ()
    duration_ms: int = 0

    @property
    def passed(self) -> bool:
        return self.status == OracleStatus.PASSED

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["category"] = self.category.value
        result["status"] = self.status.value
        return result


@dataclass(frozen=True, slots=True)
class Counterexample:
    attempt: int
    strategy_fingerprint: str
    failure_category: str
    violated_invariant: str
    evidence: tuple[str, ...]
    prohibited_equivalent_strategy: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class RepairCandidateRecord:
    candidate_id: str
    attempt: int
    strategy: str
    strategy_fingerprint: str
    edit_ir: list[EditIR]
    oracle_results: list[OracleResult]
    raw_result: dict[str, Any]
    accepted: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "attempt": self.attempt,
            "strategy": self.strategy,
            "strategy_fingerprint": self.strategy_fingerprint,
            "edit_ir": [asdict(item) for item in self.edit_ir],
            "oracle_results": [item.to_dict() for item in self.oracle_results],
            "raw_result": _persisted_raw_result(self.raw_result),
            "accepted": self.accepted,
        }


@dataclass(slots=True)
class RepairSession:
    finding_id: str
    scenario: str
    mode: RepairMode
    contract: ReproductionContract
    source_snapshot_hash: str
    baseline_results: list[OracleResult] = field(default_factory=list)
    candidates: list[RepairCandidateRecord] = field(default_factory=list)
    counterexamples: list[Counterexample] = field(default_factory=list)
    accepted_candidate_id: str | None = None
    status: str = "created"
    failure_stage: str | None = None
    terminal_reason: str | None = None

    @classmethod
    def create(
        cls,
        finding_id: str,
        scenario: str,
        contract: ReproductionContract,
        source_files: dict[str, str],
    ) -> "RepairSession":
        payload = json.dumps(
            {key: source_files[key] for key in sorted(source_files)},
            ensure_ascii=False,
            separators=(",", ":"),
        )
        mode = (
            RepairMode.AUTOMATED
            if contract.automation_ready
            else RepairMode.CANDIDATE_ONLY
        )
        return cls(
            finding_id=finding_id,
            scenario=scenario,
            mode=mode,
            contract=contract,
            source_snapshot_hash=hashlib.sha256(payload.encode("utf-8")).hexdigest(),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "scenario": self.scenario,
            "mode": self.mode.value,
            "contract": self.contract.to_dict(),
            "source_snapshot_hash": self.source_snapshot_hash,
            "baseline_results": [item.to_dict() for item in self.baseline_results],
            "candidates": [item.to_dict() for item in self.candidates],
            "counterexamples": [item.to_dict() for item in self.counterexamples],
            "accepted_candidate_id": self.accepted_candidate_id,
            "status": self.status,
            "failure_stage": self.failure_stage,
            "terminal_reason": self.terminal_reason,
        }


_RAW_RESULT_FIELDS = (
    "summary",
    "artifacts",
    "changed_files",
    "blocked_reason",
    "risks",
    "needs_human_review",
    "llm_calls",
    "change_set",
    "edit_ir",
    "workspace_checks",
    "executor",
    "failure_stage",
    "exception_type",
)


def _persisted_raw_result(raw_result: dict[str, Any]) -> dict[str, Any]:
    """Keep replay/debug evidence without serializing arbitrary backend state."""
    persisted = {
        key: raw_result[key]
        for key in _RAW_RESULT_FIELDS
        if key in raw_result
    }
    return json.loads(json.dumps(
        persisted,
        ensure_ascii=False,
        default=str,
    ))


def edit_fingerprint(edits: list[EditIR], raw_result: dict[str, Any]) -> str:
    if edits:
        payload: Any = [item.semantic_payload() for item in edits]
    else:
        payload = {
            "blocked_reason": raw_result.get("blocked_reason"),
            "risks": raw_result.get("risks", []),
            "workspace_checks": [
                {
                    "name": item.get("name"),
                    "passed": item.get("passed"),
                    "output": str(item.get("output", ""))[-500:],
                }
                for item in raw_result.get("workspace_checks", [])
                if isinstance(item, dict)
            ],
        }
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

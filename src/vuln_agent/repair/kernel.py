"""Scenario-neutral repair search loop."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from .models import (
    Counterexample,
    EditIR,
    OracleCategory,
    OracleResult,
    OracleStatus,
    RepairCandidateRecord,
    RepairMode,
    RepairSession,
    ReproductionContract,
    edit_fingerprint,
)


class RepairScenario(Protocol):
    name: str
    finding_id: str
    source_snapshot: dict[str, str]

    def build_contract(self) -> ReproductionContract: ...

    def verify_baseline(self, contract: ReproductionContract) -> list[OracleResult]: ...

    def generate_candidate(
        self,
        *,
        attempt: int,
        feedback: str,
        prefer_deterministic: bool,
    ) -> dict[str, Any]: ...

    def evaluate_candidate(
        self,
        raw_result: dict[str, Any],
        contract: ReproductionContract,
    ) -> list[OracleResult]: ...

    def edit_ir(self, raw_result: dict[str, Any]) -> list[EditIR]: ...


@dataclass(slots=True)
class RepairKernelResult:
    session: RepairSession
    raw_result: dict[str, Any]

    @property
    def accepted(self) -> bool:
        return self.session.accepted_candidate_id is not None

    def to_raw(self) -> dict[str, Any]:
        raw = dict(self.raw_result)
        raw["repair_session"] = self.session.to_dict()
        raw["repair_mode"] = self.session.mode.value
        raw["repair_kernel_accepted"] = self.accepted
        raw["executor"] = f"repair_kernel:{self.session.scenario}"
        return raw


class RepairKernel:
    """Run baseline reproduction, candidate search, oracles, and failure memory."""

    def __init__(self, *, max_attempts: int = 3) -> None:
        self.max_attempts = max(1, max_attempts)

    def run(
        self,
        scenario: RepairScenario,
        *,
        previous_feedback: str = "",
    ) -> RepairKernelResult:
        try:
            contract = scenario.build_contract()
            if not isinstance(contract, ReproductionContract):
                raise TypeError("scenario.build_contract() returned an invalid contract")
        except Exception as exc:
            contract = ReproductionContract(
                finding_id=scenario.finding_id,
                scenario=scenario.name,
            )
            session = self._create_session(scenario, contract)
            return self._blocked_exception(
                session,
                stage="build_contract",
                exc=exc,
                oracle_category=OracleCategory.GENERATION,
            )

        session = self._create_session(scenario, contract)
        if session.failure_stage == "create_session":
            reason = session.terminal_reason or "repair session creation failed"
            session.baseline_results.append(OracleResult(
                oracle_id="create_session_exception",
                category=OracleCategory.GENERATION,
                status=OracleStatus.FAILED,
                summary=reason,
            ))
            return RepairKernelResult(session, {
                "artifacts": [],
                "changed_files": [],
                "blocked_reason": reason,
                "risks": [reason],
                "needs_human_review": True,
                "llm_calls": 0,
                "failure_stage": "create_session",
            })
        try:
            session.baseline_results = scenario.verify_baseline(contract)
            if not isinstance(session.baseline_results, list):
                raise TypeError("scenario.verify_baseline() returned a non-list")
        except Exception as exc:
            return self._blocked_exception(
                session,
                stage="verify_baseline",
                exc=exc,
                oracle_category=OracleCategory.BASELINE_BUILD,
            )

        failed_baseline = [
            item for item in session.baseline_results
            if item.required and item.status == OracleStatus.FAILED
        ]
        reproduction_passed = any(
            item.category == OracleCategory.REPRODUCTION and item.passed
            for item in session.baseline_results
        )
        if not contract.search_ready or failed_baseline or not reproduction_passed:
            session.mode = RepairMode.BLOCKED
            session.status = "baseline_blocked"
            reason = "; ".join(
                [
                    *contract.missing_for_search,
                    *(item.summary for item in failed_baseline),
                    *(["vulnerability_not_reproduced"] if not reproduction_passed else []),
                ]
            )
            session.failure_stage = "verify_baseline"
            session.terminal_reason = reason or "baseline contract is not satisfied"
            return RepairKernelResult(session, {
                "artifacts": [],
                "changed_files": [],
                "blocked_reason": reason or "baseline contract is not satisfied",
                "risks": [reason or "baseline contract is not satisfied"],
                "needs_human_review": True,
                "llm_calls": 0,
            })

        feedback = previous_feedback
        best_candidate: dict[str, Any] | None = None
        seen_fingerprints: set[str] = set()
        total_llm_calls = 0

        for attempt in range(1, self.max_attempts + 1):
            stage_failure: OracleResult | None = None
            try:
                raw = scenario.generate_candidate(
                    attempt=attempt,
                    feedback=feedback,
                    prefer_deterministic=attempt == self.max_attempts,
                )
                if not isinstance(raw, dict):
                    raise TypeError("scenario.generate_candidate() returned a non-dict")
            except Exception as exc:
                raw, stage_failure = self._candidate_exception(
                    "generate_candidate",
                    exc,
                )
            total_llm_calls += int(raw.get("llm_calls", 0) or 0)
            try:
                edits = scenario.edit_ir(raw)
                if not isinstance(edits, list):
                    raise TypeError("scenario.edit_ir() returned a non-list")
            except Exception as exc:
                edits = []
                raw, stage_failure = self._merge_candidate_exception(
                    raw,
                    "edit_ir",
                    exc,
                )
            fingerprint = edit_fingerprint(edits, raw)
            if stage_failure is None:
                try:
                    oracle_results = scenario.evaluate_candidate(raw, contract)
                    if not isinstance(oracle_results, list):
                        raise TypeError(
                            "scenario.evaluate_candidate() returned a non-list"
                        )
                except Exception as exc:
                    raw, stage_failure = self._merge_candidate_exception(
                        raw,
                        "evaluate_candidate",
                        exc,
                    )
                    oracle_results = [stage_failure]
            else:
                oracle_results = [stage_failure]
            required_failures = [
                item for item in oracle_results
                if item.required and item.status != OracleStatus.PASSED
            ]
            has_artifacts = bool(raw.get("artifacts")) and not raw.get("blocked_reason")
            accepted = (
                session.mode == RepairMode.AUTOMATED
                and has_artifacts
                and not required_failures
            )
            candidate_id = f"{scenario.finding_id}-candidate-{attempt}"
            record = RepairCandidateRecord(
                candidate_id=candidate_id,
                attempt=attempt,
                strategy=(
                    "model_guided"
                    if attempt == 1
                    else (
                        "deterministic_counterexample_fallback"
                        if attempt == self.max_attempts
                        else "model_counterexample_retry"
                    )
                ),
                strategy_fingerprint=fingerprint,
                edit_ir=edits,
                oracle_results=oracle_results,
                raw_result=raw,
                accepted=accepted,
            )
            session.candidates.append(record)

            if has_artifacts and not any(
                item.status == OracleStatus.FAILED for item in oracle_results
            ):
                best_candidate = raw

            if accepted:
                session.accepted_candidate_id = candidate_id
                session.status = "accepted"
                raw["llm_calls"] = total_llm_calls
                return RepairKernelResult(session, raw)

            if (
                session.mode == RepairMode.CANDIDATE_ONLY
                and best_candidate is not None
            ):
                session.status = "candidate_only"
                best_candidate["needs_human_review"] = True
                best_candidate["llm_calls"] = total_llm_calls
                best_candidate.setdefault("risks", []).append(
                    "automation evidence incomplete: "
                    + ", ".join(contract.missing_for_automation)
                )
                return RepairKernelResult(session, best_candidate)

            duplicate = fingerprint in seen_fingerprints
            seen_fingerprints.add(fingerprint)
            failure = required_failures[0] if required_failures else OracleResult(
                "candidate_generation",
                OracleCategory.GENERATION,
                OracleStatus.FAILED,
                str(raw.get("blocked_reason") or "candidate produced no applicable artifact"),
            )
            counterexample = Counterexample(
                attempt=attempt,
                strategy_fingerprint=fingerprint,
                failure_category=failure.category.value,
                violated_invariant=failure.summary,
                evidence=failure.evidence,
                prohibited_equivalent_strategy=(
                    "Do not repeat a semantically equivalent repair strategy"
                    + ("; the strategy fingerprint was already seen" if duplicate else "")
                ),
            )
            session.counterexamples.append(counterexample)
            feedback = self._feedback(session.counterexamples)

        session.status = "exhausted"
        raw = best_candidate or {
            "artifacts": [],
            "changed_files": [],
            "blocked_reason": "repair kernel exhausted without an accepted candidate",
            "risks": ["repair kernel exhausted without an accepted candidate"],
            "needs_human_review": True,
        }
        raw["llm_calls"] = total_llm_calls
        session.failure_stage = str(raw.get("failure_stage") or "candidate_search")
        session.terminal_reason = str(
            raw.get("blocked_reason")
            or "repair kernel exhausted without an accepted candidate"
        )
        return RepairKernelResult(session, raw)

    @staticmethod
    def _create_session(
        scenario: RepairScenario,
        contract: ReproductionContract,
    ) -> RepairSession:
        try:
            return RepairSession.create(
                scenario.finding_id,
                scenario.name,
                contract,
                scenario.source_snapshot,
            )
        except Exception as exc:
            session = RepairSession(
                finding_id=scenario.finding_id,
                scenario=scenario.name,
                mode=RepairMode.BLOCKED,
                contract=contract,
                source_snapshot_hash="unavailable",
                status="session_creation_error",
                failure_stage="create_session",
                terminal_reason=RepairKernel._exception_reason(
                    "create_session",
                    exc,
                ),
            )
            return session

    @staticmethod
    def _blocked_exception(
        session: RepairSession,
        *,
        stage: str,
        exc: Exception,
        oracle_category: OracleCategory,
    ) -> RepairKernelResult:
        reason = RepairKernel._exception_reason(stage, exc)
        session.mode = RepairMode.BLOCKED
        session.status = f"{stage}_error"
        session.failure_stage = stage
        session.terminal_reason = reason
        session.baseline_results.append(OracleResult(
            oracle_id=f"{stage}_exception",
            category=oracle_category,
            status=OracleStatus.FAILED,
            summary=reason,
            evidence=(type(exc).__name__,),
        ))
        return RepairKernelResult(session, {
            "artifacts": [],
            "changed_files": [],
            "blocked_reason": reason,
            "risks": [reason],
            "needs_human_review": True,
            "llm_calls": 0,
            "failure_stage": stage,
            "exception_type": type(exc).__name__,
        })

    @staticmethod
    def _candidate_exception(
        stage: str,
        exc: Exception,
    ) -> tuple[dict[str, Any], OracleResult]:
        reason = RepairKernel._exception_reason(stage, exc)
        raw = {
            "artifacts": [],
            "changed_files": [],
            "blocked_reason": reason,
            "risks": [reason],
            "needs_human_review": True,
            "llm_calls": 0,
            "failure_stage": stage,
            "exception_type": type(exc).__name__,
        }
        return raw, OracleResult(
            oracle_id=f"{stage}_exception",
            category=OracleCategory.GENERATION,
            status=OracleStatus.FAILED,
            summary=reason,
            evidence=(type(exc).__name__,),
        )

    @staticmethod
    def _merge_candidate_exception(
        raw: dict[str, Any],
        stage: str,
        exc: Exception,
    ) -> tuple[dict[str, Any], OracleResult]:
        result = dict(raw)
        reason = RepairKernel._exception_reason(stage, exc)
        result["blocked_reason"] = reason
        result["failure_stage"] = stage
        result["exception_type"] = type(exc).__name__
        result["needs_human_review"] = True
        result.setdefault("risks", [])
        if not isinstance(result["risks"], list):
            result["risks"] = [str(result["risks"])]
        result["risks"].append(reason)
        return result, OracleResult(
            oracle_id=f"{stage}_exception",
            category=OracleCategory.GENERATION,
            status=OracleStatus.FAILED,
            summary=reason,
            evidence=(type(exc).__name__,),
        )

    @staticmethod
    def _exception_reason(stage: str, exc: Exception) -> str:
        message = " ".join(str(exc).split())[:500]
        suffix = f": {message}" if message else ""
        return f"repair kernel {stage} failed with {type(exc).__name__}{suffix}"

    @staticmethod
    def _feedback(counterexamples: list[Counterexample]) -> str:
        return "\n".join(
            (
                f"attempt={item.attempt}; category={item.failure_category}; "
                f"violated_invariant={item.violated_invariant}; "
                f"prohibited={item.prohibited_equivalent_strategy}"
            )
            for item in counterexamples[-3:]
        )

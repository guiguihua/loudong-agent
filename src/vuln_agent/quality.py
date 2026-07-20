"""Deterministic patch-quality metrics for evaluation and delivery gates."""

from __future__ import annotations

from .models import (
    PatchCandidate,
    PatchCandidateStatus,
    PatchValidationStatus,
    RemediationPlan,
    ValidationToolchainResult,
)


def assess_patch_quality(
    candidate: PatchCandidate,
    plan: RemediationPlan,
    validation: ValidationToolchainResult,
) -> dict:
    """Return comparable quality metrics without using an LLM."""
    executable = [
        artifact for artifact in candidate.artifacts
        if not artifact.needs_manual_fix
        and "--- " in artifact.content
        and "+++ " in artifact.content
        and "@@" in artifact.content
    ]
    total_artifacts = len(candidate.artifacts)
    executable_rate = (
        len(executable) / total_artifacts if total_artifacts else 0.0
    )

    planned = [
        change for change in plan.planned_changes
        if change.change_type in ("code", "dependency", "configuration", None)
    ]
    required_planned = [
        change for change in planned
        if change.causally_required
    ] or planned
    targets = {_norm(artifact.target) for artifact in executable}
    covered = [
        change for change in planned
        if _matches(_norm(change.file), targets)
    ]
    covered_required = [
        change for change in required_planned
        if _matches(_norm(change.file), targets)
    ]
    coverage_rate = (
        len(covered_required) / len(required_planned)
        if required_planned
        else 1.0
    )
    missing_planned = [
        change.file for change in required_planned
        if not _matches(_norm(change.file), targets)
    ]

    passed_layers = sum(
        1 for layer in validation.layers if layer.status.value == "passed"
    )
    validation_rate = (
        passed_layers / len(validation.layers) if validation.layers else 0.0
    )
    security_test_required = any(
        "security" in item.test_type.lower() or "安全" in item.test_type
        for item in plan.required_tests
    )
    test_text = "\n".join(
        artifact.content.lower()
        for artifact in executable
        if artifact.patch_type.value == "test"
    )
    has_attack_case = any(
        marker in test_text
        for marker in (
            "attack", "payload", "injection", "traversal", "malicious",
            "exploit", "攻击", "恶意", "' or '1'='1",
        )
    )
    has_legitimate_case = any(
        marker in test_text
        for marker in (
            "legitimate", "valid", "normal", "allowed", "benign",
            "合法", "正常",
        )
    )
    security_layer_passed = any(
        layer.layer.value == "security_regression"
        and layer.status.value == "passed"
        for layer in validation.layers
    )
    generated_test_contract_valid = (
        not security_test_required
        or (has_attack_case and has_legitimate_case)
        or security_layer_passed
    )
    gate_failures: list[str] = []
    if candidate.status != PatchCandidateStatus.GENERATED:
        gate_failures.append(candidate.blocked_reason or "candidate_not_generated")
    if not candidate.policy_check.within_patch_boundaries:
        gate_failures.extend(candidate.policy_check.violations)
    if executable_rate < 1.0:
        gate_failures.append("one_or_more_artifacts_are_not_machine_executable")
    if missing_planned:
        gate_failures.append(
            "planned_changes_without_executable_artifacts: "
            + ", ".join(missing_planned)
        )
    if validation.status != PatchValidationStatus.PASSED:
        gate_failures.append(f"validation_status:{validation.status.value}")
    if not generated_test_contract_valid:
        gate_failures.append(
            "security_test_missing_attack_or_legitimate_behavior_direction"
        )

    return {
        "candidate_status": candidate.status.value,
        "executable_artifact_rate": round(executable_rate, 4),
        "planned_change_coverage_rate": round(coverage_rate, 4),
        "validation_layer_pass_rate": round(validation_rate, 4),
        "changed_files_count": candidate.policy_check.changed_files_count,
        "estimated_diff_lines": candidate.policy_check.estimated_diff_lines,
        "manual_fix_artifact_count": total_artifacts - len(executable),
        "generated_test_contract_valid": generated_test_contract_valid,
        "missing_planned_changes": missing_planned,
        "quality_gate_passed": not gate_failures,
        "ready_for_automated_delivery": (
            not gate_failures
            and validation.status == PatchValidationStatus.PASSED
        ),
        "gate_failures": list(dict.fromkeys(gate_failures)),
    }


def _norm(path: str) -> str:
    return path.replace("\\", "/").strip().lstrip("./")


def _matches(expected: str, targets: set[str]) -> bool:
    return any(
        expected == target
        or expected.endswith("/" + target)
        or target.endswith("/" + expected)
        for target in targets
    )

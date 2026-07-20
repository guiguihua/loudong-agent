"""Verified-patch baseline metrics and release gates."""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True, slots=True)
class ReleaseThresholds:
    exact_apply_rate: float = 1.0
    false_success_rate: float = 0.0
    mandatory_validation_coverage: float = 1.0
    generated_test_contract_rate: float = 1.0
    prompt_contamination_count: int = 0
    verified_patch_rate: float = 0.60


def build_verified_patch_baseline(
    outputs: list[dict],
    *,
    prompt_contamination_count: int = 0,
    thresholds: ReleaseThresholds = ReleaseThresholds(),
) -> dict:
    """Aggregate real pipeline outputs using semantic quality gates."""
    eligible = [
        item for item in outputs
        if (item.get("repair_route") or {}).get("family")
        not in {None, "generic"}
    ]
    denominator = len(eligible)
    quality = [item.get("patch_quality") or {} for item in eligible]
    exact = sum(
        1 for item in quality
        if item.get("executable_artifact_rate") == 1.0
    )
    verified = sum(
        1 for item in quality
        if item.get("ready_for_automated_delivery") is True
    )
    mandatory_covered = sum(
        1 for item in quality
        if item.get("validation_layer_pass_rate") == 1.0
    )
    test_contract = sum(
        1 for item in quality
        if item.get("generated_test_contract_valid", True) is True
    )
    false_success = sum(
        1 for item in eligible
        if item.get("status") == "succeeded"
        and (
            (item.get("patch_candidate") or {}).get("status") != "generated"
            or (item.get("patch_validation") or {}).get("status") != "passed"
        )
    )

    def rate(value: int) -> float:
        return round(value / denominator, 4) if denominator else 0.0

    metrics = {
        "eligible_tasks": denominator,
        "verified_tasks": verified,
        "verified_patch_rate": rate(verified),
        "exact_apply_rate": rate(exact),
        "false_success_rate": rate(false_success),
        "mandatory_validation_coverage": rate(mandatory_covered),
        "generated_test_contract_rate": rate(test_contract),
        "prompt_contamination_count": prompt_contamination_count,
    }
    gates = {
        "exact_apply_rate": metrics["exact_apply_rate"] >= thresholds.exact_apply_rate,
        "false_success_rate": metrics["false_success_rate"] <= thresholds.false_success_rate,
        "mandatory_validation_coverage": (
            metrics["mandatory_validation_coverage"]
            >= thresholds.mandatory_validation_coverage
        ),
        "generated_test_contract_rate": (
            metrics["generated_test_contract_rate"]
            >= thresholds.generated_test_contract_rate
        ),
        "prompt_contamination_count": (
            prompt_contamination_count <= thresholds.prompt_contamination_count
        ),
        "verified_patch_rate": (
            metrics["verified_patch_rate"] >= thresholds.verified_patch_rate
        ),
    }
    return {
        "metrics": metrics,
        "thresholds": asdict(thresholds),
        "gates": gates,
        "release_ready": denominator > 0 and all(gates.values()),
    }


def count_prompt_contamination(
    prompts: list[str],
    forbidden_terms: tuple[str, ...] = (
        "OctKey.import_key",
        "NoneAlgorithm",
        "HMACAlgorithm.prepare_key",
        "CVE-2024-37568",
    ),
) -> int:
    return sum(
        prompt.lower().count(term.lower())
        for prompt in prompts
        for term in forbidden_terms
    )

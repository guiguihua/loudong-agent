"""Reusable, oracle-driven repair loop contracts."""

from .benchmark import (
    BenchmarkCase,
    PatchQualityMetrics,
    QualityObservation,
    default_phase1_inventory,
)
from .kernel import RepairKernel, RepairKernelResult, RepairScenario
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
)

__all__ = [
    "BenchmarkCase",
    "Counterexample",
    "EditIR",
    "OracleCategory",
    "OracleResult",
    "OracleStatus",
    "PatchQualityMetrics",
    "QualityObservation",
    "RepairCandidateRecord",
    "RepairKernel",
    "RepairKernelResult",
    "RepairMode",
    "RepairScenario",
    "RepairSession",
    "ReproductionContract",
    "default_phase1_inventory",
]

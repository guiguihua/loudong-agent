"""Oracle-driven SQL injection scenario backed by structured Python edits."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ...models import (
    EvidenceBundle,
    NormalizedVulnerability,
    RemediationPlan,
    RootCauseAssessment,
    SourceFile,
)
from ...repair.models import (
    EditIR,
    OracleCategory,
    OracleResult,
    OracleStatus,
    ReproductionContract,
)
from ...sast_executor import (
    SASTCodeRepairExecutor,
    _norm,
    _sql_oracle_problems,
)
from ...semantic import PythonSemanticContextBuilder, SemanticContextPackage
from .taxonomy import classify_sql_injection

if TYPE_CHECKING:
    from ...llm import LLMBackend


class SQLInjectionRepairScenario:
    """SQL injection task adapter for the generic RepairKernel."""

    name = "sql_injection_v1"

    def __init__(
        self,
        finding: NormalizedVulnerability,
        root_cause: RootCauseAssessment,
        plan: RemediationPlan,
        source_files: list[SourceFile],
        evidence: EvidenceBundle,
        llm: LLMBackend | None,
        *,
        timeout_seconds: int = 90,
    ) -> None:
        self.finding = finding
        self.finding_id = finding.finding_id
        self.root_cause = root_cause
        self.plan = plan
        self.source_files = source_files
        self.evidence = evidence
        self.llm = llm
        self.sql_kind = classify_sql_injection(finding)
        self.timeout_seconds = timeout_seconds
        self.source_snapshot = {
            _norm(item.path): item.content for item in source_files
        }
        self.package: SemanticContextPackage = PythonSemanticContextBuilder().build(
            finding,
            root_cause,
            plan,
            source_files,
            evidence,
            "sql_injection",
        )

    def build_contract(self) -> ReproductionContract:
        target_paths = tuple(sorted({item.file for item in self.package.symbols}))
        build_commands = (
            "python -m py_compile " + " ".join(target_paths),
        ) if target_paths else ()
        capabilities = self.evidence.validation_capabilities
        environment_payload = json.dumps(
            {
                "files": sorted(self.source_snapshot),
                "commands": {
                    "test": capabilities.test_commands,
                    "security": capabilities.security_commands,
                    "poc": capabilities.poc_commands,
                },
            },
            sort_keys=True,
        )
        return ReproductionContract(
            finding_id=self.finding_id,
            scenario=self.name,
            build_commands=build_commands,
            reproducer_ids=("builtin:sql_ast_vulnerability_reproducer",),
            poc_commands=tuple(dict.fromkeys(capabilities.poc_commands)),
            security_commands=tuple(dict.fromkeys([
                *capabilities.security_commands,
                *capabilities.poc_commands,
            ])),
            business_commands=tuple(dict.fromkeys(capabilities.test_commands)),
            side_effect_checks=(
                "exact_git_apply",
                "declared_patch_boundaries",
                "maximum_diff_lines",
            ),
            environment_hash=hashlib.sha256(
                environment_payload.encode("utf-8")
            ).hexdigest(),
            builtin_security_oracle=True,
            builtin_business_oracle=False,
        )

    def verify_baseline(
        self,
        contract: ReproductionContract,
    ) -> list[OracleResult]:
        started = time.perf_counter()
        syntax_problems: list[str] = []
        vulnerability_evidence: list[str] = []
        for context in self.package.symbols:
            content = self.source_snapshot.get(context.file, "")
            try:
                tree = ast.parse(content)
            except SyntaxError as exc:
                syntax_problems.append(f"{context.file}:{exc.lineno}:{exc.msg}")
                continue
            try:
                vulnerability_evidence.extend(
                    _sql_oracle_problems(
                        context.file,
                        tree,
                        context.symbol,
                        self.sql_kind,
                    )
                )
            except ValueError as exc:
                syntax_problems.append(str(exc))

        results = [
            OracleResult(
                "baseline_python_syntax",
                OracleCategory.BASELINE_BUILD,
                OracleStatus.FAILED if syntax_problems else OracleStatus.PASSED,
                (
                    "; ".join(syntax_problems)
                    if syntax_problems
                    else "baseline target syntax is valid"
                ),
                evidence=tuple(syntax_problems or ["ast.parse completed"]),
                duration_ms=int((time.perf_counter() - started) * 1000),
            ),
            OracleResult(
                "sql_vulnerability_reproducer",
                OracleCategory.REPRODUCTION,
                OracleStatus.PASSED if vulnerability_evidence else OracleStatus.FAILED,
                (
                    "baseline SQL injection pattern reproduced"
                    if vulnerability_evidence
                    else "baseline does not contain a reproducible dynamic SQL sink"
                ),
                evidence=tuple(vulnerability_evidence),
            ),
        ]
        results.append(self._run_baseline_poc(contract))
        results.append(self._run_baseline_business(contract))
        return results

    def generate_candidate(
        self,
        *,
        attempt: int,
        feedback: str,
        prefer_deterministic: bool,
    ) -> dict[str, Any]:
        return SASTCodeRepairExecutor(
            self.llm,
            timeout_seconds=self.timeout_seconds,
            max_attempts=1,
        ).execute(
            self.finding,
            self.root_cause,
            self.plan,
            self.source_files,
            self.evidence,
            previous_feedback=feedback,
            prefer_deterministic=prefer_deterministic,
        )

    def evaluate_candidate(
        self,
        raw_result: dict[str, Any],
        contract: ReproductionContract,
    ) -> list[OracleResult]:
        if raw_result.get("blocked_reason") or not raw_result.get("artifacts"):
            return [OracleResult(
                "candidate_generation",
                OracleCategory.GENERATION,
                OracleStatus.FAILED,
                str(raw_result.get("blocked_reason") or "no patch artifacts generated"),
                evidence=tuple(str(item) for item in raw_result.get("risks", [])),
            )]

        checks = {
            str(item.get("name")): item
            for item in raw_result.get("workspace_checks", [])
            if isinstance(item, dict)
        }
        syntax = checks.get("python_syntax")
        security = checks.get("sql_injection_security_oracle")
        results = [
            self._workspace_check_oracle(
                "candidate_python_syntax",
                OracleCategory.BASELINE_BUILD,
                syntax,
            ),
            self._workspace_check_oracle(
                "sql_parameterization_oracle",
                OracleCategory.SECURITY,
                security,
            ),
        ]
        results.extend(self._evaluate_in_fresh_workspace(raw_result, contract))
        return results

    def edit_ir(self, raw_result: dict[str, Any]) -> list[EditIR]:
        result: list[EditIR] = []
        for item in raw_result.get("edit_ir", []):
            if not isinstance(item, dict):
                continue
            result.append(EditIR(
                file=str(item.get("file") or ""),
                operation=str(item.get("operation") or ""),
                symbol=str(item["symbol"]) if item.get("symbol") else None,
                expected_original_hash=None,
                replacement=str(item.get("replacement") or ""),
                rationale=str(item.get("rationale") or ""),
                invariants=(
                    "untrusted input remains bound data",
                    "legitimate query behavior remains valid",
                ),
            ))
        return result

    def _run_baseline_business(
        self,
        contract: ReproductionContract,
    ) -> OracleResult:
        if not contract.business_commands:
            return OracleResult(
                "baseline_business_oracle",
                OracleCategory.BUSINESS,
                OracleStatus.NOT_CONFIGURED,
                "no baseline business regression command configured",
                required=False,
            )
        return self._run_commands(
            self.source_snapshot,
            contract.business_commands,
            "baseline_business_oracle",
            OracleCategory.BUSINESS,
            required=True,
        )

    def _run_baseline_poc(
        self,
        contract: ReproductionContract,
    ) -> OracleResult:
        """Run a real regression PoC that must fail before the repair."""

        if not contract.poc_commands:
            return OracleResult(
                "baseline_real_poc",
                OracleCategory.REPRODUCTION,
                OracleStatus.NOT_CONFIGURED,
                "no explicit real PoC command configured",
                required=False,
            )
        with tempfile.TemporaryDirectory(prefix="vuln-agent-sql-poc-") as tmp:
            workspace = Path(tmp) / "workspace"
            self._hydrate(workspace, self.source_snapshot)
            completed = []
            for command in contract.poc_commands[:3]:
                result = self._run(workspace, command)
                completed.append(result)
                if result.returncode == 0:
                    break
        output = "\n".join(
            filter(
                None,
                [
                    completed[-1].stdout if completed else "",
                    completed[-1].stderr if completed else "",
                ],
            )
        ).strip()
        harness_failure = any(
            marker in output.lower()
            for marker in (
                "modulenotfounderror",
                "importerror",
                "syntaxerror",
                "no tests ran",
                "collected 0 items",
                "usage:",
                "unrecognized arguments",
                "could not find",
            )
        )
        reproduced = bool(completed) and all(
            item.returncode != 0 for item in completed
        ) and not harness_failure
        return OracleResult(
            "baseline_real_poc",
            OracleCategory.REPRODUCTION,
            OracleStatus.PASSED if reproduced else OracleStatus.FAILED,
            (
                "real PoC failed against the vulnerable baseline as expected"
                if reproduced
                else (
                    "PoC harness failed before exercising the vulnerability"
                    if harness_failure
                    else "real PoC did not distinguish the vulnerable baseline"
                )
            ),
            command=" && ".join(contract.poc_commands[:3]),
            exit_code=completed[-1].returncode if completed else 1,
            evidence=(output[-3000:] or "PoC command produced no output",),
        )

    def _evaluate_in_fresh_workspace(
        self,
        raw_result: dict[str, Any],
        contract: ReproductionContract,
    ) -> list[OracleResult]:
        with tempfile.TemporaryDirectory(prefix="vuln-agent-sql-oracle-") as tmp:
            workspace = Path(tmp) / "workspace"
            self._hydrate(workspace, self.source_snapshot)
            patch = workspace.parent / "candidate.patch"
            patch.write_text(
                "\n".join(
                    str(item.get("content", ""))
                    for item in raw_result.get("artifacts", [])
                ) + "\n",
                encoding="utf-8",
            )
            check = self._run(workspace, "git apply --check ../candidate.patch")
            if check.returncode != 0:
                return [self._completed_oracle(
                    "exact_git_apply",
                    OracleCategory.DIFF_RISK,
                    check,
                    required=True,
                )]
            apply = self._run(workspace, "git apply ../candidate.patch")
            if apply.returncode != 0:
                return [self._completed_oracle(
                    "exact_git_apply",
                    OracleCategory.DIFF_RISK,
                    apply,
                    required=True,
                )]

            results = [OracleResult(
                "exact_git_apply",
                OracleCategory.DIFF_RISK,
                OracleStatus.PASSED,
                "candidate applies exactly in a fresh isolated workspace",
                command="git apply --check candidate.patch && git apply candidate.patch",
                exit_code=0,
                evidence=("all candidate artifacts applied without fuzz",),
            )]
            shared_commands = (
                contract.security_commands
                and contract.security_commands == contract.business_commands
            )
            shared_result: OracleResult | None = None
            if contract.security_commands:
                shared_result = self._run_commands(
                    self._read_workspace(workspace),
                    contract.security_commands,
                    "external_sql_security_oracle",
                    OracleCategory.SECURITY,
                    required=True,
                )
                results.append(shared_result)
            if contract.business_commands:
                if shared_commands and shared_result is not None:
                    results.append(OracleResult(
                        "business_regression_oracle",
                        OracleCategory.BUSINESS,
                        shared_result.status,
                        "shared dual-direction regression command passed"
                        if shared_result.passed
                        else "shared dual-direction regression command failed",
                        required=True,
                        command=shared_result.command,
                        exit_code=shared_result.exit_code,
                        evidence=shared_result.evidence,
                        duration_ms=shared_result.duration_ms,
                    ))
                else:
                    results.append(self._run_commands(
                        self._read_workspace(workspace),
                        contract.business_commands,
                        "business_regression_oracle",
                        OracleCategory.BUSINESS,
                        required=True,
                    ))
            else:
                results.append(OracleResult(
                    "business_regression_oracle",
                    OracleCategory.BUSINESS,
                    OracleStatus.NOT_CONFIGURED,
                    "candidate is review-only because no business oracle is configured",
                    required=True,
                ))
            results.append(self._diff_boundary_oracle(raw_result))
            return results

    def _run_commands(
        self,
        files: dict[str, str],
        commands: tuple[str, ...],
        oracle_id: str,
        category: OracleCategory,
        *,
        required: bool,
    ) -> OracleResult:
        with tempfile.TemporaryDirectory(prefix="vuln-agent-sql-command-") as tmp:
            workspace = Path(tmp) / "workspace"
            self._hydrate(workspace, files)
            completed = []
            for command in commands[:3]:
                result = self._run(workspace, command)
                completed.append(result)
                if result.returncode != 0:
                    break
        passed = bool(completed) and all(item.returncode == 0 for item in completed)
        evidence = tuple(
            (
                "\n".join(filter(None, [item.stdout, item.stderr])).strip()[-3000:]
                or f"command exited with {item.returncode}"
            )
            for item in completed
        )
        return OracleResult(
            oracle_id,
            category,
            OracleStatus.PASSED if passed else OracleStatus.FAILED,
            (
                f"{category.value} commands passed"
                if passed
                else f"{category.value} command failed"
            ),
            required=required,
            command=" && ".join(commands[:3]),
            exit_code=0 if passed else (completed[-1].returncode if completed else 1),
            evidence=evidence,
        )

    def _diff_boundary_oracle(self, raw_result: dict[str, Any]) -> OracleResult:
        allowed = {
            _norm(path) for path in self.plan.patch_boundaries.allowed_files
        }
        allowed.update(_norm(path) for path in self.package.change_set.relevant_tests)
        targets = {
            _norm(str(item.get("target") or ""))
            for item in raw_result.get("artifacts", [])
        }
        diff_lines = sum(
            1
            for item in raw_result.get("artifacts", [])
            for line in str(item.get("content", "")).splitlines()
            if (
                (line.startswith("+") and not line.startswith("+++"))
                or (line.startswith("-") and not line.startswith("---"))
            )
        )
        violations = sorted(targets - allowed)
        if diff_lines > self.plan.patch_boundaries.maximum_diff_lines:
            violations.append(
                f"diff_lines={diff_lines} exceeds "
                f"{self.plan.patch_boundaries.maximum_diff_lines}"
            )
        return OracleResult(
            "declared_patch_boundaries",
            OracleCategory.SIDE_EFFECT,
            OracleStatus.FAILED if violations else OracleStatus.PASSED,
            (
                "; ".join(violations)
                if violations
                else "candidate remains inside declared files and diff budget"
            ),
            evidence=(
                f"targets={sorted(targets)}",
                f"diff_lines={diff_lines}",
            ),
        )

    @staticmethod
    def _workspace_check_oracle(
        oracle_id: str,
        category: OracleCategory,
        check: dict[str, Any] | None,
    ) -> OracleResult:
        if check is None:
            return OracleResult(
                oracle_id,
                category,
                OracleStatus.FAILED,
                f"{oracle_id} did not produce evidence",
            )
        passed = bool(check.get("passed"))
        return OracleResult(
            oracle_id,
            category,
            OracleStatus.PASSED if passed else OracleStatus.FAILED,
            str(check.get("output") or check.get("name") or oracle_id),
            command=str(check.get("command") or ""),
            exit_code=int(check.get("exit_code", 1)),
            evidence=(str(check.get("output") or ""),),
            duration_ms=int(check.get("duration_ms", 0)),
        )

    def _run(self, workspace: Path, command: str) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["PYTHONPATH"] = os.pathsep.join(
            filter(None, [str(workspace), env.get("PYTHONPATH", "")])
        )
        try:
            return subprocess.run(
                command,
                cwd=workspace,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            return subprocess.CompletedProcess(
                command,
                124,
                exc.stdout or "",
                exc.stderr or "command timed out",
            )

    def _completed_oracle(
        self,
        oracle_id: str,
        category: OracleCategory,
        completed: subprocess.CompletedProcess[str],
        *,
        required: bool,
    ) -> OracleResult:
        output = "\n".join(
            filter(None, [completed.stdout.strip(), completed.stderr.strip()])
        )
        return OracleResult(
            oracle_id,
            category,
            OracleStatus.PASSED if completed.returncode == 0 else OracleStatus.FAILED,
            output or f"command exited with {completed.returncode}",
            required=required,
            command=str(completed.args),
            exit_code=completed.returncode,
            evidence=(output,),
        )

    @staticmethod
    def _hydrate(workspace: Path, files: dict[str, str]) -> None:
        workspace.mkdir(parents=True, exist_ok=True)
        for path, content in files.items():
            target = workspace / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")

    @staticmethod
    def _read_workspace(workspace: Path) -> dict[str, str]:
        return {
            path.relative_to(workspace).as_posix(): path.read_text(
                encoding="utf-8", errors="replace"
            )
            for path in workspace.rglob("*")
            if path.is_file()
        }

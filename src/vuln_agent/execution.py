"""Execute candidate patches and validation commands in an isolated temporary tree."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from .models import (
    PatchCandidate,
    PatchType,
    ToolExecutionStatus,
    ValidationLayer,
    ValidationToolResult,
)


@dataclass(slots=True)
class WorkspaceValidationExecutor:
    """Apply a generated diff to a disposable copy, then run real checks.

    Explicit commands take precedence. Missing commands are conservatively
    discovered from repository files; a layer that cannot be discovered is
    returned as NOT_CONFIGURED and is never synthesized as passed.
    The source workspace is read-only from this executor's perspective: candidate
    patches are never applied, committed, or merged back into the original repo.
    """

    workspace: Path
    commands: dict[str, list[str] | str] = field(default_factory=dict)
    timeout_seconds: int = 300

    def __call__(self, candidate: PatchCandidate) -> list[ValidationToolResult]:
        with tempfile.TemporaryDirectory(prefix="vuln-agent-validation-") as tmp:
            target = Path(tmp) / "workspace"
            self._copy_workspace(target)
            apply_result = self._apply_patch(target, candidate)
            if apply_result.status != ToolExecutionStatus.PASSED:
                return [apply_result, *self._not_run_after_apply_failure()]

            results = [apply_result]
            for layer in (
                ValidationLayer.BUSINESS_REGRESSION,
                ValidationLayer.SECURITY_REGRESSION,
                ValidationLayer.SCANNER_RESCAN,
            ):
                results.extend(self._run_layer(target, layer, candidate))
            results.append(self._diff_risk(candidate))
            return results

    def _copy_workspace(self, target: Path) -> None:
        ignored = shutil.ignore_patterns(".git", ".venv", "node_modules", "__pycache__", ".pytest_cache")
        shutil.copytree(self.workspace, target, ignore=ignored)

    def _apply_patch(self, target: Path, candidate: PatchCandidate) -> ValidationToolResult:
        diffs = [
            artifact.content for artifact in candidate.artifacts
            if artifact.patch_type in {PatchType.CODE, PatchType.TEST, PatchType.CONFIGURATION, PatchType.DEPENDENCY}
            and "--- " in artifact.content and "+++ " in artifact.content
        ]
        if not diffs:
            return ValidationToolResult(
                ValidationLayer.BUILD, "git apply", ToolExecutionStatus.FAILED,
                "candidate contains no applicable unified diff", command="git apply --check candidate.patch",
                evidence=["No artifact contained ---/+++ unified diff headers."], exit_code=1,
            )
        patch_file = target.parent / "candidate.patch"
        patch_file.write_text("\n".join(diffs) + "\n", encoding="utf-8")
        check = self._run(target, "git apply --check ../candidate.patch")
        if check.returncode != 0:
            return self._result(ValidationLayer.BUILD, "git apply --check", check, "candidate diff does not apply")
        apply = self._run(target, "git apply ../candidate.patch")
        if apply.returncode != 0:
            return self._result(ValidationLayer.BUILD, "git apply", apply, "candidate diff could not be applied")

        build_results = self._run_layer(target, ValidationLayer.BUILD, candidate)
        if not build_results:
            return ValidationToolResult(
                ValidationLayer.BUILD, "patch application", ToolExecutionStatus.NOT_CONFIGURED,
                "patch applied, but no build command was configured",
                command="git apply --check ../candidate.patch && git apply ../candidate.patch",
                evidence=["Unified diff applied successfully in the isolated workspace."], exit_code=0,
            )
        build_results[0].evidence.insert(0, "Unified diff applied successfully in the isolated workspace.")
        return build_results[0]

    def _run_layer(
        self, target: Path, layer: ValidationLayer, candidate: PatchCandidate
    ) -> list[ValidationToolResult]:
        configured = self.commands.get(layer.value, [])
        commands = [configured] if isinstance(configured, str) else list(configured)
        if not commands:
            commands = self._discover_commands(target, layer, candidate)
        if not commands:
            return [ValidationToolResult(
                layer, layer.value, ToolExecutionStatus.NOT_CONFIGURED,
                f"no executable command configured for {layer.value}",
            )]
        results = []
        for command in commands:
            completed = self._run(target, command)
            results.append(self._result(layer, command, completed, f"{layer.value} command completed"))
        return results

    @staticmethod
    def _discover_commands(
        target: Path, layer: ValidationLayer, candidate: PatchCandidate
    ) -> list[str]:
        python = f'"{sys.executable}"'
        if layer == ValidationLayer.BUILD:
            # Compile the isolated patched tree. This is always executable for
            # Python repositories and gives real syntax/import-independent evidence.
            if any(target.rglob("*.py")):
                return [f"{python} -m compileall -q ."]
            return []

        has_pytest = any((target / name).exists() for name in ("pytest.ini", "pyproject.toml", "tox.ini"))
        tests_dir = target / "tests"
        if layer == ValidationLayer.BUSINESS_REGRESSION:
            if tests_dir.exists() or has_pytest:
                return [f"{python} -m pytest -q"]
            return []

        if layer == ValidationLayer.SECURITY_REGRESSION:
            test_targets = [
                artifact.target.replace("\\", "/")
                for artifact in candidate.artifacts
                if artifact.patch_type == PatchType.TEST
                and artifact.target.lower().endswith(".py")
            ]
            if test_targets:
                quoted = " ".join(f'"{path}"' for path in test_targets)
                return [f"{python} -m pytest -q {quoted}"]
            return []

        if layer == ValidationLayer.SCANNER_RESCAN:
            semgrep_config = next(
                (name for name in (".semgrep.yml", ".semgrep.yaml", "semgrep.yml", "semgrep.yaml") if (target / name).exists()),
                None,
            )
            if semgrep_config and shutil.which("semgrep"):
                return [f'semgrep scan --config "{semgrep_config}" .']
            return []
        return []

    def _run(self, cwd: Path, command: str) -> subprocess.CompletedProcess[str]:
        started = time.monotonic()
        try:
            result = subprocess.run(
                command, cwd=cwd, shell=True, text=True, capture_output=True,
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            result = subprocess.CompletedProcess(command, 124, exc.stdout or "", exc.stderr or "validation timed out")
        result._duration_ms = int((time.monotonic() - started) * 1000)  # type: ignore[attr-defined]
        return result

    @staticmethod
    def _result(layer, name, completed, summary) -> ValidationToolResult:
        output = "\n".join(part for part in (completed.stdout, completed.stderr) if part).strip()
        return ValidationToolResult(
            layer=layer,
            tool_name=name,
            status=ToolExecutionStatus.PASSED if completed.returncode == 0 else ToolExecutionStatus.FAILED,
            summary=summary if completed.returncode == 0 else f"{summary}; exit code {completed.returncode}",
            command=completed.args if isinstance(completed.args, str) else " ".join(completed.args),
            evidence=[output[-8000:] or "Command completed without output."],
            exit_code=completed.returncode,
            duration_ms=getattr(completed, "_duration_ms", None),
        )

    @staticmethod
    def _diff_risk(candidate: PatchCandidate) -> ValidationToolResult:
        check = candidate.policy_check
        passed = check.within_patch_boundaries and not check.forbidden_changes_detected
        evidence = [
            f"changed_files={check.changed_files_count}",
            f"estimated_diff_lines={check.estimated_diff_lines}",
            f"allowed_files_only={check.allowed_files_only}",
            *check.violations,
        ]
        return ValidationToolResult(
            ValidationLayer.DIFFERENTIAL_RISK, "candidate policy check",
            ToolExecutionStatus.PASSED if passed else ToolExecutionStatus.FAILED,
            "candidate is within declared patch boundaries" if passed else "candidate violates patch boundaries",
            command="internal:patch-policy-check", evidence=evidence, exit_code=0 if passed else 1,
        )

    @staticmethod
    def _not_run_after_apply_failure() -> list[ValidationToolResult]:
        return [
            ValidationToolResult(layer, layer.value, ToolExecutionStatus.SKIPPED, "not run because patch application failed")
            for layer in (
                ValidationLayer.BUSINESS_REGRESSION,
                ValidationLayer.SECURITY_REGRESSION,
                ValidationLayer.SCANNER_RESCAN,
                ValidationLayer.DIFFERENTIAL_RISK,
            )
        ]

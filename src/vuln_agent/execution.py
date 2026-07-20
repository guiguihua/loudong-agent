"""Execute candidate patches and validation commands in an isolated temporary tree."""

from __future__ import annotations

import os
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
from .validation_adapters import DjangoValidationCommandAdapter


@dataclass(slots=True)
class WorkspaceValidationExecutor:
    """Apply a generated diff to a disposable copy, then run real checks.

    Explicit commands take precedence. Missing commands are conservatively
    discovered from repository files; a layer that cannot be discovered is
    returned as NOT_CONFIGURED and is never synthesized as passed.
    The source workspace is read-only from this executor's perspective: candidate
    patches are never applied, committed, or merged back into the original repo.

    When ``source_files`` is provided (in-memory file contents, e.g. from a web
    API call that didn't clone a repo), missing target files are hydrated into
    the temp workspace before ``git apply`` runs.  This decouples patch
    generation (which sees source snippets in the LLM prompt) from patch
    application (which requires real files on disk).
    """

    workspace: Path
    commands: dict[str, list[str] | str] = field(default_factory=dict)
    timeout_seconds: int = 300
    source_files: dict[str, str] | None = None
    """In-memory file path → content map. Used to hydrate missing targets before git apply."""

    def __call__(self, candidate: PatchCandidate) -> list[ValidationToolResult]:
        with tempfile.TemporaryDirectory(prefix="vuln-agent-validation-") as tmp:
            target = Path(tmp) / "workspace"
            self._copy_workspace(target)
            apply_result = self._apply_patch(target, candidate)
            # A real patch-application/build failure stops downstream checks.
            # NOT_CONFIGURED means the diff applied but no build command was
            # discoverable; independent layers (especially diff risk) must
            # still run and retain their own evidence.
            if apply_result.status == ToolExecutionStatus.FAILED:
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
            and not getattr(artifact, "needs_manual_fix", False)  # skip best-effort placeholders
        ]
        if not diffs:
            return ValidationToolResult(
                ValidationLayer.BUILD, "git apply", ToolExecutionStatus.FAILED,
                "candidate contains no applicable unified diff", command="git apply --check candidate.patch",
                evidence=["No artifact contained ---/+++ unified diff headers."], exit_code=1,
            )

        # ── 预检查：补丁目标文件是否存在于工作区 ──
        missing = self._missing_targets(target, candidate)
        if missing:
            hydrated, still_missing = self._hydrate_missing_files(target, missing)
            if still_missing:
                return ValidationToolResult(
                    ValidationLayer.BUILD, "git apply --check", ToolExecutionStatus.FAILED,
                    f"patch targets {len(still_missing)} file(s) not found in workspace "
                    f"and not available as in-memory source files",
                    command="git apply --check candidate.patch",
                    evidence=[
                        "These files are referenced by the candidate diff but do not exist "
                        "in the repository working directory:",
                        *[f"  - {p}" for p in still_missing],
                        "",
                        "Common causes:",
                        "  1. The vulnerability targets a dependency (pip package) whose source "
                        "is not checked out in --source-dir.",
                        "  2. The file was loaded in-memory via the API / web form, but "
                        "source_dir was not set — workspace defaulted to the agent's own directory.",
                        "  3. The path in the diff header does not match the actual file layout "
                        "in the repository (e.g. missing a project-root prefix).",
                        "  4. The LLM invented a plausible but non-existent file path.",
                        "",
                        "Fix: set --source-dir to the root of the target repository, or provide "
                        "the missing files in source_files when calling the API.",
                    ],
                    exit_code=1,
                )
            if hydrated:
                # Write hydrated files into the temp workspace so git apply can find them
                for rel_path, content in hydrated.items():
                    dest = target / rel_path
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_text(content, encoding="utf-8")

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

    @staticmethod
    def _parse_hunks(diff_content: str) -> list[dict]:
        """Parse a unified diff into structured hunk data."""
        import re
        hunks = []
        hunk_pattern = re.compile(
            r'^@@ -(\d+),?(\d*) \+(\d+),?(\d*) @@\s*(.*?)\s*$', re.MULTILINE
        )
        lines = diff_content.splitlines()
        current_hunk = None
        for line in lines:
            m = hunk_pattern.match(line)
            if m:
                if current_hunk:
                    hunks.append(current_hunk)
                current_hunk = {
                    "old_start": int(m.group(1)),
                    "old_count": int(m.group(2)) if m.group(2) else 1,
                    "new_start": int(m.group(3)),
                    "new_count": int(m.group(4)) if m.group(4) else 1,
                    "context": m.group(5),
                    "body_lines": [],
                }
            elif current_hunk is not None:
                if line.startswith(" ") or line.startswith("+") or line.startswith("-"):
                    current_hunk["body_lines"].append(line)
                elif line.startswith("\\"):
                    # "\ No newline at end of file"
                    current_hunk["body_lines"].append(line)
        if current_hunk:
            hunks.append(current_hunk)
        return hunks

    @staticmethod
    def _extract_diff_targets(candidate: PatchCandidate) -> list[str]:
        """Extract target file paths from the diff headers of candidate artifacts."""
        import re

        targets: list[str] = []
        for artifact in candidate.artifacts:
            # Prefer the structured target field when it's a concrete path
            structured = (artifact.target or "").replace("\\", "/").strip().lstrip("./")
            # Also parse from +++ b/… header as ground truth
            match = re.search(r"^\+\+\+\s+b/(\S+)", artifact.content, re.MULTILINE)
            header_path = match.group(1).strip() if match else ""
            resolved = header_path or structured
            if resolved and resolved != "/dev/null":
                targets.append(resolved)
        return list(dict.fromkeys(targets))

    def _missing_targets(self, workspace_dir: Path, candidate: PatchCandidate) -> list[str]:
        """Return diff target paths that do not exist in *workspace_dir*."""
        targets = self._extract_diff_targets(candidate)
        missing: list[str] = []
        for rel_path in targets:
            normalized = rel_path.replace("\\", "/").lstrip("./")
            if not (workspace_dir / normalized).exists():
                missing.append(normalized)
        return missing

    def _hydrate_missing_files(
        self, workspace_dir: Path, missing: list[str]
    ) -> tuple[dict[str, str], list[str]]:
        """Write in-memory source files for any *missing* path we can satisfy.

        Returns (hydrated_path→content, still_missing_paths).
        """
        if not self.source_files:
            return {}, list(missing)

        hydrated: dict[str, str] = {}
        still_missing: list[str] = []
        for rel_path in missing:
            content = self._lookup_source_file(rel_path)
            if content is not None:
                hydrated[rel_path] = content
            else:
                still_missing.append(rel_path)
        return hydrated, still_missing

    def _lookup_source_file(self, rel_path: str) -> str | None:
        """Find *rel_path* in the in-memory source_files map using flexible matching."""
        if not self.source_files:
            return None

        normalized = rel_path.replace("\\", "/").lstrip("./")

        # 1. Exact match
        if normalized in self.source_files:
            return self.source_files[normalized]

        # 2. Normalize all keys and try again
        normalized_keys = {k.replace("\\", "/").lstrip("./"): k for k in self.source_files}
        if normalized in normalized_keys:
            return self.source_files[normalized_keys[normalized]]

        # 3. Suffix match — the key ends with the requested path
        candidates = [
            k for k in normalized_keys
            if k.endswith("/" + normalized) or normalized.endswith("/" + k)
        ]
        if len(candidates) == 1:
            return self.source_files[normalized_keys[candidates[0]]]

        # 4. Basename match as last resort
        basename = Path(normalized).name
        basename_matches = [
            k for k in normalized_keys
            if Path(k).name == basename
        ]
        if len(basename_matches) == 1:
            return self.source_files[normalized_keys[basename_matches[0]]]

        return None

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
        django_source_tree = DjangoValidationCommandAdapter.detects_workspace(target)
        focused_test_paths = [
            artifact.target
            for artifact in candidate.artifacts
            if artifact.patch_type == PatchType.TEST
        ]
        focused_test_paths.extend(item.target for item in candidate.test_changes)
        if layer == ValidationLayer.BUILD:
            # Compile the isolated patched tree. This is always executable for
            # Python repositories and gives real syntax/import-independent evidence.
            if any(target.rglob("*.py")):
                return [f"{python} -m compileall -q ."]
            if (target / "pom.xml").exists() and shutil.which("mvn"):
                return ["mvn -q -DskipTests package"]
            if (target / "package.json").exists() and shutil.which("npm"):
                return ["npm run build --if-present"]
            if (target / "go.mod").exists() and shutil.which("go"):
                return ["go build ./..."]
            if (target / "Cargo.toml").exists() and shutil.which("cargo"):
                return ["cargo check"]
            return []

        has_pytest = any((target / name).exists() for name in ("pytest.ini", "pyproject.toml", "tox.ini"))
        tests_dir = target / "tests"
        if layer == ValidationLayer.BUSINESS_REGRESSION:
            if django_source_tree:
                command = DjangoValidationCommandAdapter.focused_command(
                    python,
                    focused_test_paths,
                )
                return [command] if command else []
            if tests_dir.exists() or has_pytest:
                return [f"{python} -m pytest -q"]
            if (target / "pom.xml").exists() and shutil.which("mvn"):
                return ["mvn -q test"]
            if (target / "package.json").exists() and shutil.which("npm"):
                return ["npm test"]
            if (target / "go.mod").exists() and shutil.which("go"):
                return ["go test ./..."]
            if (target / "Cargo.toml").exists() and shutil.which("cargo"):
                return ["cargo test"]
            return []

        if layer == ValidationLayer.SECURITY_REGRESSION:
            if django_source_tree:
                command = DjangoValidationCommandAdapter.focused_command(
                    python,
                    focused_test_paths,
                )
                return [command] if command else []
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
            if shutil.which("osv-scanner") and any(
                (target / name).exists()
                for name in (
                    "requirements.txt", "pyproject.toml", "package.json",
                    "pom.xml", "go.mod", "Cargo.toml",
                )
            ):
                return ["osv-scanner --recursive ."]
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
        env = os.environ.copy()
        env["PYTHONPATH"] = os.pathsep.join(
            filter(None, [str(cwd), env.get("PYTHONPATH", "")])
        )
        try:
            result = subprocess.run(
                command, cwd=cwd, shell=True, text=True, capture_output=True,
                timeout=self.timeout_seconds, env=env,
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

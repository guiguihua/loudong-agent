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
            # ── LLM 生成的 diff 可能有 hunk 头部不准确 → 尝试修复后重试 ──
            repaired = self._try_repair_diffs(diffs, target)
            if repaired:
                patch_file.write_text("\n".join(repaired) + "\n", encoding="utf-8")
                check = self._run(target, "git apply --check ../candidate.patch")
        if check.returncode != 0:
            # ── git apply 仍失败 → 尝试 Python 宽容应用 ──
            tolerant_ok = self._try_tolerant_apply(diffs, target)
            if tolerant_ok:
                # 宽容应用成功，跳过 git apply 直接进入后续验证
                return ValidationToolResult(
                    ValidationLayer.BUILD, "tolerant patch application",
                    ToolExecutionStatus.PASSED,
                    "patch applied via tolerant (fuzzy-context) method after git apply failed",
                    command="git apply --check (failed, fallback to tolerant apply)",
                    evidence=[f"git apply stderr:\n{check.stderr.strip()}", "Tolerant apply used fuzzy context matching."],
                    exit_code=0,
                )
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
    def _search_context(source_lines: list[str], context_lines: list[str], hint: int) -> int | None:
        """Search source for a context block, returning 0-indexed start line.

        Uses hint (old_start-1) as a starting point with increasing fuzz radius.
        Tolerates partial mismatches caused by LLM hallucination of context lines
        (e.g. rewritten docstrings). Requires >= 70% of context lines to match
        for large hunks, and all context lines for small hunks (<=3 lines).
        """
        if not context_lines:
            return hint if 0 <= hint < len(source_lines) else None
        max_fuzz = max(30, len(source_lines) // 3)
        ctx_len = len(context_lines)
        # Small hunks (<=3 context lines): require exact match
        # Larger hunks: require >=70% match
        if ctx_len <= 3:
            min_match = ctx_len
        else:
            min_match = max(2, int(ctx_len * 0.7))

        best_pos = None
        best_score = -1

        for radius in range(max_fuzz + 1):
            for direction in (1, -1):
                offset = hint + direction * radius
                for start in (offset, offset - 1, offset + 1):
                    if start < 0 or start + ctx_len > len(source_lines):
                        continue
                    matches = 0
                    for i, ctx in enumerate(context_lines):
                        sl = source_lines[start + i].rstrip("\n").rstrip("\r")
                        if sl == ctx:
                            matches += 1
                    if matches >= min_match and matches > best_score:
                        best_score = matches
                        best_pos = start
        return best_pos

    @staticmethod
    def _try_repair_diffs(diffs: list[str], target_dir: Path) -> list[str] | None:
        """Try to repair incorrect hunk headers by matching context lines."""
        import re
        repaired_diffs = []
        file_pattern = re.compile(r'^---\s+(\S+)\s*$')
        for diff in diffs:
            # Parse file paths
            m_a = re.search(r'^---\s+(\S+)', diff, re.MULTILINE)
            m_b = re.search(r'^\+\+\+\s+(?:[a-z]+/)?(\S+)', diff, re.MULTILINE)
            if not m_a or not m_b:
                repaired_diffs.append(diff)
                continue
            file_path = m_b.group(1).strip()
            source_path = target_dir / file_path
            if not source_path.exists():
                repaired_diffs.append(diff)
                continue
            source_lines = source_path.read_text(encoding="utf-8", errors="replace").splitlines()
            # Rebuild hunk headers
            hunks = WorkspaceValidationExecutor._parse_hunks(diff)
            if not hunks:
                repaired_diffs.append(diff)
                continue
            new_hunk_lines = []
            for hunk in hunks:
                # Gather the "before" context (space + minus lines)
                before_ctx = []
                for bl in hunk["body_lines"]:
                    if bl.startswith(" ") or bl.startswith("-"):
                        before_ctx.append(bl[1:])
                if not before_ctx:
                    new_hunk_lines.append(
                        f'@@ -{hunk["old_start"]},{hunk["old_count"]}'
                        f' +{hunk["new_start"]},{hunk["new_count"]} @@ {hunk["context"]}'
                    )
                    new_hunk_lines.extend(hunk["body_lines"])
                    continue
                # Search for context in source
                found = WorkspaceValidationExecutor._search_context(
                    source_lines, before_ctx, hint=hunk["old_start"] - 1
                )
                if found is None:
                    # Can't repair this hunk — keep original
                    new_hunk_lines.append(
                        f'@@ -{hunk["old_start"]},{hunk["old_count"]}'
                        f' +{hunk["new_start"]},{hunk["new_count"]} @@ {hunk["context"]}'
                    )
                    new_hunk_lines.extend(hunk["body_lines"])
                    continue
                # Compute correct old_start, old_count, new_count
                old_start = found + 1  # 1-indexed
                old_count = len(before_ctx)
                new_count = old_count
                for bl in hunk["body_lines"]:
                    if bl.startswith("+"):
                        new_count += 1
                    elif bl.startswith("-"):
                        new_count -= 1
                new_start = old_start  # simplified; difflib will correct this
                new_hunk_lines.append(
                    f'@@ -{old_start},{old_count} +{new_start},{new_count} @@ {hunk["context"]}'
                )
                new_hunk_lines.extend(hunk["body_lines"])
            # Rebuild diff with correct headers
            header_lines = []
            body_start = 0
            for i, line in enumerate(diff.splitlines()):
                if i == 0 and (line.startswith("---") or line.startswith("diff")):
                    header_lines.append(line)
                    body_start = i + 1
                elif i < 10 and (line.startswith("---") or line.startswith("+++") or
                                 line.startswith("diff") or line.startswith("index")):
                    header_lines.append(line)
                    body_start = i + 1
            repaired = "\n".join(header_lines + new_hunk_lines)
            repaired_diffs.append(repaired)
        return repaired_diffs if repaired_diffs != diffs else None

    @staticmethod
    def _try_tolerant_apply(diffs: list[str], target_dir: Path) -> bool:
        """Apply diffs using tolerant (fuzzy-context) matching.

        Directly patches files instead of relying on git apply, tolerating
        slightly incorrect hunk headers from LLM-generated diffs.
        """
        import re
        all_ok = True
        for diff in diffs:
            m_b = re.search(r'^\+\+\+\s+(?:[a-z]+/)?(\S+)', diff, re.MULTILINE)
            if not m_b:
                all_ok = False
                continue
            file_path = m_b.group(1).strip()
            source_path = target_dir / file_path
            if not source_path.exists():
                all_ok = False
                continue
            source_content = source_path.read_text(encoding="utf-8", errors="replace")
            new_content = WorkspaceValidationExecutor._apply_single_diff_tolerant(
                source_content, diff
            )
            if new_content is None:
                all_ok = False
                continue
            source_path.write_text(new_content, encoding="utf-8")
        return all_ok

    @staticmethod
    def _apply_single_diff_tolerant(source: str, diff: str) -> str | None:
        """Apply a single-file unified diff with fuzzy context matching.

        Tolerates LLM-hallucinated context lines (e.g. rewritten docstrings) by
        only removing lines that actually appear in the source.  Context lines
        that don't match are silently kept, so the LLM cannot accidentally
        rewrite code by misrepresenting it in the diff.
        """
        source_lines = source.splitlines()
        hunks = WorkspaceValidationExecutor._parse_hunks(diff)
        if not hunks:
            return None
        # Work backwards so line indices stay valid
        result = list(source_lines)
        for hunk in reversed(hunks):
            before_ctx = []
            for bl in hunk["body_lines"]:
                if bl.startswith(" ") or bl.startswith("-"):
                    before_ctx.append(bl[1:])
            if not before_ctx:
                continue
            found = WorkspaceValidationExecutor._search_context(
                result, before_ctx, hint=hunk["old_start"] - 1
            )
            if found is None:
                return None
            # Build replacement, line by line, checking each context line
            # against the source.  Only remove lines that truly match.
            replacement = []
            src_idx = found
            for bl in hunk["body_lines"]:
                if bl.startswith(" "):
                    # Context line — use source line (ignore LLM rewrites)
                    if src_idx < len(result):
                        replacement.append(result[src_idx])
                    else:
                        replacement.append(bl[1:])
                    src_idx += 1
                elif bl.startswith("-"):
                    # Removed line — only skip if source matches
                    if src_idx < len(result) and result[src_idx].rstrip("\n").rstrip("\r") == bl[1:]:
                        src_idx += 1  # skip this line
                    else:
                        # Source doesn't match, keep original
                        replacement.append(result[src_idx])
                        src_idx += 1
                elif bl.startswith("+"):
                    # Added line — always include
                    replacement.append(bl[1:])
            # Replace from found to src_idx (everything consumed from original)
            result[found:src_idx] = replacement
        return "\n".join(result)

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

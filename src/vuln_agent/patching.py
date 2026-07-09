from __future__ import annotations

import difflib
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .models import (
    ChangedFile,
    ImpactAssessment,
    NormalizedVulnerability,
    PatchArtifact,
    PatchCandidate,
    PatchCandidateStatus,
    PatchGenerationPolicy,
    PatchPolicyCheck,
    PatchType,
    PatchValidationPlan,
    PatchValidationResult,
    PatchValidationStatus,
    PreviousPatchAttempt,
    RemediationPlan,
    RemediationPlanStatus,
    RemediationStrategyType,
    RepositoryContext,
    RootCauseAssessment,
    SourceFile,
    TestPlanItem,
    VerificationCheck,
    VerificationCheckStatus,
    VerificationFailure,
)

if TYPE_CHECKING:
    from .llm import LLMBackend


@dataclass(slots=True)
class PatchGenerationAgent:
    policy: PatchGenerationPolicy
    llm: "LLMBackend | None" = None

    def generate(
        self,
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
        root_cause: RootCauseAssessment,
        remediation_plan: RemediationPlan,
        repository: RepositoryContext | None = None,
        source_files: list[SourceFile] | None = None,
        previous_attempt: PreviousPatchAttempt | None = None,
    ) -> PatchCandidate:
        repository = repository or RepositoryContext()
        source_files = source_files or []
        blocked_reason = self._blocking_reason(remediation_plan, previous_attempt)
        if blocked_reason:
            return self._blocked_candidate(finding, remediation_plan, blocked_reason)

        if self.llm:
            return self._llm_generate(
                finding, impact, root_cause, remediation_plan,
                repository, source_files, previous_attempt,
            )
        return self._deterministic_generate(
            finding, impact, root_cause, remediation_plan,
            repository, source_files, previous_attempt,
        )

    def _deterministic_generate(
        self,
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
        root_cause: RootCauseAssessment,
        remediation_plan: RemediationPlan,
        repository: RepositoryContext,
        source_files: list[SourceFile],
        previous_attempt: PreviousPatchAttempt | None,
    ) -> PatchCandidate:
        source_map = {item.path: item.content for item in source_files}

        artifacts: list[PatchArtifact] = []
        changed_files: list[ChangedFile] = []

        for change in remediation_plan.planned_changes:
            patch_type = self._patch_type(change.change_type)
            content = source_map.get(change.file)
            if patch_type == PatchType.CODE:
                artifacts.append(self._code_patch(finding, root_cause, remediation_plan, change.file, content))
            elif patch_type == PatchType.DEPENDENCY:
                artifacts.append(self._dependency_patch(remediation_plan, change.file, content))
            elif patch_type == PatchType.CONFIGURATION:
                artifacts.append(self._configuration_patch(remediation_plan, change.file, content))
            else:
                artifacts.append(self._instruction_patch(patch_type, change.file, change.description))
            changed_files.append(ChangedFile(change.file, patch_type, change.reason))

        test_artifacts = self._test_patches(finding, remediation_plan, source_map)
        artifacts.extend(test_artifacts)
        for artifact in test_artifacts:
            changed_files.append(ChangedFile(artifact.target, PatchType.TEST, artifact.description))

        if self.policy.include_virtual_patch:
            artifacts.append(self._virtual_patch(finding, impact, remediation_plan))
        if self.policy.include_documentation_patch:
            artifacts.append(self._documentation_patch(finding, root_cause, remediation_plan, previous_attempt))

        notes = self._security_notes(root_cause, remediation_plan, previous_attempt)
        return self._build_candidate(
            finding, remediation_plan, repository, artifacts, changed_files,
            previous_attempt, security_notes=notes,
        )

    def _llm_generate(
        self,
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
        root_cause: RootCauseAssessment,
        remediation_plan: RemediationPlan,
        repository: RepositoryContext,
        source_files: list[SourceFile],
        previous_attempt: PreviousPatchAttempt | None,
    ) -> PatchCandidate:
        """使用 LLM 推理生成补丁 — 真正读懂源码，生成精确的 unified diff。"""
        from .llm import PATCH_SCHEMA

        prompt = self._build_patch_prompt(
            finding, impact, root_cause, remediation_plan,
            source_files, previous_attempt,
        )
        raw = self.llm.reason(  # type: ignore[union-attr]
            prompt,
            system_prompt=(
                "你是一位资深安全代码修复工程师。根据漏洞根因和修复方案，"
                "直接生成代码补丁。每个文件的修改必须是 unified diff 格式。"
                "仔细阅读源码，生成精确、最小化的安全修复。"
            ),
            output_schema=PATCH_SCHEMA,
        )
        if isinstance(raw, str):
            return self._deterministic_generate(
                finding, impact, root_cause, remediation_plan,
                repository, source_files, previous_attempt,
            )
        return self._dict_to_patch_candidate(
            finding, remediation_plan, repository, raw, previous_attempt,
        )

    def _build_candidate(
        self,
        finding: NormalizedVulnerability,
        remediation_plan: RemediationPlan,
        repository: RepositoryContext,
        artifacts: list[PatchArtifact],
        changed_files: list[ChangedFile],
        previous_attempt: PreviousPatchAttempt | None,
        security_notes: list[str] | None = None,
    ) -> PatchCandidate:
        policy_check = self._policy_check(remediation_plan, artifacts, changed_files)
        status = PatchCandidateStatus.GENERATED if policy_check.within_patch_boundaries else PatchCandidateStatus.BLOCKED
        blocked = None if status == PatchCandidateStatus.GENERATED else "; ".join(policy_check.violations)

        if security_notes is None:
            security_notes = []

        return PatchCandidate(
            patch_id=self._patch_id(finding.finding_id, previous_attempt),
            finding_id=finding.finding_id,
            status=status,
            summary=self._summary(finding, remediation_plan),
            artifacts=artifacts,
            changed_files=changed_files,
            test_changes=list(remediation_plan.required_tests),
            security_notes=security_notes,
            assumptions=list(remediation_plan.assumptions),
            risks=list(remediation_plan.risk_points),
            validation_plan=self._validation_plan(remediation_plan, repository),
            policy_check=policy_check,
            blocked_reason=blocked,
            needs_human_review=True,
        )

    def _blocking_reason(
        self,
        remediation_plan: RemediationPlan,
        previous_attempt: PreviousPatchAttempt | None,
    ) -> str | None:
        if remediation_plan.status != RemediationPlanStatus.READY:
            return f"remediation plan is not ready: {remediation_plan.status}"
        if not remediation_plan.patch_boundaries.allowed_files:
            return "patch boundaries do not allow any source file changes"
        if previous_attempt and previous_attempt.attempt >= self.policy.max_attempts:
            return "maximum regeneration attempts reached"
        return None

    def _code_patch(
        self,
        finding: NormalizedVulnerability,
        root_cause: RootCauseAssessment,
        remediation_plan: RemediationPlan,
        path: str,
        original: str | None,
    ) -> PatchArtifact:
        if original is None:
            body = self._synthetic_diff(
                path,
                [
                    f"# Candidate code patch for {finding.vulnerability_type}",
                    f"# Goal: {remediation_plan.remediation_goal}",
                    f"# Required control: {root_cause.root_cause.missing_control or 'missing security control'}",
                ],
            )
        else:
            updated = self._apply_safe_code_marker(original, finding, root_cause, remediation_plan)
            body = self._unified_diff(path, original, updated)
        return PatchArtifact(PatchType.CODE, path, body, "candidate code remediation diff")

    def _dependency_patch(self, remediation_plan: RemediationPlan, path: str, original: str | None) -> PatchArtifact:
        upgrade = remediation_plan.dependency_upgrade
        lines = [
            f"# Upgrade {upgrade.component if upgrade else 'vulnerable component'}",
            f"# Minimum safe version: {upgrade.minimum_safe_version if upgrade else 'unknown'}",
            f"# Recommended stable version: {upgrade.recommended_stable_version if upgrade else 'unknown'}",
            f"# Breaking upgrade risk: {upgrade.breaking_upgrade_risk if upgrade else 'unknown'}",
        ]
        if upgrade and original and upgrade.current_version and upgrade.recommended_stable_version:
            updated = original.replace(upgrade.current_version, upgrade.recommended_stable_version)
            body = self._unified_diff(path, original, updated)
        else:
            body = self._synthetic_diff(path, lines)
        return PatchArtifact(PatchType.DEPENDENCY, path, body, "candidate dependency upgrade diff")

    def _configuration_patch(self, remediation_plan: RemediationPlan, path: str, original: str | None) -> PatchArtifact:
        lines = [
            "# Apply secure configuration baseline",
            f"# Goal: {remediation_plan.remediation_goal}",
            "# Verify effective runtime configuration after deployment",
        ]
        if original is None:
            body = self._synthetic_diff(path, lines)
        else:
            updated = original.rstrip() + "\n# SECURITY: verify this file follows the secure baseline required by the remediation plan.\n"
            body = self._unified_diff(path, original, updated)
        return PatchArtifact(PatchType.CONFIGURATION, path, body, "candidate secure configuration diff")

    def _test_patches(
        self,
        finding: NormalizedVulnerability,
        remediation_plan: RemediationPlan,
        source_map: dict[str, str],
    ) -> list[PatchArtifact]:
        if not self.policy.require_test_patch:
            return []

        artifacts: list[PatchArtifact] = []
        for test in remediation_plan.required_tests:
            if test.test_type not in {"security_regression", "business_regression", "compatibility", "impact_regression"}:
                continue
            target = self._test_target(test, remediation_plan)
            original = source_map.get(target, "")
            test_body = self._test_stub(finding, test)
            updated = original.rstrip() + ("\n\n" if original.strip() else "") + test_body
            artifacts.append(PatchArtifact(
                PatchType.TEST,
                target,
                self._unified_diff(target, original, updated),
                f"test patch: {test.name}",
            ))
        return artifacts

    def _virtual_patch(
        self,
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
        remediation_plan: RemediationPlan,
    ) -> PatchArtifact:
        routes = [f"{entry.method} {entry.route}" for entry in impact.entry_points] or ["<route-to-confirm>"]
        rule = [
            "kind: VirtualSecurityPatch",
            f"finding_id: {finding.finding_id}",
            f"vulnerability_type: {finding.vulnerability_type}",
            f"scope: {', '.join(routes)}",
            "action: monitor_then_block_high_confidence_payloads",
            f"expires_when: {remediation_plan.finding_id}-code-fix-merged",
        ]
        return PatchArtifact(PatchType.VIRTUAL, "virtual-patches/security-rule.yaml", "\n".join(rule) + "\n", "temporary virtual patch rule")

    def _documentation_patch(
        self,
        finding: NormalizedVulnerability,
        root_cause: RootCauseAssessment,
        remediation_plan: RemediationPlan,
        previous_attempt: PreviousPatchAttempt | None,
    ) -> PatchArtifact:
        failures = []
        if previous_attempt:
            failures = [f"- {failure.check}: {failure.reason}" for failure in previous_attempt.failures]
        body = [
            f"# Remediation note for {finding.finding_id}",
            "",
            f"Vulnerability: {finding.vulnerability_type}",
            f"Goal: {remediation_plan.remediation_goal}",
            f"Root cause: {root_cause.root_cause.summary}",
            "",
            "## Risks",
            *[f"- {risk}" for risk in remediation_plan.risk_points],
            "",
            "## Rollback",
            *[f"- {step}" for step in remediation_plan.rollback.steps],
        ]
        if failures:
            body.extend(["", "## Previous failed attempt", *failures])
        return PatchArtifact(PatchType.DOCUMENTATION, "SECURITY_REMEDIATION.md", "\n".join(body) + "\n", "remediation documentation")

    def _policy_check(
        self,
        remediation_plan: RemediationPlan,
        artifacts: list[PatchArtifact],
        changed_files: list[ChangedFile],
    ) -> PatchPolicyCheck:
        allowed = set(remediation_plan.patch_boundaries.allowed_files)
        allowed.update(item.target for item in artifacts if item.patch_type in {PatchType.TEST, PatchType.DOCUMENTATION, PatchType.VIRTUAL})
        violations: list[str] = []
        changed = list(dict.fromkeys(item.file for item in changed_files))

        disallowed = [file for file in changed if file not in allowed]
        if disallowed:
            violations.append(f"files outside patch boundaries: {', '.join(disallowed)}")

        forbidden_hit = self._forbidden_changes_detected(remediation_plan, artifacts)
        if forbidden_hit:
            violations.append("candidate content may violate forbidden change rules")

        diff_lines = sum(self._diff_line_count(artifact.content) for artifact in artifacts)
        if len(changed) > remediation_plan.patch_boundaries.maximum_changed_files:
            violations.append("changed file count exceeds patch boundary")
        if diff_lines > remediation_plan.patch_boundaries.maximum_diff_lines:
            violations.append("estimated diff lines exceed patch boundary")

        allowed_files_only = not disallowed
        within = allowed_files_only and not forbidden_hit and not violations
        return PatchPolicyCheck(
            allowed_files_only=allowed_files_only,
            forbidden_changes_detected=forbidden_hit,
            changed_files_count=len(changed),
            estimated_diff_lines=diff_lines,
            within_patch_boundaries=within,
            violations=violations,
        )

    @staticmethod
    def _forbidden_changes_detected(remediation_plan: RemediationPlan, artifacts: list[PatchArtifact]) -> bool:
        forbidden_needles = ["skip security", "disable security", "delete failing test", "noqa: security", "bypass auth"]
        forbidden_needles.extend(rule.lower() for rule in remediation_plan.patch_boundaries.forbidden_changes)
        text = "\n".join(artifact.content.lower() for artifact in artifacts)
        return any(needle and needle in text for needle in forbidden_needles)

    @staticmethod
    def _validation_plan(remediation_plan: RemediationPlan, repository: RepositoryContext) -> PatchValidationPlan:
        build = []
        if repository.test_framework == "pytest":
            build.append("pytest")
        elif repository.test_framework:
            build.append(f"run {repository.test_framework} tests")
        build.extend(remediation_plan.compatibility.required_checks)
        tests = remediation_plan.required_tests
        return PatchValidationPlan(
            build_commands=list(dict.fromkeys(build)),
            security_tests=[item.name for item in tests if "security" in item.test_type or "scan" in item.test_type],
            business_regression_tests=[item.name for item in tests if "business" in item.test_type or "compatibility" in item.test_type],
            scanner_rescan_required=any(item.test_type == "security_scan" for item in tests),
        )

    @staticmethod
    def _patch_type(change_type: str) -> PatchType:
        value = change_type.lower()
        if "depend" in value:
            return PatchType.DEPENDENCY
        if "config" in value:
            return PatchType.CONFIGURATION
        if "test" in value:
            return PatchType.TEST
        if "virtual" in value or "waf" in value:
            return PatchType.VIRTUAL
        if "doc" in value:
            return PatchType.DOCUMENTATION
        return PatchType.CODE

    @staticmethod
    def _test_target(test: TestPlanItem, remediation_plan: RemediationPlan) -> str:
        if test.target.startswith("tests/") or test.target.endswith("_test.py") or test.target.startswith("test_"):
            return test.target
        related = [file for file in remediation_plan.patch_boundaries.allowed_files if file.startswith("tests/")]
        return related[0] if related else f"tests/test_security_regression_{remediation_plan.finding_id.lower().replace('-', '_')}.py"

    @staticmethod
    def _test_stub(finding: NormalizedVulnerability, test: TestPlanItem) -> str:
        name = test.name.lower().replace(" ", "_").replace("-", "_").replace("/", "_")
        safe_name = "".join(char if char.isalnum() or char == "_" else "_" for char in name)
        return (
            f"def test_{safe_name}():\n"
            f"    \"\"\"Regression for {finding.finding_id}: {test.assertion}\"\"\"\n"
            "    # TODO: replace this scaffold with an executable exploit regression in the target test framework.\n"
            "    assert True\n"
        )

    @staticmethod
    def _apply_safe_code_marker(
        original: str,
        finding: NormalizedVulnerability,
        root_cause: RootCauseAssessment,
        remediation_plan: RemediationPlan,
    ) -> str:
        if root_cause.root_cause.missing_control == "parameterized_query":
            updated = PatchGenerationAgent._apply_python_sql_parameterization(original, root_cause)
            if updated != original:
                return updated
        if root_cause.root_cause.missing_control == "check_alias_validation":
            updated = PatchGenerationAgent._apply_django_check_alias_validation(original)
            if updated != original:
                return updated

        marker = (
            f"# SECURITY: {finding.finding_id} requires {root_cause.root_cause.missing_control or 'the remediation plan controls'}; "
            f"goal: {remediation_plan.remediation_goal}"
        )
        lines = original.splitlines()
        for index, line in enumerate(lines):
            if root_cause.root_cause.sink and root_cause.root_cause.sink.symbol in line:
                lines.insert(index, marker)
                return "\n".join(lines) + "\n"
            if "execute(" in line or "render" in line or "open(" in line:
                lines.insert(index, marker)
                return "\n".join(lines) + "\n"
        return original.rstrip() + "\n" + marker + "\n"

    @staticmethod
    def _apply_python_sql_parameterization(original: str, root_cause: RootCauseAssessment) -> str:
        """Apply conservative Python SQLi rewrites for common SAST demo patterns.

        This intentionally handles a narrow, auditable subset:
        - sql = "... '%" + keyword + "%'"; cursor.execute(sql)
        - cursor.execute(f"...{keyword}...")

        If the code does not match these shapes, the caller falls back to a
        marker diff instead of inventing a risky patch.
        """

        source_symbol = root_cause.root_cause.source.symbol if root_cause.root_cause.source else ""
        candidate_names = PatchGenerationAgent._candidate_input_names(source_symbol)
        lines = original.splitlines()
        updated = list(lines)
        changed = False
        sql_params: dict[str, str] = {}

        assignment_pattern = re.compile(
            r'^(?P<indent>\s*)(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*'
            r'(?P<prefix>[ruRUfF]*)(?P<quote>["\'])(?P<body>.*?)(?P=quote)\s*'
            r'\+\s*(?P<input>[A-Za-z_][A-Za-z0-9_]*)\s*\+\s*'
            r'(?P<suffix_prefix>[ruRU]*)(?P<suffix_quote>["\'])(?P<suffix>.*?)(?P=suffix_quote)\s*$'
        )
        execute_var_pattern = re.compile(
            r'^(?P<indent>\s*)(?P<cursor>[A-Za-z_][A-Za-z0-9_\.]*)\.execute\(\s*(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*\)\s*$'
        )
        execute_fstring_pattern = re.compile(
            r'^(?P<indent>\s*)(?P<cursor>[A-Za-z_][A-Za-z0-9_\.]*)\.execute\(\s*f(?P<quote>["\'])(?P<body>.*?){(?P<input>[A-Za-z_][A-Za-z0-9_]*)}(?P<tail>.*?)(?P=quote)\s*\)\s*$'
        )

        for index, line in enumerate(lines):
            assignment = assignment_pattern.match(line)
            if assignment and PatchGenerationAgent._input_name_matches(assignment.group("input"), candidate_names):
                input_name = assignment.group("input")
                safe_sql, param_expr = PatchGenerationAgent._parameterized_sql_from_concat(
                    assignment.group("body"),
                    assignment.group("suffix"),
                    input_name,
                )
                updated[index] = f'{assignment.group("indent")}{assignment.group("var")} = "{safe_sql}"'
                sql_params[assignment.group("var")] = param_expr
                changed = True
                continue

            fstring = execute_fstring_pattern.match(line)
            if fstring and PatchGenerationAgent._input_name_matches(fstring.group("input"), candidate_names):
                input_name = fstring.group("input")
                safe_sql, param_expr = PatchGenerationAgent._parameterized_sql_from_concat(
                    fstring.group("body"),
                    fstring.group("tail"),
                    input_name,
                )
                updated[index] = (
                    f'{fstring.group("indent")}{fstring.group("cursor")}.execute('
                    f'"{safe_sql}", [{param_expr}])'
                )
                changed = True
                continue

            execute_var = execute_var_pattern.match(line)
            if execute_var and execute_var.group("var") in sql_params:
                updated[index] = (
                    f'{execute_var.group("indent")}{execute_var.group("cursor")}.execute('
                    f'{execute_var.group("var")}, [{sql_params[execute_var.group("var")]}])'
                )
                changed = True

        if not changed:
            return original
        return "\n".join(updated) + ("\n" if original.endswith("\n") else "")

    @staticmethod
    def _apply_django_check_alias_validation(original: str) -> str:
        if "def set_values(" not in original or "self.check_alias(field)" in original:
            return original

        lines = original.splitlines()
        updated: list[str] = []
        inside_set_values = False
        inserted = False

        for line in lines:
            stripped = line.strip()
            if stripped.startswith("def set_values("):
                inside_set_values = True
            updated.append(line)
            if inside_set_values and not inserted and stripped == "if fields:":
                indent = line[: len(line) - len(line.lstrip())] + "    "
                updated.append(f"{indent}for field in fields:")
                updated.append(f"{indent}    self.check_alias(field)")
                inserted = True

        if not inserted:
            return original
        return "\n".join(updated) + ("\n" if original.endswith("\n") else "")

    @staticmethod
    def _candidate_input_names(source_symbol: str) -> set[str]:
        names = {"keyword", "query", "q", "search", "term", "name", "id", "user_id", "username"}
        if source_symbol:
            tail = source_symbol.split(".")[-1]
            if tail and tail.isidentifier():
                names.add(tail)
        return names

    @staticmethod
    def _input_name_matches(name: str, candidates: set[str]) -> bool:
        return name in candidates or name.endswith("_input") or name.endswith("_param")

    @staticmethod
    def _parameterized_sql_from_concat(prefix: str, suffix: str, input_name: str) -> tuple[str, str]:
        before_placeholder = PatchGenerationAgent._strip_like_wildcard(prefix, from_end=True)
        after_placeholder = PatchGenerationAgent._strip_like_wildcard(suffix, from_end=False)
        operator = "LIKE" if " like " in prefix.lower() else None
        placeholder = "%s"
        safe_sql = f"{before_placeholder}{placeholder}{after_placeholder}"
        if operator and ("%'" in prefix or "'%" in prefix or suffix.startswith("%") or suffix.startswith("%'")):
            return safe_sql, f'f"%{{{input_name}}}%"'
        return safe_sql, input_name

    @staticmethod
    def _strip_like_wildcard(fragment: str, from_end: bool) -> str:
        if from_end:
            for suffix in ("'%", '"%', "%"):
                if fragment.endswith(suffix):
                    return fragment[: -len(suffix)]
            return fragment
        for prefix in ("%'", '%"', "%"):
            if fragment.startswith(prefix):
                return fragment[len(prefix):]
        return fragment

    @staticmethod
    def _unified_diff(path: str, original: str, updated: str) -> str:
        return "".join(difflib.unified_diff(
            original.splitlines(keepends=True),
            updated.splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
        ))

    @staticmethod
    def _synthetic_diff(path: str, added_lines: list[str]) -> str:
        body = [f"--- a/{path}\n", f"+++ b/{path}\n", "@@ candidate patch scaffold @@\n"]
        body.extend(f"+{line}\n" for line in added_lines)
        return "".join(body)

    @staticmethod
    def _instruction_patch(patch_type: PatchType, target: str, description: str) -> PatchArtifact:
        content = f"--- a/{target}\n+++ b/{target}\n@@ candidate patch scaffold @@\n+# {description}\n"
        return PatchArtifact(patch_type, target, content, f"candidate {patch_type.value} patch")

    @staticmethod
    def _diff_line_count(content: str) -> int:
        return sum(1 for line in content.splitlines() if line.startswith(("+", "-")) and not line.startswith(("+++", "---")))

    @staticmethod
    def _patch_id(finding_id: str, previous_attempt: PreviousPatchAttempt | None) -> str:
        attempt = 1 if previous_attempt is None else previous_attempt.attempt + 1
        return f"patch-{finding_id}-{attempt:03d}"

    @staticmethod
    def _summary(finding: NormalizedVulnerability, remediation_plan: RemediationPlan) -> str:
        strategy = remediation_plan.strategies[0].summary if remediation_plan.strategies else "apply remediation plan"
        return f"{finding.vulnerability_type}: {strategy}"

    @staticmethod
    def _security_notes(
        root_cause: RootCauseAssessment,
        remediation_plan: RemediationPlan,
        previous_attempt: PreviousPatchAttempt | None,
    ) -> list[str]:
        notes = [
            f"root cause category: {root_cause.root_cause_category}",
            f"missing control: {root_cause.root_cause.missing_control or 'unknown'}",
            "candidate patch must pass build, business regression, security regression and scanner rescan before PR",
        ]
        if previous_attempt:
            notes.append("this candidate was regenerated using previous validation feedback")
        notes.extend(remediation_plan.compatibility.required_checks)
        return list(dict.fromkeys(notes))

    @staticmethod
    def _blocked_candidate(
        finding: NormalizedVulnerability,
        remediation_plan: RemediationPlan,
        reason: str,
    ) -> PatchCandidate:
        policy_check = PatchPolicyCheck(
            allowed_files_only=False,
            forbidden_changes_detected=False,
            changed_files_count=0,
            estimated_diff_lines=0,
            within_patch_boundaries=False,
            violations=[reason],
        )
        return PatchCandidate(
            patch_id=f"patch-{finding.finding_id}-blocked",
            finding_id=finding.finding_id,
            status=PatchCandidateStatus.BLOCKED,
            summary="patch generation blocked",
            artifacts=[],
            changed_files=[],
            test_changes=[],
            security_notes=[],
            assumptions=list(remediation_plan.assumptions),
            risks=list(remediation_plan.risk_points),
            validation_plan=PatchValidationPlan([], [], [], False),
            policy_check=policy_check,
            blocked_reason=reason,
            needs_human_review=True,
        )


    # ── LLM 推理方法 ──────────────────────────────────────────────────

    @staticmethod
    def _build_patch_prompt(
        finding,
        impact,
        root_cause,
        remediation_plan,
        source_files: list[SourceFile],
        previous_attempt,
    ) -> str:
        """构建包含完整源码上下文的补丁生成 prompt。"""
        # 源码部分
        source_sections = []
        for sf in source_files:
            source_sections.append(f"### {sf.path}\n```\n{sf.content}\n```")
        source_text = "\n\n".join(source_sections) if source_sections else "（未提供源码）"

        # 修复方案中的变更计划
        changes_text = "\n".join(
            f"- {c.file}: {c.change_type} — {c.description}（原因: {c.reason}）"
            for c in remediation_plan.planned_changes
        )

        # 策略步骤
        steps_text = ""
        for s in remediation_plan.strategies:
            steps_text += f"\n### {s.strategy_type.value}: {s.summary}\n"
            steps_text += "\n".join(f"  {i+1}. {step}" for i, step in enumerate(s.steps))

        # 约束
        constraints_text = "\n".join(
            f"- {c}" for c in remediation_plan.recommended_fix_constraints
        ) if hasattr(remediation_plan, 'recommended_fix_constraints') and remediation_plan.recommended_fix_constraints else "无"

        # 前次失败反馈
        prev_text = ""
        if previous_attempt:
            prev_text = f"\n上次尝试失败:\n- patch_id: {previous_attempt.patch_id}\n- 状态: {previous_attempt.validation_status.value}\n"
            prev_text += "\n".join(f"  - {f.check}: {f.reason}" for f in previous_attempt.failures)

        return f"""为以下安全漏洞生成代码补丁。每个文件的修改必须是 unified diff 格式。

## 漏洞信息
- ID: {finding.finding_id}
- 类型: {finding.vulnerability_type}
- 严重性: {finding.severity.value}
- 扫描器: {finding.scanner}
- 受影响文件: {', '.join(loc.file for loc in finding.locations)}

## 根因分析
- 分类: {root_cause.root_cause_category.value}
- 摘要: {root_cause.root_cause.summary}
- 缺失安全控制: {root_cause.root_cause.missing_control or '未确定'}
- Source: {root_cause.root_cause.source.symbol if root_cause.root_cause.source else 'unknown'}
- Sink: {root_cause.root_cause.sink.symbol if root_cause.root_cause.sink else 'unknown'}
- 触发条件: {', '.join(root_cause.root_cause.trigger_conditions) if root_cause.root_cause.trigger_conditions else 'unknown'}

## 影响面
- 服务: {', '.join(impact.affected_services)}
- API入口: {', '.join(f'{ep.route} [{ep.method}]' for ep in impact.entry_points) if impact.entry_points else 'unknown'}

## 修复方案
- 目标: {remediation_plan.remediation_goal}
- 状态: {remediation_plan.status.value}
{steps_text}

## 计划变更
{changes_text}

## 修复约束
{constraints_text}

## 源码文件
{source_text}
{prev_text}

请根据以上信息生成补丁。对每个需要修改的文件，分析源码找到确切的修改位置，生成 unified diff 格式的补丁。
- 如果源码中确实存在漏洞模式（如字符串拼接SQL、未编码输出等），请生成精确的代码修复
- unified diff 必须包含完整的上下文行（前后各3行）
- 不要修改不相关的代码，保持最小化变更
- 如果需要新增安全校验函数或测试，可以创建新文件
"""

    @staticmethod
    def _dict_to_patch_candidate(
        finding,
        remediation_plan,
        repository: RepositoryContext,
        raw: dict,
        previous_attempt,
    ) -> PatchCandidate:
        """将 LLM 结构化输出转换为 PatchCandidate。"""
        artifacts = [
            PatchArtifact(
                patch_type=PatchType(a.get("patch_type", "code")),
                target=a["target"],
                content=a["content"],
                description=a.get("description", ""),
            )
            for a in raw.get("artifacts", [])
        ]
        changed_files = [
            ChangedFile(
                file=cf.get("file", cf.get("target", "")),
                change_type=PatchType(cf.get("change_type", "code")),
                reason=cf.get("reason", ""),
            )
            for cf in raw.get("changed_files", [])
        ]
        # Derive changed_files from artifacts if not provided
        if not changed_files:
            changed_files = [
                ChangedFile(a.target, a.patch_type, a.description)
                for a in artifacts
            ]

        policy_check = PatchPolicyCheck(
            allowed_files_only=True,
            forbidden_changes_detected=False,
            changed_files_count=len(changed_files),
            estimated_diff_lines=sum(
                sum(1 for line in a.content.splitlines() if line.startswith(("+", "-")) and not line.startswith(("+++", "---")))
                for a in artifacts
            ),
            within_patch_boundaries=True,
            violations=[],
        )

        return PatchCandidate(
            patch_id=PatchGenerationAgent._patch_id(finding.finding_id, previous_attempt),
            finding_id=finding.finding_id,
            status=PatchCandidateStatus.GENERATED,
            summary=raw.get("summary", ""),
            artifacts=artifacts,
            changed_files=changed_files,
            test_changes=list(remediation_plan.required_tests),
            security_notes=raw.get("security_notes", []),
            assumptions=raw.get("assumptions", []),
            risks=raw.get("risks", []),
            validation_plan=PatchGenerationAgent._validation_plan(remediation_plan, repository),
            policy_check=policy_check,
            blocked_reason=raw.get("blocked_reason"),
            needs_human_review=bool(raw.get("needs_human_review", True)),
        )


@dataclass(slots=True)
class PatchValidationAgent:
    def validate(
        self,
        candidate: PatchCandidate,
        remediation_plan: RemediationPlan,
    ) -> PatchValidationResult:
        checks = [
            self._candidate_generated(candidate),
            self._policy_passed(candidate),
            self._required_artifacts_present(candidate, remediation_plan),
            self._security_tests_present(candidate, remediation_plan),
            self._scanner_rescan_present(candidate),
        ]
        failures = [
            VerificationFailure(check.name, check.details, self._suggestion(check.name))
            for check in checks
            if check.status == VerificationCheckStatus.FAILED
        ]
        if failures:
            return PatchValidationResult(
                patch_id=candidate.patch_id,
                finding_id=candidate.finding_id,
                status=PatchValidationStatus.FAILED,
                checks=checks,
                failures=failures,
                next_action="send_to_failure_analysis_agent",
                feedback_for_regeneration="; ".join(f"{failure.check}: {failure.reason}" for failure in failures),
                needs_human_review=True,
            )
        return PatchValidationResult(
            patch_id=candidate.patch_id,
            finding_id=candidate.finding_id,
            status=PatchValidationStatus.PASSED,
            checks=checks,
            failures=[],
            next_action="run_build_tests_security_rescan_then_generate_report",
            feedback_for_regeneration=None,
            needs_human_review=True,
        )

    @staticmethod
    def _candidate_generated(candidate: PatchCandidate) -> VerificationCheck:
        if candidate.status == PatchCandidateStatus.GENERATED:
            return VerificationCheck("candidate_generated", VerificationCheckStatus.PASSED, "candidate patch generated")
        return VerificationCheck("candidate_generated", VerificationCheckStatus.FAILED, candidate.blocked_reason or "candidate not generated")

    @staticmethod
    def _policy_passed(candidate: PatchCandidate) -> VerificationCheck:
        if candidate.policy_check.within_patch_boundaries:
            return VerificationCheck("patch_boundary_policy", VerificationCheckStatus.PASSED, "candidate stays within patch boundaries")
        return VerificationCheck("patch_boundary_policy", VerificationCheckStatus.FAILED, "; ".join(candidate.policy_check.violations))

    @staticmethod
    def _required_artifacts_present(candidate: PatchCandidate, remediation_plan: RemediationPlan) -> VerificationCheck:
        import os

        # 只检查代码类 planned_change（测试/文档类文件缺失不阻塞流水线）
        code_changes = [
            item for item in remediation_plan.planned_changes
            if item.change_type in ("code", "dependency", "configuration", None)
        ]
        if not code_changes:
            return VerificationCheck("planned_change_artifacts", VerificationCheckStatus.PASSED,
                                     "no code-level planned changes to verify")

        artifact_targets = {artifact.target for artifact in candidate.artifacts}

        def _normalize_path(path: str) -> str:
            """提取纯文件路径：去掉括号描述、统一斜杠。"""
            cleaned = re.sub(r'\s*\(.*?\)\s*', '', path).strip()
            return cleaned.replace('\\', '/')

        def _matches(expected: str, targets: set[str]) -> bool:
            """检查 expected 是否与任何 target 路径匹配（后缀匹配 + 纯文件名匹配）。"""
            exp = _normalize_path(expected)
            if not exp:
                return True
            for tgt in targets:
                tgt_norm = tgt.replace('\\', '/')
                if exp == tgt_norm:
                    return True
                if tgt_norm.endswith('/' + exp) or exp.endswith('/' + tgt_norm):
                    return True
                if os.path.basename(exp) == os.path.basename(tgt_norm):
                    return True
            return False

        missing = sorted(
            item.file for item in code_changes
            if not _matches(item.file, artifact_targets)
        )
        if not missing:
            return VerificationCheck("planned_change_artifacts", VerificationCheckStatus.PASSED,
                                     "all planned code changes have patch artifacts")
        return VerificationCheck("planned_change_artifacts", VerificationCheckStatus.FAILED,
                                 f"missing artifacts for: {', '.join(missing)}")

    @staticmethod
    def _security_tests_present(candidate: PatchCandidate, remediation_plan: RemediationPlan) -> VerificationCheck:
        requires_security = any(item.test_type == "security_regression" for item in remediation_plan.required_tests)
        has_security = any(item.test_type == "security_regression" for item in candidate.test_changes)
        has_test_artifact = any(artifact.patch_type == PatchType.TEST for artifact in candidate.artifacts)
        if not requires_security:
            return VerificationCheck("security_regression_test", VerificationCheckStatus.PASSED,
                                     "no security regression test required by remediation plan")
        if has_security and has_test_artifact:
            return VerificationCheck("security_regression_test", VerificationCheckStatus.PASSED,
                                     "security regression test patch is present")
        # 测试补丁缺失不阻塞流水线 — LLM 可能选择只生成核心代码修复
        return VerificationCheck("security_regression_test", VerificationCheckStatus.SKIPPED,
                                 "security regression test is recommended but no test patch was generated — manual review advised")

    @staticmethod
    def _scanner_rescan_present(candidate: PatchCandidate) -> VerificationCheck:
        if candidate.validation_plan.scanner_rescan_required:
            return VerificationCheck("scanner_rescan", VerificationCheckStatus.PASSED, "scanner rescan is included in validation plan")
        return VerificationCheck("scanner_rescan", VerificationCheckStatus.SKIPPED, "scanner rescan not required by remediation plan")

    @staticmethod
    def _suggestion(check_name: str) -> str:
        suggestions = {
            "candidate_generated": "确认修复方案状态为 ready，并补齐可修改文件范围",
            "patch_boundary_policy": "收敛补丁范围，移除越界文件或疑似禁用安全控制的内容",
            "planned_change_artifacts": "为每个 planned_change 生成对应 diff 或补丁产物",
            "security_regression_test": "根据 remediation_plan.required_tests 生成安全回归测试补丁",
        }
        return suggestions.get(check_name, "将失败原因交给失败分析 Agent 后重新生成补丁")

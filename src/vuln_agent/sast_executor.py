"""Workspace-based SAST repair executor for the first supported families."""

from __future__ import annotations

import ast
import json
import os
import re
import shlex
import subprocess
import tempfile
import textwrap
import time
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING

from .models import (
    EvidenceBundle,
    NormalizedVulnerability,
    RemediationPlan,
    RootCauseAssessment,
    SourceFile,
)
from .semantic import (
    PythonSemanticContextBuilder,
    SemanticContextPackage,
    SymbolContext,
)
from .scenarios.sql_injection.taxonomy import (
    SQLInjectionKind,
    classify_sql_injection,
    is_sql_injection,
)

if TYPE_CHECKING:
    from .llm import LLMBackend


SUPPORTED_SAST_FAMILIES = {
    "sql_injection",
    "command_injection",
    "path_traversal",
}


@dataclass(frozen=True, slots=True)
class StructuredEdit:
    file: str
    operation: str
    symbol: str | None
    replacement: str
    rationale: str


@dataclass(frozen=True, slots=True)
class WorkspaceCheck:
    name: str
    command: str
    passed: bool
    exit_code: int
    output: str
    duration_ms: int


class SASTCodeRepairExecutor:
    """Apply structured symbol edits in a disposable Git workspace.

    The model never writes unified-diff headers. It proposes symbol-level edits;
    this executor performs deterministic AST-bounded replacements, runs checks,
    and lets Git produce the final diff.
    """

    def __init__(
        self,
        llm: LLMBackend | None,
        *,
        timeout_seconds: int = 90,
        max_attempts: int = 2,
    ) -> None:
        self.llm = llm
        self.timeout_seconds = timeout_seconds
        self.max_attempts = max(1, max_attempts)
        self.context_builder = PythonSemanticContextBuilder()

    @staticmethod
    def classify(finding: NormalizedVulnerability) -> str | None:
        text = finding.vulnerability_type.lower()
        if is_sql_injection(finding):
            return "sql_injection"
        if any(term in text for term in ("sql injection", "sql注入", "sql 注入")):
            return "sql_injection"
        if any(term in text for term in ("command injection", "os command", "命令注入")):
            return "command_injection"
        if any(term in text for term in ("path traversal", "directory traversal", "路径遍历")):
            return "path_traversal"
        return None

    def execute(
        self,
        finding: NormalizedVulnerability,
        root_cause: RootCauseAssessment,
        plan: RemediationPlan,
        source_files: list[SourceFile],
        evidence: EvidenceBundle,
        *,
        previous_feedback: str = "",
        prefer_deterministic: bool = False,
    ) -> dict:
        family = self.classify(finding)
        if family not in SUPPORTED_SAST_FAMILIES:
            return {
                "artifacts": [],
                "blocked_reason": "SAST workspace executor does not support this vulnerability family",
            }
        package = self.context_builder.build(
            finding, root_cause, plan, source_files, evidence, family,
        )
        if package.change_set.missing_context or not package.symbols:
            return {
                "artifacts": [],
                "blocked_reason": (
                    "semantic context incomplete: "
                    + ", ".join(package.change_set.missing_context or ("no_target_symbol",))
                ),
                "change_set": package.change_set.to_dict(),
            }

        baseline = {_norm(item.path): item.content for item in source_files}
        sql_kind = (
            classify_sql_injection(finding)
            if family == "sql_injection"
            else None
        )
        if sql_kind == SQLInjectionKind.IDENTIFIER:
            package = self._constrain_identifier_package(package, finding)
        generation_errors: list[str] = []
        all_checks: list[WorkspaceCheck] = []
        llm_calls = 0
        last_edits: list[StructuredEdit] = []

        with tempfile.TemporaryDirectory(prefix="vuln-agent-sast-") as tmp:
            workspace = Path(tmp) / "workspace"
            self._hydrate(workspace, baseline)
            self._git_baseline(workspace)

            baseline_checks = self._syntax_checks(workspace, package)
            all_checks.extend(baseline_checks)
            if any(not check.passed for check in baseline_checks):
                return self._blocked(
                    package,
                    "baseline source does not pass syntax checks",
                    all_checks,
                    llm_calls,
                )

            feedback = previous_feedback
            for attempt in range(1, self.max_attempts + 1):
                self._restore(workspace, baseline)
                edits: list[StructuredEdit] = []
                use_model = (
                    self.llm is not None
                    and not prefer_deterministic
                    and not (
                        family == "sql_injection"
                        and attempt == self.max_attempts
                        and generation_errors
                    )
                )
                if use_model:
                    try:
                        raw = self._request_edits(
                            finding, root_cause, plan, package, feedback,
                        )
                        llm_calls += 1
                        edits = self._parse_edits(raw)
                    except Exception as exc:
                        generation_errors.append(
                            f"structured edit generation failed: {type(exc).__name__}"
                        )
                if not edits:
                    edits = self._deterministic_edits(
                        package,
                        family,
                        source_snapshot=baseline,
                        sql_kind=sql_kind,
                    )
                if not edits:
                    generation_errors.append("no valid structured edits generated")
                    break
                last_edits = list(edits)

                apply_errors = self._apply_edits(workspace, package, edits)
                if apply_errors:
                    feedback = "; ".join(apply_errors)
                    generation_errors.extend(apply_errors)
                    continue

                checks = [
                    *self._syntax_checks(workspace, package),
                    *self._security_oracle_checks(
                        workspace,
                        package,
                        family,
                        sql_kind=sql_kind,
                    ),
                    *self._focused_checks(workspace, package),
                ]
                all_checks.extend(checks)
                failures = [check for check in checks if not check.passed]
                if failures:
                    feedback = "\n".join(
                        f"{item.name}: {item.output[-2000:]}" for item in failures
                    )
                    generation_errors.extend(
                        f"{item.name}: exit={item.exit_code}" for item in failures
                    )
                    continue

                artifacts = self._git_artifacts(workspace, baseline)
                if not artifacts:
                    generation_errors.append("structured edits produced no Git diff")
                    break
                return {
                    "summary": (
                        f"SAST workspace executor repaired {finding.finding_id} "
                        f"as {family} in {attempt} attempt(s)"
                    ),
                    "artifacts": artifacts,
                    "changed_files": [
                        {
                            "file": item["target"],
                            "change_type": item["patch_type"],
                            "reason": "AST-bounded structured edit verified in isolated workspace",
                        }
                        for item in artifacts
                    ],
                    "security_notes": [
                        "LLM produced structured edits; Git generated the unified diff.",
                        "Target symbols were resolved from complete Python AST ranges.",
                        "Attack-oriented security oracle and legitimate regression command passed.",
                    ],
                    "assumptions": ["python_ast_symbol_resolution"],
                    "risks": generation_errors,
                    "needs_human_review": True,
                    "blocked_reason": None,
                    "llm_calls": llm_calls,
                    "change_set": package.change_set.to_dict(),
                    "edit_ir": [asdict(item) for item in edits],
                    "workspace_checks": [asdict(item) for item in all_checks],
                    "executor": "sast_workspace_executor",
                    "sql_injection_kind": (
                        sql_kind.value if sql_kind is not None else None
                    ),
                }

        blocked = self._blocked(
            package,
            "; ".join(generation_errors) or "workspace repair exhausted",
            all_checks,
            llm_calls,
        )
        blocked["edit_ir"] = [asdict(item) for item in last_edits]
        return blocked

    @staticmethod
    def _constrain_identifier_package(
        package: SemanticContextPackage,
        finding: NormalizedVulnerability,
    ) -> SemanticContextPackage:
        """Keep an identifier fix at the reported, evidence-backed ingress."""

        target_paths = {
            _norm(location.file)
            for location in finding.locations
            if location.file
        }
        target_functions = {
            location.function.split("(", 1)[0].strip()
            for location in finding.locations
            if location.function
        }
        selected = tuple(
            context
            for context in package.symbols
            if context.file in target_paths
            and (
                not target_functions
                or any(
                    context.symbol == function
                    or context.symbol.endswith("." + function)
                    for function in target_functions
                )
            )
        )
        if not selected:
            return package
        selected_keys = {
            (context.file, context.symbol)
            for context in selected
        }
        changes = tuple(
            change
            for change in package.change_set.changes
            if (change.file, change.symbol) in selected_keys
        )
        return replace(
            package,
            symbols=selected,
            change_set=replace(
                package.change_set,
                changes=changes,
            ),
        )

    def _request_edits(
        self,
        finding: NormalizedVulnerability,
        root_cause: RootCauseAssessment,
        plan: RemediationPlan,
        package: SemanticContextPackage,
        feedback: str,
    ) -> dict:
        context = package.to_dict()
        # Related tests are useful but bounded; target symbols are never truncated.
        context["test_sources"] = {
            path: content[:8000]
            for path, content in context["test_sources"].items()
        }
        prompt = f"""Produce structured source edits for a security repair.

Vulnerability: {finding.vulnerability_type}
Root cause: {root_cause.root_cause.summary}
Missing control: {root_cause.root_cause.missing_control or 'unknown'}
Goal: {plan.remediation_goal}
Previous real execution feedback:
{feedback or '(none)'}

Semantic context and ChangeSet:
{json.dumps(context, ensure_ascii=False, indent=2)}

Rules:
- Do not output unified diff or hunk line numbers.
- replace_symbol replacement must contain the complete function/class named by symbol.
- Only edit files and symbols present in the ChangeSet or append tests to relevant_tests.
- Preserve public signatures unless the ChangeSet explicitly requires a signature change.
- Security tests must exercise both an attack input and a legitimate input.
- Do not weaken existing assertions or delete legitimate behavior.
"""
        schema = {
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
                "edits": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "file": {"type": "string"},
                            "operation": {
                                "type": "string",
                                "enum": ["replace_symbol", "insert_import", "append_test"],
                            },
                            "symbol": {"type": ["string", "null"]},
                            "replacement": {"type": "string"},
                            "rationale": {"type": "string"},
                        },
                        "required": [
                            "file", "operation", "symbol", "replacement", "rationale",
                        ],
                    },
                },
            },
            "required": ["summary", "edits"],
        }
        result = self.llm.reason(
            user_prompt=prompt,
            system_prompt=(
                "You are a security code-repair executor. Return exact structured "
                "symbol replacements grounded only in the supplied repository context."
            ),
            output_schema=schema,
            temperature=0.1,
            max_tokens=12000,
        )
        return result if isinstance(result, dict) else {}

    @staticmethod
    def _parse_edits(raw: dict) -> list[StructuredEdit]:
        result: list[StructuredEdit] = []
        for item in raw.get("edits", []):
            if not isinstance(item, dict):
                continue
            if item.get("operation") not in {
                "replace_symbol", "insert_import", "append_test",
            }:
                continue
            if not item.get("file") or not item.get("replacement"):
                continue
            result.append(StructuredEdit(
                file=_norm(str(item["file"])),
                operation=str(item["operation"]),
                symbol=str(item["symbol"]) if item.get("symbol") else None,
                replacement=str(item["replacement"]),
                rationale=str(item.get("rationale") or ""),
            ))
        return result

    def _apply_edits(
        self,
        workspace: Path,
        package: SemanticContextPackage,
        edits: list[StructuredEdit],
    ) -> list[str]:
        allowed_symbols = {
            (_norm(item.file), item.symbol): item for item in package.symbols
        }
        test_files = {_norm(path) for path in package.change_set.relevant_tests}
        allowed_files = {item[0] for item in allowed_symbols} | test_files
        errors: list[str] = []
        grouped: dict[str, list[StructuredEdit]] = {}
        for edit in edits:
            path = _norm(edit.file)
            if path not in allowed_files:
                errors.append(f"edit outside ChangeSet: {path}")
                continue
            if edit.operation == "replace_symbol" and (path, edit.symbol or "") not in allowed_symbols:
                errors.append(f"unknown target symbol: {path}:{edit.symbol}")
                continue
            if edit.operation == "append_test" and path not in test_files:
                errors.append(f"append_test target is not a relevant test: {path}")
                continue
            grouped.setdefault(path, []).append(edit)
        if errors:
            return errors

        for path, file_edits in grouped.items():
            target = workspace / path
            content = target.read_text(encoding="utf-8")
            replace_edits = [
                item for item in file_edits if item.operation == "replace_symbol"
            ]
            contexts = sorted(
                [
                    (
                        allowed_symbols[(path, item.symbol or "")],
                        item,
                    )
                    for item in replace_edits
                ],
                key=lambda pair: pair[0].start_line,
                reverse=True,
            )
            lines = content.splitlines(keepends=True)
            for context, edit in contexts:
                replacement = self._indent_replacement(
                    edit.replacement, context.indentation,
                )
                lines[context.start_line - 1:context.end_line] = [
                    replacement.rstrip() + "\n"
                ]
            content = "".join(lines)
            for edit in file_edits:
                if edit.operation == "insert_import":
                    content = self._insert_import(content, edit.replacement)
                elif edit.operation == "append_test":
                    content = content.rstrip() + "\n\n" + edit.replacement.strip() + "\n"
            try:
                ast.parse(content)
            except SyntaxError as exc:
                errors.append(f"edited Python syntax invalid: {path}:{exc.lineno}: {exc.msg}")
                continue
            target.write_text(content, encoding="utf-8")
        return errors

    @staticmethod
    def _indent_replacement(replacement: str, indentation: int) -> str:
        clean = textwrap.dedent(replacement).strip("\n")
        prefix = " " * indentation
        return "\n".join(prefix + line if line else "" for line in clean.splitlines())

    @staticmethod
    def _insert_import(content: str, replacement: str) -> str:
        statement = replacement.strip()
        if statement in content.splitlines():
            return content
        tree = ast.parse(content)
        insert_after = 0
        if tree.body and isinstance(tree.body[0], ast.Expr):
            value = tree.body[0].value
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                insert_after = tree.body[0].end_lineno or 0
        for node in tree.body:
            if isinstance(node, ast.ImportFrom) and node.module == "__future__":
                insert_after = node.end_lineno or insert_after
        lines = content.splitlines(keepends=True)
        lines.insert(insert_after, statement + "\n")
        return "".join(lines)

    def _deterministic_sql_edits(
        self,
        package: SemanticContextPackage,
        *,
        source_snapshot: dict[str, str],
        sql_kind: SQLInjectionKind,
    ) -> list[StructuredEdit]:
        edits: list[StructuredEdit] = []
        for context in package.symbols:
            if sql_kind == SQLInjectionKind.VALUE:
                replacement = self._parameterize_simple_dbapi_function(context)
                rationale = (
                    "Replace SQL string concatenation with a DB-API bound parameter."
                )
            else:
                replacement = self._insert_peer_identifier_guard(
                    context,
                    source_snapshot.get(_norm(context.file), ""),
                    sql_kind,
                )
                rationale = (
                    "Apply the existing sibling security control at the untrusted "
                    f"{sql_kind.value} ingress."
                )
            if replacement:
                edits.append(StructuredEdit(
                    context.file,
                    "replace_symbol",
                    context.symbol,
                    replacement,
                    rationale,
                ))
                test_path = next(iter(package.change_set.relevant_tests), None)
                if test_path:
                    test = self._sql_dual_direction_test(context)
                    if test:
                        edits.append(StructuredEdit(
                            test_path,
                            "append_test",
                            None,
                            test,
                            "Verify attack input is data and legitimate input still works.",
                        ))
        return edits

    def _deterministic_edits(
        self,
        package: SemanticContextPackage,
        family: str,
        *,
        source_snapshot: dict[str, str] | None = None,
        sql_kind: SQLInjectionKind | None = None,
    ) -> list[StructuredEdit]:
        """Return conservative AST-backed fallbacks for high-confidence shapes.

        These fallbacks deliberately support a small, auditable subset.  An
        unfamiliar call shape is blocked instead of being rewritten by
        string heuristics.
        """
        if family == "sql_injection":
            return self._deterministic_sql_edits(
                package,
                source_snapshot=source_snapshot or {},
                sql_kind=sql_kind or SQLInjectionKind.VALUE,
            )
        edits: list[StructuredEdit] = []
        for context in package.symbols:
            if family == "command_injection":
                replacement = self._replace_simple_shell_call(context)
                import_line = "import subprocess"
                test = self._command_dual_direction_test(context)
                rationale = (
                    "Replace shell interpretation with an atomic subprocess argv list "
                    "while preserving os.system return-code behavior."
                )
            elif family == "path_traversal":
                replacement = self._guard_simple_path_read(context)
                import_line = ""
                test = self._path_dual_direction_test(context)
                rationale = (
                    "Resolve the base and candidate path, then enforce containment "
                    "before the filesystem read."
                )
            else:
                continue
            if not replacement:
                continue
            if import_line:
                edits.append(StructuredEdit(
                    context.file,
                    "insert_import",
                    None,
                    import_line,
                    rationale,
                ))
            edits.append(StructuredEdit(
                context.file,
                "replace_symbol",
                context.symbol,
                replacement,
                rationale,
            ))
            test_path = next(iter(package.change_set.relevant_tests), None)
            if test_path and test:
                edits.append(StructuredEdit(
                    test_path,
                    "append_test",
                    None,
                    test,
                    "Exercise an attack input and a legitimate input.",
                ))
        return edits

    @staticmethod
    def _insert_peer_identifier_guard(
        context: SymbolContext,
        full_source: str,
        sql_kind: SQLInjectionKind,
    ) -> str | None:
        """Reuse a security guard already established by sibling methods."""

        if not full_source or "." not in context.symbol:
            return None
        try:
            tree = ast.parse(full_source)
        except SyntaxError:
            return None
        target = _find_symbol(tree, context.symbol)
        parent = _find_symbol(tree, context.symbol.rsplit(".", 1)[0])
        if not isinstance(target, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None
        if not isinstance(parent, ast.ClassDef):
            return None

        target_calls = {
            call.func.attr
            for call in ast.walk(target)
            if isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id == "self"
        }
        candidates: dict[str, int] = {}
        for sibling in parent.body:
            if (
                not isinstance(sibling, (ast.FunctionDef, ast.AsyncFunctionDef))
                or sibling is target
            ):
                continue
            for call in ast.walk(sibling):
                if (
                    isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Attribute)
                    and isinstance(call.func.value, ast.Name)
                    and call.func.value.id == "self"
                    and _looks_like_security_control(call.func.attr, sql_kind)
                ):
                    candidates[call.func.attr] = candidates.get(call.func.attr, 0) + 1
        if not candidates:
            return None
        guard = sorted(candidates, key=lambda name: (-candidates[name], name))[0]
        if guard in target_calls:
            return None

        parameters = [
            argument.arg
            for argument in target.args.args
            if argument.arg not in {"self", "cls"}
        ]
        parameter = next(
            (
                name
                for name in parameters
                if any(
                    token in name.lower()
                    for token in (
                        "field",
                        "column",
                        "alias",
                        "identifier",
                        "name",
                        "order",
                        "sort",
                        "expression",
                    )
                )
            ),
            None,
        )
        if parameter is None:
            return None

        original = textwrap.dedent(context.source).strip("\n")
        try:
            local_tree = ast.parse(original)
        except SyntaxError:
            return None
        local_target = next(
            (
                node
                for node in local_tree.body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            ),
            None,
        )
        if local_target is None:
            return None
        insert_after = local_target.lineno
        if (
            local_target.body
            and isinstance(local_target.body[0], ast.Expr)
            and isinstance(local_target.body[0].value, ast.Constant)
            and isinstance(local_target.body[0].value.value, str)
        ):
            insert_after = local_target.body[0].end_lineno or insert_after

        lines = original.splitlines()
        body_indent = " " * (
            local_target.body[0].col_offset if local_target.body else 4
        )
        collection_like = (
            parameter.endswith(("s", "_list", "_set", "_fields", "_names"))
            or parameter in {"fields", "columns", "aliases", "identifiers"}
        )
        guarded_block = next(
            (
                node
                for node in local_target.body
                if isinstance(node, ast.If)
                and any(
                    isinstance(part, ast.Name)
                    and part.id == parameter
                    for part in ast.walk(node.test)
                )
            ),
            None,
        )
        if collection_like and guarded_block is not None:
            insert_after = guarded_block.lineno
            body_indent = " " * (
                guarded_block.body[0].col_offset
                if guarded_block.body
                else local_target.col_offset + 8
            )
        if collection_like:
            item = _singular_identifier(parameter)
            guard_lines = [
                f"{body_indent}for {item} in {parameter}:",
                f"{body_indent}    self.{guard}({item})",
            ]
        else:
            guard_lines = [f"{body_indent}self.{guard}({parameter})"]
        lines[insert_after:insert_after] = guard_lines
        return "\n".join(lines)

    @staticmethod
    def _replace_simple_shell_call(context: SymbolContext) -> str | None:
        """Rewrite provably tokenizable os.system calls inside one function."""
        try:
            tree = ast.parse(textwrap.dedent(context.source))
        except SyntaxError:
            return None
        function = next(
            (
                node for node in tree.body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            ),
            None,
        )
        if function is None:
            return None
        assignments = {
            node.targets[0].id: node.value
            for node in ast.walk(function)
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
            )
        }

        class ShellTransformer(ast.NodeTransformer):
            changed = 0

            def _argv(self, value: ast.expr) -> ast.List | None:
                resolved = assignments.get(value.id, value) if isinstance(value, ast.Name) else value
                values = _shell_expression_to_argv(resolved)
                if not values or not any(not isinstance(item, ast.Constant) for item in values):
                    return None
                return ast.List(elts=values, ctx=ast.Load())

            def visit_Return(self, node: ast.Return) -> ast.AST:
                self.generic_visit(node)
                call = node.value
                if not (
                    isinstance(call, ast.Call)
                    and ast.unparse(call.func) == "os.system"
                    and len(call.args) == 1
                ):
                    return node
                argv = self._argv(call.args[0])
                if argv is None:
                    return node
                run = ast.Call(
                    func=ast.Attribute(
                        value=ast.Name(id="subprocess", ctx=ast.Load()),
                        attr="run",
                        ctx=ast.Load(),
                    ),
                    args=[argv],
                    keywords=[ast.keyword(arg="check", value=ast.Constant(False))],
                )
                node.value = ast.Attribute(value=run, attr="returncode", ctx=ast.Load())
                self.changed += 1
                return node

            def visit_Expr(self, node: ast.Expr) -> ast.AST:
                self.generic_visit(node)
                call = node.value
                if not (
                    isinstance(call, ast.Call)
                    and ast.unparse(call.func) == "os.system"
                    and len(call.args) == 1
                ):
                    return node
                argv = self._argv(call.args[0])
                if argv is None:
                    return node
                node.value = ast.Call(
                    func=ast.Attribute(
                        value=ast.Name(id="subprocess", ctx=ast.Load()),
                        attr="run",
                        ctx=ast.Load(),
                    ),
                    args=[argv],
                    keywords=[ast.keyword(arg="check", value=ast.Constant(True))],
                )
                self.changed += 1
                return node

        transformer = ShellTransformer()
        transformer.visit(function)
        if transformer.changed != 1:
            return None
        ast.fix_missing_locations(function)
        return ast.unparse(function)

    @staticmethod
    def _guard_simple_path_read(context: SymbolContext) -> str | None:
        """Guard a direct ``(Path(base) / user_path).read_*`` expression."""
        try:
            tree = ast.parse(textwrap.dedent(context.source))
        except SyntaxError:
            return None
        function = next(
            (
                node for node in tree.body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            ),
            None,
        )
        if function is None:
            return None

        match: tuple[ast.expr, ast.expr] | None = None
        for node in ast.walk(function):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in {
                    "read_text", "read_bytes", "open", "write_text", "write_bytes",
                }
            ):
                continue
            match = _path_join_components(node.func.value)
            if match is not None:
                break
        if match is None:
            return None
        base_expr, relative_expr = match

        class PathTransformer(ast.NodeTransformer):
            changed = 0

            def visit_Call(self, node: ast.Call) -> ast.AST:
                self.generic_visit(node)
                if (
                    self.changed == 0
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr in {
                        "read_text", "read_bytes", "open", "write_text", "write_bytes",
                    }
                    and _path_join_components(node.func.value) is not None
                ):
                    node.func.value = ast.Name(id="candidate_path", ctx=ast.Load())
                    self.changed += 1
                return node

        transformer = PathTransformer()
        transformer.visit(function)
        if transformer.changed != 1:
            return None
        base_resolved = ast.Call(
            func=ast.Attribute(value=base_expr, attr="resolve", ctx=ast.Load()),
            args=[],
            keywords=[],
        )
        candidate_join = ast.BinOp(
            left=ast.Name(id="base_path", ctx=ast.Load()),
            op=ast.Div(),
            right=relative_expr,
        )
        candidate_resolved = ast.Call(
            func=ast.Attribute(
                value=candidate_join,
                attr="resolve",
                ctx=ast.Load(),
            ),
            args=[],
            keywords=[],
        )
        guard = ast.If(
            test=ast.UnaryOp(
                op=ast.Not(),
                operand=ast.Call(
                    func=ast.Attribute(
                        value=ast.Name(id="candidate_path", ctx=ast.Load()),
                        attr="is_relative_to",
                        ctx=ast.Load(),
                    ),
                    args=[ast.Name(id="base_path", ctx=ast.Load())],
                    keywords=[],
                ),
            ),
            body=[
                ast.Raise(
                    exc=ast.Call(
                        func=ast.Name(id="ValueError", ctx=ast.Load()),
                        args=[ast.Constant("path escapes base directory")],
                        keywords=[],
                    ),
                    cause=None,
                )
            ],
            orelse=[],
        )
        insertion = 1 if (
            function.body
            and isinstance(function.body[0], ast.Expr)
            and isinstance(function.body[0].value, ast.Constant)
            and isinstance(function.body[0].value.value, str)
        ) else 0
        function.body[insertion:insertion] = [
            ast.Assign(
                targets=[ast.Name(id="base_path", ctx=ast.Store())],
                value=base_resolved,
            ),
            ast.Assign(
                targets=[ast.Name(id="candidate_path", ctx=ast.Store())],
                value=candidate_resolved,
            ),
            guard,
        ]
        ast.fix_missing_locations(function)
        return ast.unparse(function)

    @staticmethod
    def _command_dual_direction_test(context: SymbolContext) -> str | None:
        function = context.symbol.rsplit(".", 1)[-1]
        module = context.file[:-3].replace("/", ".")
        try:
            tree = ast.parse(textwrap.dedent(context.source))
        except SyntaxError:
            return None
        target = next(
            (
                node for node in tree.body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            ),
            None,
        )
        if target is None or len(target.args.args) != 1 or "." in context.symbol:
            return None
        return f'''def test_{function}_keeps_untrusted_host_as_one_argv_element(monkeypatch):
    import importlib
    from types import SimpleNamespace

    module = importlib.import_module("{module}")
    calls = []

    def recording_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(module.subprocess, "run", recording_run)
    attack = "127.0.0.1; touch /tmp/pwned"
    module.{function}(attack)
    assert isinstance(calls[-1][0], list)
    assert attack in calls[-1][0]

    legitimate = "127.0.0.1"
    module.{function}(legitimate)
    assert legitimate in calls[-1][0]'''

    @staticmethod
    def _path_dual_direction_test(context: SymbolContext) -> str | None:
        function = context.symbol.rsplit(".", 1)[-1]
        module = context.file[:-3].replace("/", ".")
        try:
            tree = ast.parse(textwrap.dedent(context.source))
        except SyntaxError:
            return None
        target = next(
            (
                node for node in tree.body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            ),
            None,
        )
        if target is None or len(target.args.args) != 2 or "." in context.symbol:
            return None
        return f'''def test_{function}_rejects_escape_and_allows_file_inside_base(tmp_path):
    import importlib
    import pytest

    module = importlib.import_module("{module}")
    base = tmp_path / "base"
    base.mkdir()
    legitimate = base / "ok.txt"
    legitimate.write_text("ok", encoding="utf-8")
    module.{function}(base, "ok.txt")

    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    with pytest.raises(ValueError):
        module.{function}(base, "../outside.txt")'''

    @staticmethod
    def _parameterize_simple_dbapi_function(context: SymbolContext) -> str | None:
        try:
            tree = ast.parse(textwrap.dedent(context.source))
        except SyntaxError:
            return None
        function = next(
            (
                node for node in tree.body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            ),
            None,
        )
        if function is None:
            return None
        lines = textwrap.dedent(context.source).splitlines()
        assignments: dict[str, ast.Assign] = {}
        for node in ast.walk(function):
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
            ):
                assignments[node.targets[0].id] = node
        for call in ast.walk(function):
            if not (
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Attribute)
                and call.func.attr in {"execute", "executemany"}
                and len(call.args) == 1
                and isinstance(call.args[0], ast.Name)
            ):
                continue
            assignment = assignments.get(call.args[0].id)
            if assignment is None:
                continue
            parts = _flatten_string_add(assignment.value)
            dynamic = [item for item in parts if isinstance(item, ast.Name)]
            if len(dynamic) != 1 or any(
                not isinstance(item, (ast.Constant, ast.Name)) for item in parts
            ):
                continue
            name = dynamic[0].id
            before, after = _constant_around(parts, dynamic[0])
            wildcard = before.endswith("'%") and after.startswith("%'")
            if wildcard:
                query = before[:-2] + "%s" + after[2:]
                parameter = f'f"%{{{name}}}%"'
            else:
                query = before + "%s" + after
                parameter = name
            indent_assign = " " * assignment.col_offset
            indent_call = " " * call.col_offset
            lines[assignment.lineno - 1:assignment.end_lineno] = [
                f"{indent_assign}{call.args[0].id} = {json.dumps(query)}"
            ]
            offset = assignment.end_lineno - assignment.lineno
            call_line = call.lineno - 1 - offset
            receiver = ast.unparse(call.func.value)
            lines[call_line:call_line + (call.end_lineno - call.lineno + 1)] = [
                f"{indent_call}{receiver}.{call.func.attr}("
                f"{call.args[0].id}, ({parameter},))"
            ]
            return "\n".join(lines)
        return None

    @staticmethod
    def _sql_dual_direction_test(context: SymbolContext) -> str | None:
        function = context.symbol.rsplit(".", 1)[-1]
        module = context.file[:-3].replace("/", ".")
        if "." in context.symbol:
            return None
        return f'''def test_{function}_uses_bound_parameters_for_attack_and_legitimate_input():
    import importlib
    from types import SimpleNamespace

    module = importlib.import_module("{module}")

    class RecordingCursor:
        def execute(self, *args):
            self.last_execute = args

        def fetchall(self):
            return []

    original_request = module.request
    try:
        cursor = RecordingCursor()
        attack = "' OR '1'='1"
        module.request = SimpleNamespace(args={{"q": attack}})
        module.{function}(cursor)
        query, params = cursor.last_execute
        assert attack not in query
        assert attack in repr(params)

        legitimate = "alice"
        module.request = SimpleNamespace(args={{"q": legitimate}})
        assert module.{function}(cursor) == []
        query, params = cursor.last_execute
        assert legitimate not in query
        assert legitimate in repr(params)
    finally:
        module.request = original_request'''

    def _syntax_checks(
        self,
        workspace: Path,
        package: SemanticContextPackage,
    ) -> list[WorkspaceCheck]:
        targets = sorted({item.file for item in package.symbols})
        if not targets:
            return []
        command = "python -m py_compile " + " ".join(_quote(path) for path in targets)
        return [self._run(workspace, "python_syntax", command)]

    def _security_oracle_checks(
        self,
        workspace: Path,
        package: SemanticContextPackage,
        family: str,
        *,
        sql_kind: SQLInjectionKind | None = None,
    ) -> list[WorkspaceCheck]:
        started = time.perf_counter()
        problems: list[str] = []
        for context in package.symbols:
            content = (workspace / context.file).read_text(encoding="utf-8")
            try:
                tree = ast.parse(content)
            except SyntaxError as exc:
                problems.append(f"{context.file}: {exc}")
                continue
            if family == "sql_injection":
                try:
                    problems.extend(
                        _sql_oracle_problems(
                            context.file,
                            tree,
                            context.symbol,
                            sql_kind or SQLInjectionKind.VALUE,
                        )
                    )
                except ValueError as exc:
                    problems.append(str(exc))
            elif family == "command_injection":
                problems.extend(_command_oracle_problems(context.file, tree))
            elif family == "path_traversal":
                problems.extend(
                    _path_oracle_problems(context.file, tree, context.symbol)
                )
        return [WorkspaceCheck(
            name=f"{family}_security_oracle",
            command="deterministic AST security oracle",
            passed=not problems,
            exit_code=0 if not problems else 1,
            output="; ".join(problems) if problems else "security invariant satisfied",
            duration_ms=int((time.perf_counter() - started) * 1000),
        )]

    def _focused_checks(
        self,
        workspace: Path,
        package: SemanticContextPackage,
    ) -> list[WorkspaceCheck]:
        checks: list[WorkspaceCheck] = []
        seen: set[str] = set()
        for command in package.change_set.validation_commands:
            command = command.strip()
            if not command or command in seen:
                continue
            seen.add(command)
            if not self._command_targets_exist(workspace, command):
                continue
            checks.append(self._run(workspace, "focused_regression", command))
            if len(checks) >= 2:
                break
        return checks

    @staticmethod
    def _command_targets_exist(workspace: Path, command: str) -> bool:
        paths = re.findall(r"(?:^|\s)((?:tests?|specs?)[/\\][^\s]+)", command)
        return all((workspace / path.strip("'\"")).exists() for path in paths)

    def _run(self, workspace: Path, name: str, command: str) -> WorkspaceCheck:
        started = time.perf_counter()
        env = os.environ.copy()
        env["PYTHONPATH"] = os.pathsep.join(
            filter(None, [str(workspace), env.get("PYTHONPATH", "")])
        )
        try:
            result = subprocess.run(
                command,
                cwd=workspace,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
                env=env,
            )
            output = "\n".join(filter(None, [result.stdout.strip(), result.stderr.strip()]))
            return WorkspaceCheck(
                name, command, result.returncode == 0, result.returncode,
                output[-6000:], int((time.perf_counter() - started) * 1000),
            )
        except subprocess.TimeoutExpired as exc:
            return WorkspaceCheck(
                name, command, False, 124, str(exc),
                int((time.perf_counter() - started) * 1000),
            )

    @staticmethod
    def _hydrate(workspace: Path, baseline: dict[str, str]) -> None:
        workspace.mkdir(parents=True, exist_ok=True)
        for path, content in baseline.items():
            target = workspace / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")

    @staticmethod
    def _restore(workspace: Path, baseline: dict[str, str]) -> None:
        for path, content in baseline.items():
            (workspace / path).write_text(content, encoding="utf-8")

    @staticmethod
    def _git_baseline(workspace: Path) -> None:
        subprocess.run(["git", "init", "-q"], cwd=workspace, check=True)
        subprocess.run(["git", "add", "."], cwd=workspace, check=True)
        subprocess.run(
            [
                "git", "-c", "user.name=vuln-agent",
                "-c", "user.email=vuln-agent@localhost",
                "commit", "-q", "-m", "baseline",
            ],
            cwd=workspace,
            check=True,
        )

    @staticmethod
    def _git_artifacts(
        workspace: Path,
        baseline: dict[str, str],
    ) -> list[dict]:
        changed = subprocess.run(
            ["git", "diff", "--name-only"],
            cwd=workspace,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.splitlines()
        artifacts: list[dict] = []
        for path in changed:
            normalized = _norm(path)
            if normalized not in baseline:
                continue
            diff = subprocess.run(
                ["git", "diff", "--no-ext-diff", "--", normalized],
                cwd=workspace,
                capture_output=True,
                text=True,
                check=True,
            ).stdout
            if diff:
                artifacts.append({
                    "patch_type": "test" if _is_test(normalized) else "code",
                    "target": normalized,
                    "content": diff.rstrip(),
                    "description": "Git-generated diff from verified structured edits",
                })
        return artifacts

    @staticmethod
    def _blocked(
        package: SemanticContextPackage,
        reason: str,
        checks: list[WorkspaceCheck],
        llm_calls: int,
    ) -> dict:
        return {
            "artifacts": [],
            "changed_files": [],
            "blocked_reason": reason,
            "risks": [reason],
            "needs_human_review": True,
            "llm_calls": llm_calls,
            "change_set": package.change_set.to_dict(),
            "workspace_checks": [asdict(item) for item in checks],
            "executor": "sast_workspace_executor",
        }


def _flatten_string_add(node: ast.AST) -> list[ast.AST]:
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return [*_flatten_string_add(node.left), *_flatten_string_add(node.right)]
    return [node]


def _shell_expression_to_argv(node: ast.AST) -> list[ast.expr] | None:
    """Convert a simple shell string expression into atomic argv expressions.

    Dynamic values must occupy a complete shell token.  Constructs such as
    ``"--output=" + value`` are intentionally rejected because silently
    changing their token boundaries could alter behavior.
    """
    pieces: list[ast.AST]
    if isinstance(node, ast.JoinedStr):
        pieces = list(node.values)
    else:
        pieces = _flatten_string_add(node)
    result: list[ast.expr] = []
    dynamic_count = 0
    for index, piece in enumerate(pieces):
        if isinstance(piece, ast.Constant) and isinstance(piece.value, str):
            try:
                tokens = shlex.split(piece.value, posix=True)
            except ValueError:
                return None
            result.extend(ast.Constant(token) for token in tokens)
            continue
        if isinstance(piece, ast.FormattedValue):
            value = piece.value
        elif isinstance(piece, ast.expr):
            value = piece
        else:
            return None
        previous = pieces[index - 1] if index else None
        following = pieces[index + 1] if index + 1 < len(pieces) else None
        if (
            isinstance(previous, ast.Constant)
            and isinstance(previous.value, str)
            and previous.value
            and not previous.value[-1].isspace()
        ):
            return None
        if (
            isinstance(following, ast.Constant)
            and isinstance(following.value, str)
            and following.value
            and not following.value[0].isspace()
        ):
            return None
        result.append(value)
        dynamic_count += 1
    return result if result and dynamic_count else None


def _path_join_components(node: ast.AST) -> tuple[ast.expr, ast.expr] | None:
    if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Div):
        return None
    if not isinstance(node.left, ast.Call):
        return None
    if ast.unparse(node.left.func) not in {"Path", "pathlib.Path"}:
        return None
    if len(node.left.args) != 1 or not isinstance(node.right, ast.expr):
        return None
    return node.left, node.right


def _constant_around(parts: list[ast.AST], dynamic: ast.Name) -> tuple[str, str]:
    index = parts.index(dynamic)
    before = "".join(
        str(item.value) for item in parts[:index]
        if isinstance(item, ast.Constant) and isinstance(item.value, str)
    )
    after = "".join(
        str(item.value) for item in parts[index + 1:]
        if isinstance(item, ast.Constant) and isinstance(item.value, str)
    )
    return before, after


def _sql_oracle_problems(
    path: str,
    tree: ast.AST,
    target_symbol: str,
    sql_kind: SQLInjectionKind = SQLInjectionKind.VALUE,
) -> list[str]:
    scope = _resolve_ast_symbol(tree, target_symbol)
    if scope is None:
        raise ValueError(f"{path}: target symbol {target_symbol!r} could not be resolved")
    if sql_kind != SQLInjectionKind.VALUE:
        expected_controls = _peer_sql_security_controls(
            tree,
            target_symbol,
            sql_kind,
        )
        if not expected_controls:
            return [
                f"{path}:{target_symbol}: no same-scope {sql_kind.value} "
                "security-control precedent was found"
            ]
        target_controls = {
            _call_name(node)
            for node in _walk_symbol_scope(scope)
            if isinstance(node, ast.Call)
        }
        missing = sorted(expected_controls - target_controls)
        return [
            f"{path}:{target_symbol}: missing peer security control {control}"
            for control in missing
        ]
    assignments: dict[str, ast.AST] = {}
    problems: list[str] = []
    saw_execute = False
    saw_bound_execute = False
    scoped_nodes = tuple(_walk_symbol_scope(scope))
    for node in scoped_nodes:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        ):
            assignments[node.targets[0].id] = node.value
    for node in scoped_nodes:
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"execute", "executemany"}
            and node.args
        ):
            continue
        saw_execute = True
        query = node.args[0]
        value = assignments.get(query.id) if isinstance(query, ast.Name) else query
        if _dynamic_string_expression(value):
            problems.append(f"{path}:{node.lineno}: dynamic SQL reaches execute")
        if len(node.args) >= 2 or any(
            keyword.arg in {"params", "parameters"} for keyword in node.keywords
        ):
            saw_bound_execute = True
        if (
            isinstance(value, ast.Constant)
            and re.search(r"%s|\?|:[A-Za-z_]", str(value.value))
            and len(node.args) < 2
        ):
            problems.append(f"{path}:{node.lineno}: SQL placeholder has no bound parameters")
    if saw_execute and not saw_bound_execute:
        problems.append(f"{path}: vulnerable path has no bound-parameter execute call")
    return problems


def _peer_sql_security_controls(
    tree: ast.AST,
    target_symbol: str,
    sql_kind: SQLInjectionKind,
) -> set[str]:
    parent_name, _, child_name = target_symbol.rpartition(".")
    parent = _resolve_ast_symbol(tree, parent_name) if parent_name else tree
    if parent is None:
        return set()
    candidates: dict[str, int] = {}
    for sibling in getattr(parent, "body", []):
        if not isinstance(sibling, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if sibling.name == child_name:
            continue
        for node in _walk_symbol_scope(sibling):
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node)
            leaf = name.rsplit(".", 1)[-1]
            if _looks_like_security_control(leaf, sql_kind):
                candidates[name] = candidates.get(name, 0) + 1
    if not candidates:
        return set()
    highest = max(candidates.values())
    return {
        name for name, count in candidates.items()
        if count == highest
    }


def _call_name(call: ast.Call) -> str:
    if (
        isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id in {"self", "cls"}
    ):
        return f"{call.func.value.id}.{call.func.attr}"
    if isinstance(call.func, ast.Name):
        return call.func.id
    return ast.unparse(call.func)


def _resolve_ast_symbol(tree: ast.AST, target_symbol: str) -> ast.AST | None:
    """Resolve an exact semantic qualname without falling back to the module."""

    found: dict[str, ast.AST] = {}

    def visit(node: ast.AST, parents: tuple[str, ...] = ()) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                qualname = ".".join((*parents, child.name))
                found[qualname] = child
                visit(child, (*parents, child.name))
            else:
                visit(child, parents)

    visit(tree)
    return found.get(target_symbol)


def _walk_symbol_scope(scope: ast.AST):
    """Walk one symbol while excluding unrelated nested symbol definitions."""

    def visit(node: ast.AST):
        yield node
        for child in ast.iter_child_nodes(node):
            if isinstance(
                child,
                (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda),
            ):
                continue
            yield from visit(child)

    yield scope
    for child in ast.iter_child_nodes(scope):
        if isinstance(
            child,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda),
        ):
            continue
        yield from visit(child)


def _command_oracle_problems(path: str, tree: ast.AST) -> list[str]:
    problems: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = ast.unparse(node.func)
        if name in {"os.system", "os.popen"}:
            problems.append(f"{path}:{node.lineno}: unsafe command API remains")
        if any(
            keyword.arg == "shell"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        ):
            problems.append(f"{path}:{node.lineno}: shell=True remains")
        if (
            name.startswith("subprocess.")
            and node.args
            and not isinstance(node.args[0], (ast.List, ast.Tuple))
        ):
            problems.append(
                f"{path}:{node.lineno}: subprocess command is not a structured argv list"
            )
    return problems


def _path_oracle_problems(
    path: str,
    tree: ast.AST,
    symbol: str,
) -> list[str]:
    node = _find_symbol(tree, symbol)
    if node is None:
        return [f"{path}: repaired path symbol {symbol} not found"]
    calls = [
        item for item in ast.walk(node) if isinstance(item, ast.Call)
    ]
    has_resolve = any(
        isinstance(call.func, ast.Attribute) and call.func.attr == "resolve"
        for call in calls
    )
    has_containment = any(
        (
            isinstance(call.func, ast.Attribute)
            and call.func.attr in {"is_relative_to", "relative_to"}
        )
        or ast.unparse(call.func) == "os.path.commonpath"
        for call in calls
    )
    problems: list[str] = []
    if not has_resolve:
        problems.append(f"{path}: target symbol does not resolve candidate paths")
    if not has_containment:
        problems.append(f"{path}: target symbol has no resolved-path containment check")
    return problems


def _find_symbol(tree: ast.AST, symbol: str) -> ast.AST | None:
    parts = symbol.split(".")
    current: ast.AST = tree
    for part in parts:
        match = next(
            (
                child for child in getattr(current, "body", [])
                if isinstance(
                    child,
                    (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
                )
                and child.name == part
            ),
            None,
        )
        if match is None:
            return None
        current = match
    return current


def _dynamic_string_expression(node: ast.AST | None) -> bool:
    if node is None:
        return False
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"format", "format_map"}
    ):
        return True
    return False


def _looks_like_security_control(
    name: str,
    sql_kind: SQLInjectionKind,
) -> bool:
    lowered = name.lower()
    common = (
        "check",
        "validate",
        "sanitize",
        "escape",
        "quote",
        "allow",
        "safe",
        "normalize",
    )
    if not any(token in lowered for token in common):
        return False
    if sql_kind == SQLInjectionKind.ORDERING:
        return any(
            token in lowered
            for token in ("order", "sort", "field", "column", "name")
        )
    if sql_kind == SQLInjectionKind.IDENTIFIER:
        return any(
            token in lowered
            for token in ("alias", "identifier", "column", "field", "name")
        )
    if sql_kind == SQLInjectionKind.ORM_EXPRESSION:
        return any(
            token in lowered
            for token in ("expression", "resolve", "filter", "lookup")
        )
    return True


def _singular_identifier(name: str) -> str:
    known = {
        "fields": "field",
        "columns": "column",
        "aliases": "alias",
        "identifiers": "identifier",
        "names": "name",
        "expressions": "expression",
        "orderings": "ordering",
    }
    if name in known:
        return known[name]
    if name.endswith("_list"):
        return name[:-5] or "item"
    if name.endswith("_set"):
        return name[:-4] or "item"
    if name.endswith("ies"):
        return name[:-3] + "y"
    if name.endswith("s") and len(name) > 1:
        return name[:-1]
    return "item"


def _norm(path: str) -> str:
    return path.replace("\\", "/").strip().lstrip("./")


def _is_test(path: str) -> bool:
    name = Path(path).name.lower()
    return "tests" in {part.lower() for part in Path(path).parts} or name.startswith("test_")


def _quote(value: str) -> str:
    return subprocess.list2cmdline([value])

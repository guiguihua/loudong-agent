"""AST-backed semantic context and ChangeSet contracts for code repair."""

from __future__ import annotations

import ast
import hashlib
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .models import (
    EvidenceBundle,
    NormalizedVulnerability,
    RemediationPlan,
    RootCauseAssessment,
    SourceFile,
)


@dataclass(frozen=True, slots=True)
class SymbolContext:
    file: str
    symbol: str
    kind: str
    start_line: int
    end_line: int
    indentation: int
    source: str
    direct_references: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SemanticChange:
    file: str
    symbol: str
    edit_intent: str
    reason: str
    depends_on: tuple[str, ...] = ()
    causally_required: bool = False


@dataclass(frozen=True, slots=True)
class ChangeSet:
    finding_id: str
    vulnerability_family: str
    security_invariant: str
    base_files: dict[str, str]
    changes: tuple[SemanticChange, ...]
    relevant_tests: tuple[str, ...]
    validation_commands: tuple[str, ...]
    missing_context: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class SemanticContextPackage:
    change_set: ChangeSet
    symbols: tuple[SymbolContext, ...]
    imports_by_file: dict[str, tuple[str, ...]] = field(default_factory=dict)
    test_sources: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "change_set": self.change_set.to_dict(),
            "symbols": [asdict(item) for item in self.symbols],
            "imports_by_file": {
                key: list(value) for key, value in self.imports_by_file.items()
            },
            "test_sources": dict(self.test_sources),
        }


class PythonSemanticContextBuilder:
    """Resolve complete target symbols and direct references with Python AST."""

    def build(
        self,
        finding: NormalizedVulnerability,
        root_cause: RootCauseAssessment,
        plan: RemediationPlan,
        source_files: list[SourceFile],
        evidence: EvidenceBundle,
        vulnerability_family: str,
    ) -> SemanticContextPackage:
        files = {_norm(item.path): item.content for item in source_files}
        symbol_indexes = {
            path: self._index_symbols(path, content)
            for path, content in files.items()
            if path.endswith(".py")
        }
        target_hints = self._target_hints(finding, root_cause)
        symbols: list[SymbolContext] = []
        changes: list[SemanticChange] = []
        missing: list[str] = []

        for change in plan.planned_changes:
            if change.change_type == "test":
                continue
            path = _resolve_path(change.file, files)
            if path is None:
                missing.append(f"source_file:{change.file}")
                continue
            if not path.endswith(".py"):
                missing.append(f"python_ast_unsupported:{path}")
                continue
            selected = self._select_symbol(
                path,
                symbol_indexes.get(path, ()),
                target_hints.get(path, ()),
            )
            if selected is None:
                missing.append(f"target_symbol:{path}")
                continue
            refs = self._references(selected.symbol, files)
            context = SymbolContext(
                file=path,
                symbol=selected.symbol,
                kind=selected.kind,
                start_line=selected.start_line,
                end_line=selected.end_line,
                indentation=selected.indentation,
                source=selected.source,
                direct_references=tuple(refs[:40]),
            )
            symbols.append(context)
            changes.append(SemanticChange(
                file=path,
                symbol=selected.symbol,
                edit_intent=change.description,
                reason=change.reason,
                causally_required=change.causally_required,
            ))

        relevant_tests = tuple(
            path for path in files
            if _is_test_path(path)
            and (
                not changes
                or any(Path(item.file).stem.lower() in path.lower() for item in changes)
            )
        )
        if not relevant_tests:
            relevant_tests = tuple(path for path in files if _is_test_path(path))[:5]

        commands = tuple(dict.fromkeys([
            *evidence.validation_capabilities.security_commands,
            *evidence.validation_capabilities.test_commands,
        ]))
        invariant = (
            getattr(root_cause, "security_invariant", "")
            or root_cause.root_cause.missing_control
            or plan.remediation_goal
        )
        change_set = ChangeSet(
            finding_id=finding.finding_id,
            vulnerability_family=vulnerability_family,
            security_invariant=invariant,
            base_files={
                path: hashlib.sha256(content.encode("utf-8")).hexdigest()
                for path, content in files.items()
            },
            changes=tuple(changes),
            relevant_tests=relevant_tests,
            validation_commands=commands,
            missing_context=tuple(dict.fromkeys(missing)),
        )
        imports = {
            path: tuple(self._imports(content))
            for path, content in files.items()
            if path.endswith(".py")
        }
        return SemanticContextPackage(
            change_set=change_set,
            symbols=tuple(symbols),
            imports_by_file=imports,
            test_sources={path: files[path] for path in relevant_tests},
        )

    @dataclass(frozen=True, slots=True)
    class _IndexedSymbol:
        symbol: str
        kind: str
        start_line: int
        end_line: int
        indentation: int
        source: str

    def _index_symbols(self, path: str, content: str) -> tuple[_IndexedSymbol, ...]:
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return ()
        lines = content.splitlines(keepends=True)
        result: list[PythonSemanticContextBuilder._IndexedSymbol] = []

        def visit(node: ast.AST, parents: tuple[str, ...] = ()) -> None:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    qualname = ".".join((*parents, child.name))
                    start = child.lineno
                    end = getattr(child, "end_lineno", child.lineno)
                    source = "".join(lines[start - 1:end])
                    result.append(self._IndexedSymbol(
                        symbol=qualname,
                        kind=type(child).__name__,
                        start_line=start,
                        end_line=end,
                        indentation=child.col_offset,
                        source=source,
                    ))
                    visit(child, (*parents, child.name))
                else:
                    visit(child, parents)

        visit(tree)
        return tuple(result)

    @staticmethod
    def _target_hints(
        finding: NormalizedVulnerability,
        root_cause: RootCauseAssessment,
    ) -> dict[str, tuple[tuple[str | None, int | None], ...]]:
        hints: dict[str, list[tuple[str | None, int | None]]] = {}
        for location in finding.locations:
            hints.setdefault(_norm(location.file), []).append(
                (location.function, location.line)
            )
        for affected in root_cause.affected_code:
            hints.setdefault(_norm(affected.file), []).append(
                (affected.function, affected.lines[0] if affected.lines else None)
            )
        return {key: tuple(value) for key, value in hints.items()}

    @staticmethod
    def _select_symbol(
        path: str,
        symbols: tuple[_IndexedSymbol, ...],
        hints: tuple[tuple[str | None, int | None], ...],
    ) -> _IndexedSymbol | None:
        for function, _line in hints:
            if not function:
                continue
            normalized = function.split("(", 1)[0].strip()
            for symbol in symbols:
                if symbol.symbol == normalized or symbol.symbol.endswith("." + normalized):
                    return symbol
        for _function, line in hints:
            if line is None:
                continue
            containing = [
                symbol for symbol in symbols
                if symbol.start_line <= line <= symbol.end_line
            ]
            if containing:
                return min(
                    containing,
                    key=lambda item: item.end_line - item.start_line,
                )
        return symbols[0] if len(symbols) == 1 else None

    @staticmethod
    def _references(symbol: str, files: dict[str, str]) -> list[str]:
        name = symbol.rsplit(".", 1)[-1]
        refs: list[str] = []
        for path, content in files.items():
            if not path.endswith(".py"):
                continue
            try:
                tree = ast.parse(content)
            except SyntaxError:
                continue
            lines = content.splitlines()
            for node in ast.walk(tree):
                matched = (
                    isinstance(node, ast.Name) and node.id == name
                    or isinstance(node, ast.Attribute) and node.attr == name
                )
                if matched and hasattr(node, "lineno"):
                    line = lines[node.lineno - 1].strip()
                    refs.append(f"{path}:{node.lineno}: {line}")
        return refs

    @staticmethod
    def _imports(content: str) -> list[str]:
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return []
        return [
            ast.get_source_segment(content, node) or ""
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
        ]


def _resolve_path(expected: str, files: dict[str, str]) -> str | None:
    normalized = _norm(expected)
    if normalized in files:
        return normalized
    matches = [
        path for path in files
        if path.endswith("/" + normalized) or normalized.endswith("/" + path)
    ]
    return matches[0] if len(matches) == 1 else None


def _norm(path: str) -> str:
    return path.replace("\\", "/").strip().lstrip("./")


def _is_test_path(path: str) -> bool:
    parts = {part.lower() for part in Path(path).parts}
    name = Path(path).name.lower()
    return (
        bool(parts & {"test", "tests", "spec", "specs", "__tests__"})
        or name.startswith("test_")
        or "_test." in name
    )

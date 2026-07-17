"""Deterministic workspace executor for vulnerable direct dependencies."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

from .models import (
    EvidenceBundle,
    NormalizedVulnerability,
    RemediationPlan,
    SourceFile,
)


_MANIFEST_NAMES = {
    "requirements.txt",
    "pyproject.toml",
    "package.json",
    "pom.xml",
    "go.mod",
    "cargo.toml",
}
_LOCKFILE_NAMES = {
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "pdm.lock",
    "uv.lock",
    "pipfile.lock",
    "cargo.lock",
    "go.sum",
    "gradle.lockfile",
}


@dataclass(frozen=True, slots=True)
class DependencyChangeSet:
    finding_id: str
    component: str
    current_version: str
    target_version: str
    ecosystem: str
    dependency_scope: str
    compatibility_risk: str
    manifests: tuple[str, ...]
    lockfiles: tuple[str, ...]
    validation_invariants: tuple[str, ...]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class SCAWorkspaceCheck:
    name: str
    passed: bool
    details: str
    duration_ms: int


class SCADependencyRepairExecutor:
    """Edit direct dependency declarations and verify them in a Git workspace.

    This executor intentionally does not invent lockfile checksums or registry
    metadata.  If a matching lockfile would become stale and cannot be safely
    regenerated offline, the candidate is blocked.
    """

    def __init__(
        self,
        *,
        timeout_seconds: int = 180,
        lockfile_regenerator: Callable[
            [Path, str, str, str, tuple[str, ...]],
            tuple[bool, str],
        ] | None = None,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.lockfile_regenerator = (
            lockfile_regenerator or self._regenerate_lockfiles_offline
        )

    def execute(
        self,
        finding: NormalizedVulnerability,
        plan: RemediationPlan,
        source_files: list[SourceFile],
        evidence: EvidenceBundle,
    ) -> dict:
        del evidence  # The normalized dependency plus repository files are authoritative here.
        dependency = finding.dependency
        if dependency is None:
            return self._blocked("normalized finding has no dependency details")
        component = dependency.component.strip()
        current = _clean_version(dependency.current_version or "")
        if not component or not current:
            return self._blocked(
                "dependency repair requires component and current_version"
            )
        target, target_error = _select_target_version(
            current,
            dependency.fixed_versions,
            dependency.breaking_upgrade,
        )
        if target_error:
            return self._blocked(target_error)

        baseline = {_norm(item.path): item.content for item in source_files}
        manifests = tuple(
            path for path in baseline if Path(path).name.lower() in _MANIFEST_NAMES
        )
        if not manifests:
            return self._blocked("no supported dependency manifest is available")
        planned = {
            _norm(item.file)
            for item in plan.planned_changes
            if item.change_type == "dependency" and item.file
        }
        candidates = tuple(
            path for path in manifests
            if not planned or _path_matches_any(path, planned)
        )
        if not candidates:
            return self._blocked(
                "planned dependency manifests are not present in repository context"
            )
        lockfiles = tuple(
            path for path in baseline if Path(path).name.lower() in _LOCKFILE_NAMES
        )
        ecosystem = _ecosystem(candidates)
        current_major = _version_key(current)[0]
        target_major = _version_key(target)[0]
        compatibility_risk = (
            "declared_breaking_upgrade"
            if dependency.breaking_upgrade is True
            else (
                "major_version_change"
                if current_major != target_major
                else "same_major_upgrade"
            )
        )
        change_set = DependencyChangeSet(
            finding_id=finding.finding_id,
            component=component,
            current_version=current,
            target_version=target,
            ecosystem=ecosystem,
            dependency_scope="direct",
            compatibility_risk=compatibility_risk,
            manifests=candidates,
            lockfiles=lockfiles,
            validation_invariants=(
                "the vulnerable direct version is absent from changed declarations",
                "the selected version is one of the reported fixed versions",
                "all changed manifests remain syntactically valid",
                "lock metadata must not be silently left stale",
            ),
        )

        updates: dict[str, str] = {}
        checks: list[SCAWorkspaceCheck] = []
        edit_errors: list[str] = []
        for path in candidates:
            started = time.perf_counter()
            updated, changed, error = _update_manifest(
                path,
                baseline[path],
                component,
                current,
                target,
            )
            checks.append(SCAWorkspaceCheck(
                name=f"edit:{path}",
                passed=changed and error is None,
                details=error or (
                    f"updated {component} from {current} to {target}"
                    if changed else f"no matching direct declaration for {component} {current}"
                ),
                duration_ms=int((time.perf_counter() - started) * 1000),
            ))
            if error:
                edit_errors.append(f"{path}: {error}")
            elif changed:
                updates[path] = updated

        required_present = {
            path for path in candidates
            if not planned or _path_matches_any(path, planned)
        }
        missing_required = sorted(required_present - set(updates))
        if missing_required:
            edit_errors.append(
                "no exact vulnerable declaration found in planned manifest(s): "
                + ", ".join(missing_required)
            )
        if edit_errors or not updates:
            transitive = [
                path for path in lockfiles
                if _lockfile_has_version(
                    path,
                    baseline[path],
                    component,
                    current,
                )
            ]
            if not updates and transitive:
                edit_errors.append(
                    "dependency appears only in lock metadata and is therefore "
                    "transitive; parent dependency evidence is required: "
                    + ", ".join(transitive)
                )
            return self._blocked(
                "; ".join(edit_errors) or "no dependency declaration was changed",
                change_set,
                checks,
            )

        relevant_locks = [
            path for path in lockfiles
            if _lockfile_relevant(path, updates)
        ]
        with tempfile.TemporaryDirectory(prefix="vuln-agent-sca-") as tmp:
            workspace = Path(tmp) / "workspace"
            self._hydrate(workspace, baseline)
            self._git_baseline(workspace)
            for path, content in updates.items():
                (workspace / path).write_text(content, encoding="utf-8")

            artifact_paths = dict(updates)
            if relevant_locks:
                started = time.perf_counter()
                regenerated, details = self.lockfile_regenerator(
                    workspace,
                    ecosystem,
                    component,
                    target,
                    tuple(relevant_locks),
                )
                lock_check = SCAWorkspaceCheck(
                    "offline_lockfile_regeneration",
                    regenerated,
                    details,
                    int((time.perf_counter() - started) * 1000),
                )
                checks.append(lock_check)
                if not regenerated:
                    return self._blocked(
                        "lockfile regeneration could not be reproduced safely "
                        "offline: " + details,
                        change_set,
                        checks,
                    )
                lock_failures: list[str] = []
                for path in relevant_locks:
                    target_path = workspace / path
                    if not target_path.exists():
                        lock_failures.append(f"{path}: package manager removed lockfile")
                        continue
                    content = target_path.read_text(encoding="utf-8")
                    if content == baseline[path]:
                        lock_failures.append(f"{path}: lockfile did not change")
                    elif not _lockfile_has_version(
                        path,
                        content,
                        component,
                        target,
                    ):
                        lock_failures.append(
                            f"{path}: target version {target} is not resolved"
                        )
                    else:
                        artifact_paths[path] = content
                checks.append(SCAWorkspaceCheck(
                    "lockfile_resolution",
                    not lock_failures,
                    (
                        "; ".join(lock_failures)
                        if lock_failures
                        else "regenerated lockfiles resolve the fixed version"
                    ),
                    0,
                ))
                if lock_failures:
                    return self._blocked(
                        "regenerated lockfile verification failed",
                        change_set,
                        checks,
                    )

            syntax_checks = [
                self._syntax_check(workspace, path) for path in sorted(updates)
            ]
            lock_syntax_checks = [
                self._lock_syntax_check(workspace, path)
                for path in sorted(relevant_locks)
            ]
            checks.extend(syntax_checks)
            checks.extend(lock_syntax_checks)
            oracle = self._dependency_oracle(
                workspace,
                updates,
                component,
                current,
                target,
            )
            checks.append(oracle)
            if any(not item.passed for item in [
                *syntax_checks,
                *lock_syntax_checks,
                oracle,
            ]):
                return self._blocked(
                    "SCA workspace verification failed",
                    change_set,
                    checks,
                )

            artifacts = self._git_artifacts(workspace, artifact_paths)
            if not artifacts:
                return self._blocked(
                    "dependency edits produced no Git diff",
                    change_set,
                    checks,
                )
            return {
                "summary": (
                    f"SCA executor upgraded {component} from {current} to {target} "
                    f"across {len(artifacts)} manifest(s)"
                ),
                "artifacts": artifacts,
                "changed_files": [
                    {
                        "file": item["target"],
                        "change_type": "dependency",
                        "reason": (
                            f"replace vulnerable direct dependency {component} "
                            f"{current} with fixed version {target}"
                        ),
                    }
                    for item in artifacts
                ],
                "security_notes": [
                    "Target version was selected only from reported fixed_versions.",
                    "Manifest syntax and the exact dependency declaration were re-parsed.",
                    *(
                        ["Lock metadata was regenerated by an offline package-manager command."]
                        if relevant_locks else []
                    ),
                    "Git generated the final unified diff from verified workspace edits.",
                ],
                "assumptions": [],
                "risks": [
                    (
                        f"Compatibility risk classification: {compatibility_risk}. "
                        "Full consumer compatibility requires the configured build "
                        "and regression commands."
                    )
                ],
                "needs_human_review": True,
                "blocked_reason": None,
                "llm_calls": 0,
                "change_set": change_set.to_dict(),
                "workspace_checks": [asdict(item) for item in checks],
                "executor": "sca_dependency_workspace_executor",
            }

    @staticmethod
    def _syntax_check(workspace: Path, path: str) -> SCAWorkspaceCheck:
        started = time.perf_counter()
        content = (workspace / path).read_text(encoding="utf-8")
        name = Path(path).name.lower()
        try:
            if name == "package.json":
                parsed = json.loads(content)
                if not isinstance(parsed, dict):
                    raise ValueError("package.json root must be an object")
            elif name == "pyproject.toml" or name == "cargo.toml":
                tomllib.loads(content)
            elif name == "pom.xml":
                ET.fromstring(content)
            elif name == "go.mod":
                if not re.search(r"(?m)^\s*module\s+\S+", content):
                    raise ValueError("go.mod has no module declaration")
            elif name == "requirements.txt":
                if "\x00" in content:
                    raise ValueError("requirements.txt contains NUL")
            else:
                raise ValueError(f"unsupported manifest {name}")
            passed, details = True, "manifest syntax is valid"
        except (ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError, ET.ParseError) as exc:
            passed, details = False, str(exc)
        return SCAWorkspaceCheck(
            f"syntax:{path}",
            passed,
            details,
            int((time.perf_counter() - started) * 1000),
        )

    @staticmethod
    def _dependency_oracle(
        workspace: Path,
        updates: dict[str, str],
        component: str,
        current: str,
        target: str,
    ) -> SCAWorkspaceCheck:
        started = time.perf_counter()
        failures: list[str] = []
        for path in updates:
            content = (workspace / path).read_text(encoding="utf-8")
            versions = _declared_versions(path, content, component)
            if target not in versions:
                failures.append(f"{path}: target {target} not declared")
            if current != target and current in versions:
                failures.append(f"{path}: vulnerable version {current} remains")
        return SCAWorkspaceCheck(
            "fixed_dependency_declaration",
            not failures,
            "; ".join(failures) if failures else "fixed direct dependency is declared",
            int((time.perf_counter() - started) * 1000),
        )

    @staticmethod
    def _lock_syntax_check(
        workspace: Path,
        path: str,
    ) -> SCAWorkspaceCheck:
        started = time.perf_counter()
        content = (workspace / path).read_text(encoding="utf-8")
        name = Path(path).name.lower()
        try:
            if name in {
                "package-lock.json",
                "npm-shrinkwrap.json",
                "pipfile.lock",
            }:
                parsed = json.loads(content)
                if not isinstance(parsed, dict):
                    raise ValueError("lockfile root must be an object")
            elif name in {"poetry.lock", "pdm.lock", "uv.lock", "cargo.lock"}:
                tomllib.loads(content)
            elif not content.strip():
                raise ValueError("lockfile is empty")
            passed, details = True, "lockfile syntax is valid"
        except (
            ValueError,
            json.JSONDecodeError,
            tomllib.TOMLDecodeError,
        ) as exc:
            passed, details = False, str(exc)
        return SCAWorkspaceCheck(
            f"syntax:{path}",
            passed,
            details,
            int((time.perf_counter() - started) * 1000),
        )

    def _regenerate_lockfiles_offline(
        self,
        workspace: Path,
        ecosystem: str,
        component: str,
        target: str,
        lockfiles: tuple[str, ...],
    ) -> tuple[bool, str]:
        """Use the owning package manager without allowing registry access."""
        names = {Path(path).name.lower() for path in lockfiles}
        command: list[str] | None = None
        environment = os.environ.copy()
        if names.intersection({"package-lock.json", "npm-shrinkwrap.json"}):
            if not shutil.which("npm"):
                return False, "npm is not installed"
            command = [
                "npm", "install", "--package-lock-only", "--ignore-scripts",
                "--offline", "--no-audit", "--no-fund",
            ]
        elif "pnpm-lock.yaml" in names:
            if not shutil.which("pnpm"):
                return False, "pnpm is not installed"
            command = [
                "pnpm", "install", "--lockfile-only", "--offline",
                "--ignore-scripts",
            ]
        elif "yarn.lock" in names:
            if not shutil.which("yarn"):
                return False, "yarn is not installed"
            command = [
                "yarn", "install", "--offline", "--ignore-scripts",
                "--non-interactive",
            ]
        elif "uv.lock" in names:
            if not shutil.which("uv"):
                return False, "uv is not installed"
            command = ["uv", "lock", "--offline"]
        elif "pdm.lock" in names:
            if not shutil.which("pdm"):
                return False, "pdm is not installed"
            command = ["pdm", "lock", "--offline"]
        elif "pipfile.lock" in names:
            if not shutil.which("pipenv"):
                return False, "pipenv is not installed"
            environment["PIP_NO_INDEX"] = "1"
            command = ["pipenv", "lock"]
        elif "cargo.lock" in names:
            if ecosystem != "cargo" or not shutil.which("cargo"):
                return False, "cargo is not installed"
            command = [
                "cargo", "update", "-p", component.split(":")[-1],
                "--precise", target, "--offline",
            ]
        elif "go.sum" in names:
            if ecosystem != "go" or not shutil.which("go"):
                return False, "go is not installed"
            environment["GOPROXY"] = "off"
            environment["GOSUMDB"] = "off"
            command = ["go", "mod", "tidy"]
        elif "poetry.lock" in names:
            return (
                False,
                "Poetry exposes no consistently offline lock operation across "
                "supported versions; provide a reproducible lockfile regenerator",
            )
        else:
            return False, "no offline lockfile strategy for " + ", ".join(sorted(names))

        try:
            result = subprocess.run(
                command,
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return False, f"{' '.join(command)} timed out"
        output = "\n".join(
            part.strip() for part in (result.stdout, result.stderr) if part.strip()
        )
        if result.returncode != 0:
            return (
                False,
                f"{' '.join(command)} exited {result.returncode}: {output[-2000:]}",
            )
        return True, f"{' '.join(command)} completed offline"

    @staticmethod
    def _hydrate(workspace: Path, baseline: dict[str, str]) -> None:
        workspace.mkdir(parents=True, exist_ok=True)
        for path, content in baseline.items():
            target = workspace / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")

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
        updates: dict[str, str],
    ) -> list[dict]:
        artifacts: list[dict] = []
        for path in sorted(updates):
            diff = subprocess.run(
                ["git", "diff", "--no-ext-diff", "--", path],
                cwd=workspace,
                capture_output=True,
                text=True,
                check=True,
            ).stdout
            if diff:
                artifacts.append({
                    "patch_type": "dependency",
                    "target": path,
                    "content": diff.rstrip(),
                    "description": (
                        "Git-generated direct dependency upgrade from the verified "
                        "SCA workspace"
                    ),
                })
        return artifacts

    @staticmethod
    def _blocked(
        reason: str,
        change_set: DependencyChangeSet | None = None,
        checks: list[SCAWorkspaceCheck] | None = None,
    ) -> dict:
        return {
            "artifacts": [],
            "changed_files": [],
            "blocked_reason": reason,
            "risks": [reason],
            "needs_human_review": True,
            "llm_calls": 0,
            "change_set": change_set.to_dict() if change_set else None,
            "workspace_checks": [asdict(item) for item in checks or []],
            "executor": "sca_dependency_workspace_executor",
        }


def _update_manifest(
    path: str,
    content: str,
    component: str,
    current: str,
    target: str,
) -> tuple[str, bool, str | None]:
    name = Path(path).name.lower()
    if name == "requirements.txt":
        return _update_requirements(content, component, current, target)
    if name == "pyproject.toml":
        return _update_pyproject(content, component, current, target)
    if name == "package.json":
        return _update_package_json(content, component, current, target)
    if name == "pom.xml":
        return _update_pom(content, component, current, target)
    if name == "go.mod":
        return _update_go_mod(content, component, current, target)
    if name == "cargo.toml":
        return _update_cargo(content, component, current, target)
    return content, False, f"unsupported manifest {name}"


def _update_requirements(
    content: str,
    component: str,
    current: str,
    target: str,
) -> tuple[str, bool, str | None]:
    normalized = _package_key(component)
    pattern = re.compile(
        r"(?im)^(?P<prefix>\s*(?P<name>[A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*)"
        r"(?P<op>===|==|~=|>=)\s*(?P<version>[A-Za-z0-9_.+!-]+)(?P<suffix>\s*(?:;.*)?(?:#.*)?)$"
    )
    changed = False

    def replace(match: re.Match[str]) -> str:
        nonlocal changed
        if _package_key(match.group("name")) != normalized:
            return match.group(0)
        if _clean_version(match.group("version")) != current:
            return match.group(0)
        changed = True
        return (
            f"{match.group('prefix')}{match.group('op')}{target}"
            f"{match.group('suffix')}"
        )

    return pattern.sub(replace, content), changed, None


def _update_pyproject(
    content: str,
    component: str,
    current: str,
    target: str,
) -> tuple[str, bool, str | None]:
    package = component.split(":")[-1]
    changed = False
    pep_pattern = re.compile(
        rf"(?P<prefix>[\"']{re.escape(package)}(?:\[[^\]]+\])?\s*"
        rf"(?:===|==|~=|>=)\s*){re.escape(current)}(?P<suffix>[^\"']*[\"'])",
        re.IGNORECASE,
    )
    content, count = pep_pattern.subn(
        lambda match: f"{match.group('prefix')}{target}{match.group('suffix')}",
        content,
    )
    changed = count > 0
    poetry_pattern = re.compile(
        rf"(?im)^(?P<prefix>\s*{re.escape(package)}\s*=\s*[\"']"
        rf"(?P<operator>\^|~|>=|==)?){re.escape(current)}(?P<suffix>[\"']\s*(?:#.*)?)$"
    )
    content, count = poetry_pattern.subn(
        lambda match: (
            f"{match.group('prefix')}{target}{match.group('suffix')}"
        ),
        content,
    )
    return content, changed or count > 0, None


def _update_package_json(
    content: str,
    component: str,
    current: str,
    target: str,
) -> tuple[str, bool, str | None]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        return content, False, f"invalid package.json: {exc}"
    declared = False
    for section in (
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ):
        values = data.get(section)
        if isinstance(values, dict) and component in values:
            declared = True
            if _clean_version(str(values[component])) != current:
                return (
                    content,
                    False,
                    f"{component} declaration does not match current_version {current}",
                )
    if not declared:
        return content, False, None
    pattern = re.compile(
        rf'(?m)(^\s*"{re.escape(component)}"\s*:\s*")'
        rf"(?P<operator>\^|~|>=|==)?{re.escape(current)}(?P<suffix>\"\s*,?\s*$)"
    )
    updated, count = pattern.subn(
        lambda match: (
            f"{match.group(1)}{match.group('operator') or ''}{target}"
            f"{match.group('suffix')}"
        ),
        content,
    )
    return updated, count > 0, None


def _update_pom(
    content: str,
    component: str,
    current: str,
    target: str,
) -> tuple[str, bool, str | None]:
    artifact = component.split(":")[-1]
    changed = False
    property_pattern = re.compile(
        rf"(<(?P<property>[A-Za-z0-9_.-]*{re.escape(artifact)}[A-Za-z0-9_.-]*"
        rf"\.version)>\s*){re.escape(current)}(\s*</(?P=property)>)",
        re.IGNORECASE,
    )
    content, property_count = property_pattern.subn(
        lambda match: f"{match.group(1)}{target}{match.group(3)}",
        content,
    )
    changed = property_count > 0
    dependency_pattern = re.compile(
        rf"(?P<prefix><dependency\b[^>]*>.*?<artifactId>\s*"
        rf"{re.escape(artifact)}\s*</artifactId>.*?<version>\s*)"
        rf"{re.escape(current)}(?P<suffix>\s*</version>.*?</dependency>)",
        re.IGNORECASE | re.DOTALL,
    )
    content, direct_count = dependency_pattern.subn(
        lambda match: f"{match.group('prefix')}{target}{match.group('suffix')}",
        content,
    )
    return content, changed or direct_count > 0, None


def _update_go_mod(
    content: str,
    component: str,
    current: str,
    target: str,
) -> tuple[str, bool, str | None]:
    pattern = re.compile(
        rf"(?m)^(?P<prefix>\s*(?:require\s+)?{re.escape(component)}\s+v?)"
        rf"{re.escape(current)}(?P<suffix>\s*(?://.*)?)$"
    )
    updated, count = pattern.subn(
        lambda match: f"{match.group('prefix')}{target}{match.group('suffix')}",
        content,
    )
    return updated, count > 0, None


def _update_cargo(
    content: str,
    component: str,
    current: str,
    target: str,
) -> tuple[str, bool, str | None]:
    package = component.split(":")[-1]
    simple = re.compile(
        rf"(?im)^(?P<prefix>\s*{re.escape(package)}\s*=\s*[\"']"
        rf"(?P<operator>\^|~|>=|==|=)?){re.escape(current)}(?P<suffix>[\"']\s*)$"
    )
    content, simple_count = simple.subn(
        lambda match: f"{match.group('prefix')}{target}{match.group('suffix')}",
        content,
    )
    inline = re.compile(
        rf"(?im)^(?P<prefix>\s*{re.escape(package)}\s*=\s*\{{[^}}\n]*"
        rf"version\s*=\s*[\"'](?P<operator>\^|~|>=|==|=)?)"
        rf"{re.escape(current)}(?P<suffix>[\"'][^}}\n]*\}}\s*)$"
    )
    content, inline_count = inline.subn(
        lambda match: f"{match.group('prefix')}{target}{match.group('suffix')}",
        content,
    )
    return content, simple_count + inline_count > 0, None


def _declared_versions(path: str, content: str, component: str) -> set[str]:
    name = Path(path).name.lower()
    versions: set[str] = set()
    if name == "package.json":
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return versions
        for section in (
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
        ):
            values = data.get(section)
            if isinstance(values, dict) and component in values:
                versions.add(_clean_version(str(values[component])))
        return versions
    artifact = component.split(":")[-1]
    for line in content.splitlines():
        if _package_key(artifact) not in _package_key(line):
            continue
        versions.update(
            _clean_version(value)
            for value in re.findall(r"\d+(?:\.\d+)+(?:[-+][A-Za-z0-9.]+)?", line)
        )
    if name == "pom.xml":
        versions.update(
            _clean_version(value)
            for value in re.findall(
                rf"<[^>]*{re.escape(artifact)}[^>]*version[^>]*>\s*([^<]+)",
                content,
                flags=re.IGNORECASE,
            )
        )
        dependency_match = re.search(
            rf"<dependency\b[^>]*>.*?<artifactId>\s*{re.escape(artifact)}"
            rf"\s*</artifactId>.*?<version>\s*([^<]+)",
            content,
            flags=re.IGNORECASE | re.DOTALL,
        )
        if dependency_match:
            versions.add(_clean_version(dependency_match.group(1)))
    return {value for value in versions if value}


def _select_target_version(
    current: str,
    fixed_versions: list[str],
    breaking_upgrade: bool | None,
) -> tuple[str, str | None]:
    candidates = [_clean_version(item) for item in fixed_versions]
    candidates = [item for item in candidates if item and _version_key(item)]
    if not candidates:
        return "", "dependency repair requires at least one parseable fixed_version"
    candidates = sorted(set(candidates), key=_version_key)
    current_key = _version_key(current)
    candidates = [item for item in candidates if _version_key(item) >= current_key]
    if not candidates:
        return "", "all reported fixed_versions are older than current_version"
    if breaking_upgrade is False:
        current_major = current_key[0] if current_key else None
        compatible = [
            item for item in candidates
            if _version_key(item) and _version_key(item)[0] == current_major
        ]
        if compatible:
            return compatible[0], None
        return (
            "",
            "finding declares a non-breaking upgrade but no fixed version shares "
            "the current major version",
        )
    return candidates[0], None


def _clean_version(value: str) -> str:
    cleaned = str(value).strip().strip("\"'")
    cleaned = re.sub(r"^(?:v|===|==|=|~=|>=|\^|~)\s*", "", cleaned)
    return cleaned.strip()


def _version_key(value: str) -> tuple[int, ...]:
    match = re.match(r"^(\d+(?:\.\d+)*)(?:[-+].*)?$", value)
    return tuple(int(part) for part in match.group(1).split(".")) if match else ()


def _package_key(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value.strip().lower())


def _ecosystem(paths: tuple[str, ...]) -> str:
    names = {Path(path).name.lower() for path in paths}
    if "pom.xml" in names:
        return "maven"
    if "package.json" in names:
        return "npm"
    if "go.mod" in names:
        return "go"
    if "cargo.toml" in names:
        return "cargo"
    return "python"


def _lockfile_relevant(path: str, updates: dict[str, str]) -> bool:
    name = Path(path).name.lower()
    manifest_names = {Path(item).name.lower() for item in updates}
    if name in {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"}:
        return "package.json" in manifest_names
    if name in {"poetry.lock", "pdm.lock", "uv.lock"}:
        return "pyproject.toml" in manifest_names
    if name == "pipfile.lock":
        return "pipfile" in manifest_names
    if name == "cargo.lock":
        return "cargo.toml" in manifest_names
    if name == "go.sum":
        return "go.mod" in manifest_names
    if name == "gradle.lockfile":
        return False
    return False


def _lockfile_has_version(
    path: str,
    content: str,
    component: str,
    version: str,
) -> bool:
    name = Path(path).name.lower()
    package = component.split(":")[-1]
    if name in {"package-lock.json", "npm-shrinkwrap.json"}:
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return False
        packages = data.get("packages")
        if isinstance(packages, dict):
            for key, value in packages.items():
                if (
                    isinstance(value, dict)
                    and (
                        key.replace("\\", "/").endswith("/node_modules/" + component)
                        or key.replace("\\", "/") == "node_modules/" + component
                    )
                    and _clean_version(str(value.get("version", ""))) == version
                ):
                    return True
        dependencies = data.get("dependencies")
        if isinstance(dependencies, dict):
            value = dependencies.get(component)
            if (
                isinstance(value, dict)
                and _clean_version(str(value.get("version", ""))) == version
            ):
                return True
        return False
    if name == "pipfile.lock":
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return False
        for section in ("default", "develop"):
            values = data.get(section)
            if not isinstance(values, dict):
                continue
            for key, value in values.items():
                if _package_key(key) != _package_key(package) or not isinstance(value, dict):
                    continue
                if _clean_version(str(value.get("version", ""))) == version:
                    return True
        return False
    if name in {"poetry.lock", "pdm.lock", "uv.lock", "cargo.lock"}:
        try:
            data = tomllib.loads(content)
        except tomllib.TOMLDecodeError:
            return False
        values = data.get("package", [])
        if isinstance(values, dict):
            values = list(values.values())
        return any(
            isinstance(item, dict)
            and _package_key(str(item.get("name", ""))) == _package_key(package)
            and _clean_version(str(item.get("version", ""))) == version
            for item in values
        )
    if name == "go.sum":
        return bool(re.search(
            rf"(?m)^{re.escape(component)}\s+v{re.escape(version)}(?:/go\.mod)?\s+",
            content,
        ))
    escaped_component = re.escape(component)
    escaped_package = re.escape(package)
    escaped_version = re.escape(version)
    return bool(
        re.search(
            rf"(?:{escaped_component}|{escaped_package})[^\n]{{0,180}}"
            rf"(?:version\s*[:=]\s*[\"']?|@|/|v){escaped_version}\b",
            content,
            flags=re.IGNORECASE,
        )
        or re.search(
            rf"(?:{escaped_component}|{escaped_package})@{escaped_version}\b",
            content,
            flags=re.IGNORECASE,
        )
    )


def _path_matches_any(path: str, candidates: set[str]) -> bool:
    return any(
        path == item
        or path.endswith("/" + item)
        or item.endswith("/" + path)
        or Path(path).name.lower() == Path(item).name.lower()
        for item in candidates
    )


def _norm(path: str) -> str:
    return path.replace("\\", "/").strip().lstrip("./")

"""Deterministic, bounded evidence collection shared by all analysis stages."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections import OrderedDict
from dataclasses import asdict
from pathlib import PurePosixPath

from .models import (
    CodePointEvidence,
    CodeSlice,
    ConfigEvidence,
    DependencyEvidence,
    EngineeringContext,
    EntryPointEvidence,
    EvidenceBundle,
    FileEvidence,
    NormalizedVulnerability,
    RepositoryContext,
    RepositorySummary,
    SourceFile,
    TestEvidence,
    ValidationCapabilities,
)


_LANGUAGES = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".java": "Java",
    ".go": "Go", ".rb": "Ruby", ".php": "PHP", ".rs": "Rust",
    ".cs": "C#", ".kt": "Kotlin", ".scala": "Scala",
}
_MANIFESTS = {
    "requirements.txt", "pyproject.toml", "setup.py", "setup.cfg", "poetry.lock",
    "pipfile", "pipfile.lock", "package.json", "package-lock.json", "yarn.lock",
    "pnpm-lock.yaml", "pom.xml", "build.gradle", "build.gradle.kts", "go.mod",
    "go.sum", "cargo.toml", "cargo.lock", "composer.json", "gemfile",
}
_CONFIG_NAMES = {
    "pytest.ini", "tox.ini", ".semgrep.yml", ".semgrep.yaml", "semgrep.yml",
    "semgrep.yaml", "dockerfile", "docker-compose.yml", "docker-compose.yaml",
}
_TEST_PARTS = {"test", "tests", "spec", "specs", "__tests__"}

_ROUTE_PATTERNS = (
    ("FastAPI/Flask", re.compile(r"@(?:\w+\.)?(get|post|put|patch|delete|route)\(\s*['\"]([^'\"]+)"), 1, 2),
    ("Django", re.compile(r"\bpath\(\s*['\"]([^'\"]+)['\"]"), None, 1),
    ("Express", re.compile(r"\b(?:app|router)\.(get|post|put|patch|delete|use)\(\s*['\"]([^'\"]+)"), 1, 2),
    ("Spring", re.compile(r"@(?:Get|Post|Put|Patch|Delete|Request)Mapping\(?(?:value\s*=\s*)?['\"]([^'\"]+)"), None, 1),
    ("Go", re.compile(r"(?:Handle|HandleFunc)\(\s*['\"]([^'\"]+)['\"]"), None, 1),
)

_SINK_FAMILIES = {
    "sql": (r"\b(?:execute|executemany|raw|cursor\.execute|createQuery|query)\s*\(",),
    "ssrf": (r"\b(?:requests\.(?:get|post|request)|httpx\.|urllib\.|urlopen|openConnection)\s*\(",),
    "command": (r"\b(?:os\.system|subprocess\.|Runtime\.getRuntime\(\)\.exec|exec|spawn)\s*\(",),
    "deserialization": (r"\b(?:pickle\.loads?|yaml\.load|ObjectInputStream|unserialize|marshal\.loads?)\s*\(",),
    "path": (r"\b(?:open|Path|send_file|send_from_directory|read_text|write_text)\s*\(",),
    "xss": (r"\b(?:render_template_string|innerHTML|dangerouslySetInnerHTML|mark_safe|Html\.raw)\b",),
    "auth": (r"\b(?:decode|verify|authenticate|authorize|check_password|prepare_key)\s*\(", r"\balgorithms?\b"),
    "crypto": (r"\b(?:md5|sha1|DES|RC4|ECB|HMACAlgorithm|JWSAlgorithm|prepare_key)\b",),
    "secret": (r"\b(?:password|passwd|secret|token|api[_-]?key|credential|private[_-]?key)\b",),
}
_GENERIC_SINKS = (r"\b(?:eval|exec|open|execute|decode|load|loads|render)\s*\(",)
_SOURCE_PATTERNS = (
    re.compile(r"\b(?:request\.(?:args|form|json|values|headers|cookies|query_params|path_params|body)|req\.(?:query|body|params|headers)|input\s*\(|getenv\s*\(|environ\[)"),
    re.compile(r"\b(?:authorization|bearer|jwt|token|username|password|url|path|query|payload|algorithm|alg)\b", re.IGNORECASE),
)
_SECRET_LINE = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|credential|private[_-]?key)(\s*[:=]\s*)(['\"]?)[^\s,'\"}]+"
)
_BEARER_VALUE = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+")
_ACCESS_KEY = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")


class EvidenceCollector:
    """Collect a reusable evidence bundle without LLM or workspace mutation."""

    _cache: OrderedDict[str, EvidenceBundle] = OrderedDict()

    def __init__(
        self,
        *,
        context_lines: int = 80,
        candidate_context_lines: int = 24,
        max_slices: int = 20,
        max_candidates_per_kind: int = 20,
        max_total_chars: int = 50_000,
        cache_size: int = 64,
    ) -> None:
        self.context_lines = max(1, context_lines)
        self.candidate_context_lines = max(1, candidate_context_lines)
        self.max_slices = max(1, max_slices)
        self.max_candidates_per_kind = max(1, max_candidates_per_kind)
        self.max_total_chars = max(1_000, max_total_chars)
        self.cache_size = max(1, cache_size)

    def collect(
        self,
        finding: NormalizedVulnerability,
        source_files: list[SourceFile] | None = None,
        repository: RepositoryContext | None = None,
        engineering: EngineeringContext | None = None,
    ) -> EvidenceBundle:
        repository = repository or RepositoryContext()
        engineering = engineering or EngineeringContext()
        files = self._normalized_files(source_files or [])
        cache_key = self._cache_key(finding, files, repository, engineering)
        cached = self._cache.get(cache_key)
        if cached is not None:
            self._cache.move_to_end(cache_key)
            return copy.deepcopy(cached)

        warnings: list[str] = []
        slices: list[CodeSlice] = []
        slice_keys: set[tuple[str, int, int]] = set()
        char_budget = [self.max_total_chars]
        target_files = self._target_file_evidence(finding, files, warnings)
        file_map = {item.path: item.content for item in files}
        scan_files = self._prioritize_files(files, {item.path for item in target_files})

        for location in finding.locations:
            path = self._match_path(location.file, file_map)
            if not path:
                continue
            lines = file_map[path].splitlines()
            center = location.line or self._find_symbol_line(lines, location.function) or 1
            self._add_slice(
                slices, slice_keys, char_budget, path, lines, center,
                self.context_lines,
                f"finding target: {location.function or location.file}",
            )

        entry_points = self._collect_entry_points(scan_files, slices, slice_keys, char_budget)
        source_candidates = self._collect_candidates(
            scan_files, _SOURCE_PATTERNS, "source", "possible untrusted-input source",
            slices, slice_keys, char_budget,
        )
        sink_patterns = tuple(re.compile(pattern, re.IGNORECASE) for pattern in self._sink_patterns(finding))
        sink_candidates = self._collect_candidates(
            scan_files, sink_patterns, "sink", f"{finding.vulnerability_type} sink pattern",
            slices, slice_keys, char_budget,
        )

        dependency_evidence = self._collect_dependency_evidence(finding, files)
        test_evidence, capabilities = self._collect_tests_and_capabilities(files, engineering, finding)
        config_evidence = self._collect_config_evidence(files, finding)

        if not files:
            warnings.append("no source files were supplied; evidence is limited to the normalized finding")
        if not slices:
            warnings.append("no bounded code slice could be selected")
        if not sink_candidates and finding.dependency is None:
            warnings.append("no vulnerability-family sink candidate was found")
        if char_budget[0] <= 0:
            warnings.append("code slice character budget was exhausted")

        languages = sorted({self._language(item.path) for item in files if self._language(item.path)})
        if engineering.language and engineering.language not in languages:
            languages.insert(0, engineering.language)
        frameworks = [value for value in [engineering.framework] if value]
        frameworks.extend(ep.framework for ep in entry_points if ep.framework and ep.framework not in frameworks)
        manifests = [item.path for item in files if self._basename(item.path) in _MANIFESTS]
        summary = RepositorySummary(
            repository=repository.repository or finding.repository,
            revision=repository.base_revision or finding.revision,
            file_count=len(files),
            languages=languages,
            frameworks=frameworks,
            manifests=manifests,
        )

        hash_payload = {
            "cache_key": cache_key,
            "targets": [item.path for item in target_files],
            "slices": [(item.path, item.start_line, item.end_line) for item in slices],
            "sources": [(item.path, item.line, item.pattern) for item in source_candidates],
            "sinks": [(item.path, item.line, item.pattern) for item in sink_candidates],
        }
        bundle_hash = hashlib.sha256(
            json.dumps(hash_payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        bundle = EvidenceBundle(
            finding_id=finding.finding_id,
            repository_summary=summary,
            target_files=target_files,
            code_slices=slices,
            entry_points=entry_points,
            source_candidates=source_candidates,
            sink_candidates=sink_candidates,
            dependency_evidence=dependency_evidence,
            test_evidence=test_evidence,
            config_evidence=config_evidence,
            validation_capabilities=capabilities,
            collection_warnings=list(dict.fromkeys(warnings)),
            bundle_hash=bundle_hash,
        )
        self._cache[cache_key] = copy.deepcopy(bundle)
        self._cache.move_to_end(cache_key)
        while len(self._cache) > self.cache_size:
            self._cache.popitem(last=False)
        return bundle

    @staticmethod
    def _normalized_files(source_files: list[SourceFile]) -> list[SourceFile]:
        deduped: dict[str, str] = {}
        for item in source_files:
            path = EvidenceCollector._clean_path(item.path)
            if path and path not in deduped:
                deduped[path] = item.content or ""
        return [SourceFile(path, deduped[path]) for path in sorted(deduped)]

    def _cache_key(self, finding, files, repository, engineering) -> str:
        payload = {
            "finding": finding.to_dict(),
            "files": [(item.path, hashlib.sha256(item.content.encode("utf-8")).hexdigest()) for item in files],
            "repository": asdict(repository),
            "engineering": asdict(engineering),
            "schema": 1,
            "collector": {
                "context_lines": self.context_lines,
                "candidate_context_lines": self.candidate_context_lines,
                "max_slices": self.max_slices,
                "max_candidates_per_kind": self.max_candidates_per_kind,
                "max_total_chars": self.max_total_chars,
            },
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
        ).hexdigest()

    def _target_file_evidence(self, finding, files, warnings) -> list[FileEvidence]:
        file_map = {item.path: item.content for item in files}
        result: list[FileEvidence] = []
        seen: set[str] = set()
        for location in finding.locations:
            path = self._match_path(location.file, file_map)
            if not path:
                warnings.append(f"reported target file was not supplied: {location.file}")
                continue
            if path in seen:
                continue
            seen.add(path)
            content = file_map[path]
            result.append(FileEvidence(
                path=path,
                matched_by="exact_path" if path == self._clean_path(location.file) else "suffix_path",
                line_count=len(content.splitlines()),
                sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
                language=self._language(path),
            ))
        return result

    def _collect_entry_points(self, files, slices, slice_keys, char_budget):
        result: list[EntryPointEvidence] = []
        for item in files:
            if self._is_sensitive_env(item.path):
                continue
            lines = item.content.splitlines()
            for line_no, line in enumerate(lines, 1):
                for framework, pattern, method_group, route_group in _ROUTE_PATTERNS:
                    match = pattern.search(line)
                    if not match:
                        continue
                    method = match.group(method_group).upper() if method_group else "ANY"
                    route = match.group(route_group)
                    snippet_id = self._add_slice(
                        slices, slice_keys, char_budget, item.path, lines, line_no,
                        self.candidate_context_lines, f"{framework} entry point",
                    )
                    result.append(EntryPointEvidence(route, method, item.path, line_no, framework, snippet_id))
                    if len(result) >= self.max_candidates_per_kind:
                        return result
        return result

    def _collect_candidates(self, files, patterns, kind, reason, slices, slice_keys, char_budget):
        result: list[CodePointEvidence] = []
        for item in files:
            if self._is_sensitive_env(item.path) or self._is_non_code(item.path):
                continue
            lines = item.content.splitlines()
            for line_no, line in enumerate(lines, 1):
                for pattern in patterns:
                    match = pattern.search(line)
                    if not match:
                        continue
                    snippet_id = self._add_slice(
                        slices, slice_keys, char_budget, item.path, lines, line_no,
                        self.candidate_context_lines, reason,
                    )
                    result.append(CodePointEvidence(
                        symbol=self._nearest_symbol(lines, line_no),
                        path=item.path,
                        line=line_no,
                        kind=kind,
                        pattern=match.group(0)[:120],
                        reason=reason,
                        snippet_id=snippet_id,
                    ))
                    break
                if len(result) >= self.max_candidates_per_kind:
                    return result
        return result

    def _collect_dependency_evidence(self, finding, files):
        result: list[DependencyEvidence] = []
        dependency = finding.dependency
        if dependency:
            result.append(DependencyEvidence(
                dependency.component, dependency.current_version, None, None, "normalized_finding"
            ))
            needle = dependency.component.lower().split(":")[-1]
            for item in files:
                if self._basename(item.path) not in _MANIFESTS:
                    continue
                for line_no, line in enumerate(item.content.splitlines(), 1):
                    if needle and needle in line.lower():
                        result.append(DependencyEvidence(
                            dependency.component, dependency.current_version, item.path, line_no, "manifest"
                        ))
                        break
        return result

    def _collect_tests_and_capabilities(self, files, engineering, finding):
        paths = [item.path for item in files]
        basenames = {self._basename(path) for path in paths}
        test_paths = [path for path in paths if self._is_test_path(path)]
        detected: list[str] = []
        build: list[str] = []
        tests = list(engineering.available_test_commands)

        if "pyproject.toml" in basenames or "pytest.ini" in basenames or test_paths and any(p.endswith(".py") for p in test_paths):
            detected.append("python")
            build.append("python -m compileall -q .")
            tests.append("python -m pytest")
        if "package.json" in basenames:
            detected.append("npm")
            tests.append("npm test")
        if "pom.xml" in basenames:
            detected.append("maven")
            tests.append("mvn test")
        if "go.mod" in basenames:
            detected.append("go")
            tests.append("go test ./...")
        if "cargo.toml" in basenames:
            detected.append("cargo")
            tests.append("cargo test")

        scanner: list[str] = []
        if basenames.intersection({".semgrep.yml", ".semgrep.yaml", "semgrep.yml", "semgrep.yaml"}):
            detected.append("semgrep")
            scanner.append("semgrep scan --config auto .")

        target_stems = {
            PurePosixPath(location.file).stem.lower()
            for location in finding.locations if location.file
        }
        vuln_terms = {
            term for term in re.findall(r"[a-z0-9]+", finding.vulnerability_type.lower())
            if len(term) >= 4 and term not in {"vulnerability", "exposure"}
        }
        test_evidence = []
        for path in test_paths[:20]:
            lowered = path.lower()
            related = any(stem and stem in lowered for stem in target_stems) or any(
                term in lowered for term in vuln_terms
            )
            test_evidence.append(TestEvidence(path, self._test_framework(path), None, related, None))
        for command in dict.fromkeys(tests):
            test_evidence.append(TestEvidence(None, None, command, False, None))
        security = [command for command in tests if "security" in command.lower()]
        for item in test_evidence:
            if item.related and item.path and item.path.endswith(".py"):
                security.append(f"python -m pytest {item.path}")
        return test_evidence, ValidationCapabilities(
            build_commands=list(dict.fromkeys(build)),
            test_commands=list(dict.fromkeys(tests)),
            security_commands=list(dict.fromkeys(security)),
            scanner_commands=scanner,
            detected_tools=list(dict.fromkeys(detected)),
        )

    def _collect_config_evidence(self, files, finding):
        result: list[ConfigEvidence] = []
        for item in files:
            base = self._basename(item.path)
            if base not in _CONFIG_NAMES and base not in _MANIFESTS and not self._is_sensitive_env(item.path):
                continue
            if self._is_sensitive_env(item.path):
                keys = []
                for line_no, line in enumerate(item.content.splitlines(), 1):
                    match = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", line)
                    if match:
                        keys.append((line_no, match.group(1)))
                result.extend(ConfigEvidence(item.path, key, line_no, "<redacted>", "environment") for line_no, key in keys[:20])
                continue
            if finding.dependency and base in _MANIFESTS:
                result.append(ConfigEvidence(item.path, "dependency_manifest", None, "present", "repository"))
            elif base in _CONFIG_NAMES:
                result.append(ConfigEvidence(item.path, "configuration_file", None, "present", "repository"))
        return result

    def _add_slice(self, result, keys, char_budget, path, lines, center, radius, reason):
        if len(result) >= self.max_slices or char_budget[0] <= 0 or not lines:
            return None
        start = max(1, int(center) - radius)
        end = min(len(lines), int(center) + radius)
        key = (path, start, end)
        if key in keys:
            for item in result:
                if (item.path, item.start_line, item.end_line) == key:
                    return item.slice_id
            return None
        content_lines = self._redact_lines(lines[start - 1:end])
        selected_lines: list[str] = []
        selected_size = 0
        for line in content_lines:
            addition = len(line) + (1 if selected_lines else 0)
            if selected_lines and selected_size + addition > char_budget[0]:
                break
            if not selected_lines and addition > char_budget[0]:
                selected_lines.append(line[:char_budget[0]])
                selected_size = len(selected_lines[0])
                break
            selected_lines.append(line)
            selected_size += addition
        content = "\n".join(selected_lines)
        if not content:
            return None
        slice_id = f"slice-{len(result) + 1:03d}"
        actual_end = min(end, start + len(selected_lines) - 1)
        result.append(CodeSlice(slice_id, path, start, actual_end, content, reason))
        keys.add(key)
        char_budget[0] -= len(content)
        return slice_id

    @staticmethod
    def _sink_patterns(finding):
        text = " ".join(filter(None, [finding.vulnerability_type, finding.cwe or ""])).lower()
        families: list[str] = []
        mapping = {
            "sql": ("sql", "cwe-89"), "ssrf": ("ssrf", "cwe-918"),
            "command": ("command injection", "cwe-78"),
            "deserialization": ("deserial", "cwe-502"),
            "path": ("path traversal", "cwe-22"), "xss": ("xss", "cross-site", "cwe-79"),
            "auth": ("auth", "jwt", "cwe-287", "cwe-347"),
            "crypto": ("crypto", "algorithm", "cwe-327", "cwe-328"),
            "secret": ("secret", "credential", "information exposure", "cwe-200", "cwe-798"),
        }
        for family, needles in mapping.items():
            if any(needle in text for needle in needles):
                families.append(family)
        patterns: list[str] = []
        for family in families:
            patterns.extend(_SINK_FAMILIES[family])
        return tuple(dict.fromkeys(patterns or _GENERIC_SINKS))

    @staticmethod
    def _find_symbol_line(lines, symbol):
        if not symbol:
            return None
        pattern = re.compile(rf"\b{re.escape(symbol)}\b")
        return next((index for index, line in enumerate(lines, 1) if pattern.search(line)), None)

    @staticmethod
    def _nearest_symbol(lines, line_no):
        patterns = (
            re.compile(r"\b(?:def|class|function|func|fn)\s+([A-Za-z_$][\w$]*)"),
            re.compile(r"\b(?:public|private|protected|static|async)\s+[\w<>,\[\]?]+\s+([A-Za-z_$][\w$]*)\s*\("),
        )
        for index in range(min(line_no, len(lines)) - 1, max(-1, line_no - 40), -1):
            for pattern in patterns:
                match = pattern.search(lines[index])
                if match:
                    return match.group(1)
        return "<module>"

    @staticmethod
    def _match_path(expected, file_map):
        clean = EvidenceCollector._clean_path(expected)
        if clean in file_map:
            return clean
        matches = [path for path in file_map if path.endswith("/" + clean) or clean.endswith("/" + path)]
        return sorted(matches, key=len)[0] if matches else None

    @staticmethod
    def _clean_path(path):
        normalized = str(PurePosixPath((path or "").replace("\\", "/")))
        return normalized[2:] if normalized.startswith("./") else normalized.lstrip("/")

    @staticmethod
    def _prioritize_files(files, target_paths):
        return sorted(files, key=lambda item: (item.path not in target_paths, item.path))

    @staticmethod
    def _basename(path):
        return PurePosixPath(path).name.lower()

    @staticmethod
    def _language(path):
        return _LANGUAGES.get(PurePosixPath(path).suffix.lower())

    @staticmethod
    def _is_test_path(path):
        pure = PurePosixPath(path)
        parts = {part.lower() for part in pure.parts}
        name = pure.name.lower()
        return bool(parts.intersection(_TEST_PARTS)) or name.startswith("test_") or name.endswith(("_test.py", ".test.js", ".spec.js", ".test.ts", ".spec.ts"))

    @staticmethod
    def _test_framework(path):
        suffix = PurePosixPath(path).suffix.lower()
        return {".py": "pytest", ".js": "javascript-test", ".ts": "typescript-test", ".java": "junit", ".go": "go-test", ".rs": "cargo-test"}.get(suffix)

    @staticmethod
    def _is_sensitive_env(path):
        name = PurePosixPath(path).name.lower()
        return name == ".env" or name.startswith(".env.")

    @staticmethod
    def _is_non_code(path):
        return EvidenceCollector._basename(path) in _MANIFESTS or PurePosixPath(path).suffix.lower() in {".md", ".txt", ".lock"}

    @staticmethod
    def _redact_line(line):
        line = _SECRET_LINE.sub(lambda match: f"{match.group(1)}{match.group(2)}<redacted>", line)
        line = _BEARER_VALUE.sub(r"\1<redacted>", line)
        return _ACCESS_KEY.sub("<redacted-access-key>", line)

    @staticmethod
    def _redact_lines(lines):
        result: list[str] = []
        in_private_key = False
        for line in lines:
            upper = line.upper()
            if "-----BEGIN" in upper and "PRIVATE KEY-----" in upper:
                in_private_key = True
                result.append("<redacted-private-key-block>")
                continue
            if in_private_key:
                if "-----END" in upper and "PRIVATE KEY-----" in upper:
                    in_private_key = False
                continue
            result.append(EvidenceCollector._redact_line(line))
        return result


def format_evidence_bundle(bundle: EvidenceBundle | None, max_chars: int = 24_000) -> str:
    """Render a bounded, stable representation suitable for an Agent prompt."""
    if bundle is None:
        return "(EvidenceBundle not provided)"
    payload = bundle.to_dict()
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2)
    if len(text) <= max_chars:
        return text
    compact = {
        "finding_id": payload["finding_id"],
        "repository_summary": payload["repository_summary"],
        "target_files": payload["target_files"],
        "entry_points": payload["entry_points"][:12],
        "source_candidates": payload["source_candidates"][:12],
        "sink_candidates": payload["sink_candidates"][:12],
        "dependency_evidence": payload["dependency_evidence"][:12],
        "test_evidence": payload["test_evidence"][:12],
        "config_evidence": payload["config_evidence"][:12],
        "validation_capabilities": payload["validation_capabilities"],
        "collection_warnings": payload["collection_warnings"],
        "bundle_hash": payload["bundle_hash"],
        "code_slices": [],
    }
    base = json.dumps(compact, ensure_ascii=False, sort_keys=True, indent=2)
    if len(base) > max_chars:
        summary = {
            "finding_id": payload["finding_id"],
            "target_files": [item["path"] for item in payload["target_files"]],
            "entry_point_count": len(payload["entry_points"]),
            "source_candidate_count": len(payload["source_candidates"]),
            "sink_candidate_count": len(payload["sink_candidates"]),
            "code_slice_count": len(payload["code_slices"]),
            "validation_capabilities": payload["validation_capabilities"],
            "collection_warnings": payload["collection_warnings"],
            "bundle_hash": payload["bundle_hash"],
            "prompt_view_truncated": True,
        }
        return json.dumps(summary, ensure_ascii=False, sort_keys=True, indent=2)[:max_chars]

    remaining = max_chars - len(base) - 100
    for item in payload.get("code_slices", []):
        if remaining <= 0:
            break
        candidate = dict(item)
        candidate["content"] = candidate.get("content", "")[:max(0, remaining - 300)]
        compact["code_slices"].append(candidate)
        rendered = json.dumps(compact, ensure_ascii=False, sort_keys=True, indent=2)
        if len(rendered) > max_chars:
            compact["code_slices"].pop()
            break
        remaining = max_chars - len(rendered) - 100
    text = json.dumps(compact, ensure_ascii=False, sort_keys=True, indent=2)
    return text

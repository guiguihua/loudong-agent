from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Protocol

from .models import (
    Confidence,
    DependencyDetails,
    Location,
    NormalizedVulnerability,
    Severity,
)


class LLMNormalizationAssistant(Protocol):
    """Only resolves fields that deterministic rules cannot safely map."""

    def enrich(self, raw: dict[str, Any], unresolved_fields: list[str]) -> dict[str, Any]: ...


@dataclass(slots=True)
class NullLLMAssistant:
    def enrich(self, raw: dict[str, Any], unresolved_fields: list[str]) -> dict[str, Any]:
        return {}


class VulnerabilityNormalizer:
    SEVERITY_ALIASES = {
        "critical": Severity.CRITICAL,
        "严重": Severity.CRITICAL,
        "high": Severity.HIGH,
        "高": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "中": Severity.MEDIUM,
        "low": Severity.LOW,
        "低": Severity.LOW,
        "info": Severity.INFO,
        "informational": Severity.INFO,
    }
    CONFIDENCE_ALIASES = {
        "high": Confidence.HIGH,
        "高": Confidence.HIGH,
        "medium": Confidence.MEDIUM,
        "中": Confidence.MEDIUM,
        "low": Confidence.LOW,
        "低": Confidence.LOW,
    }
    TYPE_ALIASES = {
        "sql injection": "SQL Injection",
        "sqli": "SQL Injection",
        "cwe-89": "SQL Injection",
        "cross-site scripting": "Cross-Site Scripting",
        "xss": "Cross-Site Scripting",
        "cwe-79": "Cross-Site Scripting",
        "path traversal": "Path Traversal",
        "cwe-22": "Path Traversal",
        "dependency": "Vulnerable Dependency",
        "sca": "Vulnerable Dependency",
    }

    def __init__(self, llm_assistant: LLMNormalizationAssistant | None = None) -> None:
        self.llm = llm_assistant or NullLLMAssistant()

    def normalize(self, raw: dict[str, Any]) -> NormalizedVulnerability:
        canonical = self._flatten_known_formats(raw)
        unresolved: list[str] = []
        if not canonical.get("vulnerability_type"):
            unresolved.append("vulnerability_type")
        if not canonical.get("evidence"):
            unresolved.append("evidence")
        if unresolved:
            canonical.update({k: v for k, v in self.llm.enrich(raw, unresolved).items() if k in unresolved})

        locations = self._locations(canonical)
        warnings: list[str] = []
        if not locations:
            warnings.append("missing_location")
        vulnerability_type = self._normalize_type(canonical)
        if vulnerability_type == "Unknown":
            warnings.append("unmapped_vulnerability_type")

        dependency = self._dependency(canonical, locations)
        evidence = canonical.get("evidence") or []
        if isinstance(evidence, str):
            evidence = [evidence]

        finding_id = str(canonical.get("finding_id") or self._stable_id(canonical))
        return NormalizedVulnerability(
            schema_version="1.0",
            finding_id=finding_id,
            vulnerability_type=vulnerability_type,
            severity=self._enum(self.SEVERITY_ALIASES, canonical.get("severity"), Severity.UNKNOWN),
            confidence=self._enum(self.CONFIDENCE_ALIASES, canonical.get("confidence"), Confidence.UNKNOWN),
            scanner=str(canonical.get("scanner") or canonical.get("source") or "unknown"),
            locations=locations,
            evidence=[str(item) for item in evidence],
            recommendation=canonical.get("recommendation"),
            cve=canonical.get("cve"),
            cwe=canonical.get("cwe"),
            repository=canonical.get("repository"),
            revision=canonical.get("revision"),
            dependency=dependency,
            raw_reference=canonical.get("raw_reference"),
            normalization_warnings=warnings,
        )

    @staticmethod
    def _flatten_known_formats(raw: dict[str, Any]) -> dict[str, Any]:
        # Native canonical-ish format plus common SARIF properties/location subset.
        result = dict(raw)
        if "ruleId" in raw:
            result.setdefault("finding_id", raw.get("fingerprints", {}).get("primaryLocationLineHash"))
            result.setdefault("vulnerability_type", raw.get("ruleId"))
            result.setdefault("scanner", "SARIF")
            result.setdefault("evidence", raw.get("message", {}).get("text"))
            sarif_locations = raw.get("locations") or []
            if sarif_locations:
                physical = sarif_locations[0].get("physicalLocation", {})
                region = physical.get("region", {})
                result.setdefault("affected_file", physical.get("artifactLocation", {}).get("uri"))
                result.setdefault("line", region.get("startLine"))
        return result

    def _normalize_type(self, canonical: dict[str, Any]) -> str:
        raw_type = str(canonical.get("vulnerability_type") or canonical.get("cwe") or "").strip()
        return self.TYPE_ALIASES.get(raw_type.lower(), raw_type or "Unknown")

    @staticmethod
    def _enum(mapping: dict[str, Any], value: Any, default: Any) -> Any:
        return mapping.get(str(value).strip().lower(), default)

    @staticmethod
    def _locations(canonical: dict[str, Any]) -> list[Location]:
        values = canonical.get("locations")
        if values:
            return [Location(file=v["file"], function=v.get("function"), line=v.get("line")) for v in values]
        file = canonical.get("affected_file") or canonical.get("file")
        if not file:
            return []
        return [Location(file=str(file), function=canonical.get("affected_function"), line=canonical.get("line"))]

    @staticmethod
    def _dependency(canonical: dict[str, Any], locations: list[Location]) -> DependencyDetails | None:
        component = canonical.get("component") or canonical.get("package_name")
        if not component:
            return None
        fixed = canonical.get("fixed_versions") or canonical.get("fixed_version") or []
        if isinstance(fixed, str):
            fixed = [fixed]
        return DependencyDetails(
            component=str(component),
            current_version=canonical.get("current_version"),
            fixed_versions=[str(v) for v in fixed],
            breaking_upgrade=canonical.get("breaking_upgrade"),
            usage_locations=locations,
            affected_artifacts=[str(v) for v in canonical.get("affected_artifacts", [])],
        )

    @staticmethod
    def _stable_id(canonical: dict[str, Any]) -> str:
        material = "|".join(
            str(canonical.get(key) or "")
            for key in ("repository", "vulnerability_type", "affected_file", "line", "component", "cve")
        )
        return "F-" + hashlib.sha256(material.encode()).hexdigest()[:12]


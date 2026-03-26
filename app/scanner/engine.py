from __future__ import annotations

import logging
from pathlib import Path

from app.models.schemas import SEVERITY_WEIGHTS, Finding, ScanResult, ScanSummary
from app.scanner.rules import Rule, build_rules
from app.utils.file_loader import load_json_directory, load_json_file

logger = logging.getLogger(__name__)


class ScannerEngine:
    def __init__(self, rules: dict[str, list[Rule]] | None = None):
        self.rules = rules or build_rules()

    def scan_file(self, file_path: Path) -> ScanResult:
        resource = load_json_file(file_path)
        findings = self._scan_resource(
            resource.resource_type, resource.resource_id, resource.data
        )
        return self._build_result(findings, scanned_resources=1)

    def scan_directory(self, directory_path: Path) -> ScanResult:
        resources = load_json_directory(directory_path)
        findings: list[Finding] = []
        for resource in resources:
            findings.extend(
                self._scan_resource(
                    resource.resource_type,
                    resource.resource_id,
                    resource.data,
                )
            )
        return self._build_result(findings, scanned_resources=len(resources))

    def _scan_resource(
        self,
        resource_type: str,
        resource_id: str,
        data: dict,
    ) -> list[Finding]:
        findings: list[Finding] = []
        if resource_type not in self.rules:
            logger.warning("Unsupported resource type encountered: %s", resource_type)
            return findings

        from app.models.schemas import ResourceDocument

        resource = ResourceDocument(
            resource_type=resource_type,
            resource_id=resource_id,
            data=data,
        )
        for rule in self.rules[resource_type]:
            findings.extend(rule.evaluate(resource))
        return findings

    def _build_result(
        self, findings: list[Finding], scanned_resources: int
    ) -> ScanResult:
        severity_breakdown = {
            sev: len([f for f in findings if f.severity == sev])
            for sev in SEVERITY_WEIGHTS
        }
        weighted_risk_score = sum(SEVERITY_WEIGHTS[f.severity] for f in findings)
        summary = ScanSummary(
            total_findings=len(findings),
            severity_breakdown=severity_breakdown,
            weighted_risk_score=weighted_risk_score,
        )
        return ScanResult(
            findings=findings,
            summary=summary,
            scanned_resources=scanned_resources,
        )

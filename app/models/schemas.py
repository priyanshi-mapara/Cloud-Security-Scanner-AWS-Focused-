from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.critical: 10,
    Severity.high: 7,
    Severity.medium: 4,
    Severity.low: 1,
}


class Finding(BaseModel):
    finding_id: str
    severity: Severity
    title: str
    description: str
    affected_resource: str
    remediation: str
    compliance_tags: list[str] = Field(default_factory=list)
    resource_type: str


class ScanSummary(BaseModel):
    total_findings: int
    severity_breakdown: dict[Severity, int]
    weighted_risk_score: int


class ScanResult(BaseModel):
    findings: list[Finding]
    summary: ScanSummary
    scanned_resources: int


class ScanFileResponse(BaseModel):
    result: ScanResult


class ScanDirectoryResponse(BaseModel):
    result: ScanResult


class ScanState(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
    scanned_resources: int = 0


class ResourceDocument(BaseModel):
    resource_type: str
    resource_id: str
    data: dict[str, Any]

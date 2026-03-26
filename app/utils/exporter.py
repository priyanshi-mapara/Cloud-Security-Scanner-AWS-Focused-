from __future__ import annotations

import csv
import json
from pathlib import Path

from app.models.schemas import Finding


def export_findings_json(findings: list[Finding], output_path: Path) -> None:
    output_path.write_text(json.dumps([f.model_dump() for f in findings], indent=2))


def export_findings_csv(findings: list[Finding], output_path: Path) -> None:
    fieldnames = [
        "finding_id",
        "severity",
        "title",
        "description",
        "affected_resource",
        "remediation",
        "compliance_tags",
        "resource_type",
    ]
    with output_path.open("w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for finding in findings:
            row = finding.model_dump()
            row["compliance_tags"] = ";".join(row["compliance_tags"])
            writer.writerow(row)

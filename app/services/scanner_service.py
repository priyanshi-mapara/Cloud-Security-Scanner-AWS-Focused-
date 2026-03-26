from __future__ import annotations

import logging
from pathlib import Path

from app.models.schemas import ScanResult, ScanState, ScanSummary
from app.scanner.engine import ScannerEngine

logger = logging.getLogger(__name__)


class ScannerService:
    def __init__(self) -> None:
        self.engine = ScannerEngine()
        self.state = ScanState()

    def scan_file(self, file_path: Path) -> ScanResult:
        logger.info("Scanning file: %s", file_path)
        result = self.engine.scan_file(file_path)
        self._update_state(result)
        return result

    def scan_directory(self, directory_path: Path) -> ScanResult:
        logger.info("Scanning directory: %s", directory_path)
        result = self.engine.scan_directory(directory_path)
        self._update_state(result)
        return result

    def _update_state(self, result: ScanResult) -> None:
        self.state.findings = result.findings
        self.state.scanned_resources = result.scanned_resources

    def get_findings(self):
        return self.state.findings

    def get_summary(self) -> ScanSummary:
        return self.engine._build_result(
            findings=self.state.findings,
            scanned_resources=self.state.scanned_resources,
        ).summary

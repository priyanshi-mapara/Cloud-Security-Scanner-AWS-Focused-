from __future__ import annotations

from pathlib import Path

import typer

from app.services.scanner_service import ScannerService
from app.utils.exporter import export_findings_csv, export_findings_json
from app.utils.logging_config import setup_logging

setup_logging()
app = typer.Typer(help="AWS Cloud Security Scanner CLI")
service = ScannerService()


@app.command("scan-file")
def scan_file(
    path: str = typer.Argument(..., help="Path to JSON resource file"),
    export_json: str | None = typer.Option(None, help="Output findings to JSON file"),
    export_csv: str | None = typer.Option(None, help="Output findings to CSV file"),
):
    result = service.scan_file(Path(path))
    typer.echo(result.model_dump_json(indent=2))
    if export_json:
        export_findings_json(result.findings, Path(export_json))
    if export_csv:
        export_findings_csv(result.findings, Path(export_csv))


@app.command("scan-directory")
def scan_directory(
    path: str = typer.Argument(..., help="Directory containing JSON resources"),
    export_json: str | None = typer.Option(None, help="Output findings to JSON file"),
    export_csv: str | None = typer.Option(None, help="Output findings to CSV file"),
):
    result = service.scan_directory(Path(path))
    typer.echo(result.model_dump_json(indent=2))
    if export_json:
        export_findings_json(result.findings, Path(export_json))
    if export_csv:
        export_findings_csv(result.findings, Path(export_csv))


if __name__ == "__main__":
    app()

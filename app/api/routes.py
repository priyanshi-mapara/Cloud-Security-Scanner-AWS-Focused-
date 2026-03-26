from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.services.scanner_service import ScannerService
from app.utils.file_loader import FileLoadError

router = APIRouter()
service = ScannerService()


class FileScanRequest(BaseModel):
    path: str


class DirectoryScanRequest(BaseModel):
    path: str


@router.post("/scan/file")
def scan_file(payload: FileScanRequest):
    try:
        result = service.scan_file(Path(payload.path))
    except FileLoadError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(
            status_code=400, detail=f"Invalid resource document: {exc}"
        ) from exc
    return {"result": result}


@router.post("/scan/directory")
def scan_directory(payload: DirectoryScanRequest):
    try:
        result = service.scan_directory(Path(payload.path))
    except FileLoadError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(
            status_code=400, detail=f"Invalid resource document: {exc}"
        ) from exc
    return {"result": result}


@router.get("/findings")
def get_findings():
    return {"findings": service.get_findings()}


@router.get("/summary")
def get_summary():
    return {"summary": service.get_summary()}


@router.get("/health")
def health():
    return {"status": "ok"}

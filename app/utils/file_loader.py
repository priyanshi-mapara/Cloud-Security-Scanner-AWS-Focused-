from __future__ import annotations

import json
from pathlib import Path

from app.models.schemas import ResourceDocument


class FileLoadError(Exception):
    pass


def load_json_file(file_path: Path) -> ResourceDocument:
    try:
        raw_data = json.loads(file_path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        raise FileLoadError(f"Failed to load {file_path}: {exc}") from exc

    return ResourceDocument(
        resource_type=raw_data["resource_type"],
        resource_id=raw_data["resource_id"],
        data=raw_data,
    )


def load_json_directory(directory_path: Path) -> list[ResourceDocument]:
    if not directory_path.exists() or not directory_path.is_dir():
        raise FileLoadError(f"Directory does not exist: {directory_path}")

    resources: list[ResourceDocument] = []
    for file_path in sorted(directory_path.glob("*.json")):
        resources.append(load_json_file(file_path))
    return resources

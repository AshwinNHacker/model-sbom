"""
io.py
=====
Load/save ModelSBOM documents as JSON files.
"""
from __future__ import annotations

import json
from pathlib import Path

from .models import ModelSBOM


def save(sbom: ModelSBOM, path: str | Path, indent: int = 2) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(sbom.as_dict(), f, indent=indent, sort_keys=False, ensure_ascii=False)
        f.write("\n")


def load(path: str | Path) -> ModelSBOM:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return ModelSBOM.from_dict(data)

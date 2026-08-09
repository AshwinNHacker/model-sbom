"""
hashing.py
==========
Checksum utilities used for integrity verification of SBOM components and
for producing a deterministic hash of the SBOM document itself (so two
SBOMs describing the same supply chain state hash identically regardless
of dict key ordering, and so tampering is detectable).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

CHUNK_SIZE = 1024 * 1024  # 1 MiB


def sha256_file(path: str | Path) -> str:
    """Stream-hash a single file. Safe for large model weight files."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            h.update(chunk)
    return h.hexdigest()


def sha256_dir(path: str | Path) -> str:
    """
    Deterministic hash of a directory's contents: hashes each file, then
    hashes the sorted (relative_path, file_hash) pairs together. This is
    order-independent and catches added/removed/modified/renamed files —
    useful for hashing a full model checkpoint directory (weights + config
    + tokenizer files) as a single component checksum.
    """
    root = Path(path)
    if not root.is_dir():
        raise NotADirectoryError(f"{path} is not a directory")

    entries = []
    for file_path in sorted(root.rglob("*")):
        if file_path.is_file():
            rel = file_path.relative_to(root).as_posix()
            entries.append((rel, sha256_file(file_path)))

    combined = hashlib.sha256()
    for rel, digest in sorted(entries):
        combined.update(rel.encode("utf-8"))
        combined.update(b"\x00")
        combined.update(digest.encode("utf-8"))
        combined.update(b"\n")
    return combined.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj) -> str:
    """Stable JSON serialization: sorted keys, no extraneous whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def document_hash(sbom_dict: dict) -> str:
    """
    Deterministic sha256 over the SBOM document's canonical JSON form,
    excluding the `metadata.timestamp` field (which changes on every
    regeneration even when the described supply chain is identical).
    This lets you diff two SBOM *contents* for equality without false
    positives caused only by regeneration time.
    """
    trimmed = json.loads(canonical_json(sbom_dict))
    if "metadata" in trimmed and isinstance(trimmed["metadata"], dict):
        trimmed["metadata"] = {k: v for k, v in trimmed["metadata"].items() if k != "timestamp"}
    return sha256_bytes(canonical_json(trimmed).encode("utf-8"))


def verify_checksum(path: str | Path, expected_algorithm: str, expected_value: str) -> bool:
    if expected_algorithm.lower() != "sha256":
        raise ValueError(f"Unsupported checksum algorithm: {expected_algorithm}")
    p = Path(path)
    actual = sha256_dir(p) if p.is_dir() else sha256_file(p)
    return actual.lower() == expected_value.lower()

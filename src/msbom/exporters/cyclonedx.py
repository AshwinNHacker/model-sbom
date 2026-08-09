"""
cyclonedx.py
============
Exports a ModelSBOM as CycloneDX-shaped JSON for interoperability with the
broader SBOM tooling ecosystem (CycloneDX viewers, dependency-track, etc.).

IMPORTANT ACCURACY NOTE
------------------------
This is a **best-effort, CycloneDX-inspired mapping**, not a certified
CycloneDX 1.6 ML-BOM implementation. It uses CycloneDX's stable, generic
building blocks that are safe to rely on (bomFormat/specVersion envelope,
`components[].type`, `licenses`, `hashes`, `externalReferences`, and the
generic `properties` name/value-pair extension mechanism), and places
ModelSBOM-specific fields (rank, alpha, lineage_stage, pii_reviewed, etc.)
into `properties` with a `msbom:` namespace prefix rather than guessing at
exact ML-BOM-profile field names that may not match your CycloneDX
tooling's expected schema version. If your organization requires strict
CycloneDX ML-BOM (CBOM) profile compliance, validate this output against
your specific CycloneDX tooling version before relying on it, and treat
this exporter as a starting point to adapt rather than a drop-in
guarantee.

Native ModelSBOM JSON (via `ModelSBOM.as_dict()`) is the source of truth
for this project; this exporter is provided purely for downstream
interop.
"""
from __future__ import annotations

from ..models import Component, ComponentType, ModelSBOM

_CDX_TYPE_BY_COMPONENT_TYPE = {
    ComponentType.BASE_MODEL: "machine-learning-model",
    ComponentType.ADAPTER: "machine-learning-model",
    ComponentType.MERGED_MODEL: "machine-learning-model",
    ComponentType.DATASET: "data",
    ComponentType.TOKENIZER: "library",
}


def _flatten_properties(prefix: str, props: dict) -> list[dict]:
    out = []
    for key, value in props.items():
        if value is None:
            continue
        if isinstance(value, (list, dict)):
            import json as _json
            value = _json.dumps(value, sort_keys=True)
        out.append({"name": f"{prefix}:{key}", "value": str(value)})
    return out


def _component_to_cyclonedx(comp: Component) -> dict:
    entry = {
        "type": _CDX_TYPE_BY_COMPONENT_TYPE.get(comp.type, "library"),
        "bom-ref": comp.id,
        "name": comp.name,
        "version": comp.version,
        "supplier": {"name": comp.supplier} if comp.supplier else None,
        "licenses": (
            [{"license": {"id": comp.license.value}}]
            if comp.license.value not in ("UNKNOWN", "OTHER")
            else [{"license": {"name": comp.license.value}}]
        ),
        "description": comp.notes or None,
    }

    if comp.checksum:
        entry["hashes"] = [{"alg": comp.checksum.algorithm.upper(), "content": comp.checksum.value}]

    if comp.external_refs:
        entry["externalReferences"] = [
            {
                "type": "distribution" if ref.ref_type in ("huggingface", "internal_registry") else "other",
                "url": ref.uri,
                "comment": f"ref_type={ref.ref_type}" + (f"; revision={ref.revision}" if ref.revision else ""),
            }
            for ref in comp.external_refs
        ]

    props = [{"name": "msbom:component_type", "value": comp.type.value}]
    props += _flatten_properties("msbom", comp.properties)
    if comp.license_note:
        props.append({"name": "msbom:license_note", "value": comp.license_note})
    entry["properties"] = props

    return {k: v for k, v in entry.items() if v is not None}


def to_cyclonedx(sbom: ModelSBOM) -> dict:
    """Produce a CycloneDX-shaped dict. See module docstring re: accuracy scope."""
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": sbom.serial_number,
        "version": sbom.version,
        "metadata": {
            "timestamp": sbom.metadata.timestamp,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": sbom.metadata.tool_name,
                        "version": sbom.metadata.tool_version,
                    }
                ]
            },
            "authors": [{"name": a} for a in sbom.metadata.authors],
            "manufacture": {"name": sbom.metadata.organization} if sbom.metadata.organization else None,
            "properties": [
                {"name": "msbom:native_format", "value": "ModelSBOM"},
                {"name": "msbom:native_spec_version", "value": sbom.spec_version},
                {"name": "msbom:export_note", "value": "best-effort mapping; see module docstring"},
            ],
        },
        "components": [_component_to_cyclonedx(c) for c in sbom.components],
        "dependencies": [
            {"ref": comp.id, "dependsOn": [
                rel.target_id for rel in sbom.relationships if rel.source_id == comp.id
            ]}
            for comp in sbom.components
            if any(rel.source_id == comp.id for rel in sbom.relationships)
        ],
    }
    doc["metadata"] = {k: v for k, v in doc["metadata"].items() if v is not None}
    return doc

"""
models.py
=========
Core data model for a Model Supply Chain SBOM (MSBOM).

Design goals
------------
- Every component (base model / dataset / adapter / merged model / tokenizer)
  carries enough metadata to answer "where did this artifact come from, what
  license governs it, and can I verify its integrity?"
- Provenance is expressed as an explicit directed graph (`Relationship`
  edges), not just nested fields, so lineage can be traversed in either
  direction (ancestors of an adapter, or every downstream artifact that
  depends on a given dataset).
- The document is plain-dataclass + dict, so it has zero required
  third-party dependencies to build or read. JSON Schema validation
  (schema/model-sbom.schema.json) is layered on top, optionally, via
  `validator.py`.

This is deliberately modeled on concepts from CycloneDX's ML-BOM profile
and SPDX 3.0's AI/dataset profiles, but is its own lightweight schema, not
a certified implementation of either spec. See docs/spec.md for exact
field-by-field rationale and the mapping notes in
`exporters/cyclonedx.py` for how this maps onto CycloneDX for interop.
"""
from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ComponentType(str, Enum):
    BASE_MODEL = "base_model"
    DATASET = "dataset"
    ADAPTER = "adapter"
    MERGED_MODEL = "merged_model"
    TOKENIZER = "tokenizer"


class AdapterMethod(str, Enum):
    LORA = "LoRA"
    QLORA = "QLoRA"
    FULL_FINE_TUNE = "full_fine_tune"
    RLHF = "RLHF"
    DPO = "DPO"
    PROMPT_TUNING = "prompt_tuning"
    PREFIX_TUNING = "prefix_tuning"
    OTHER = "other"


class DataLineageStage(str, Enum):
    """Where in a dataset's own lifecycle this record describes it."""
    RAW_COLLECTION = "raw_collection"
    FILTERED = "filtered"
    DEDUPLICATED = "deduplicated"
    PII_SCRUBBED = "pii_scrubbed"
    LABELED = "labeled"
    SYNTHETIC_GENERATED = "synthetic_generated"
    MIXED = "mixed"
    FINAL_TRAINING_SET = "final_training_set"


class RelationshipType(str, Enum):
    DERIVED_FROM = "DERIVED_FROM"      # adapter/merged_model DERIVED_FROM base_model
    TRAINED_ON = "TRAINED_ON"          # adapter/base_model TRAINED_ON dataset
    FINE_TUNED_FROM = "FINE_TUNED_FROM"  # base_model FINE_TUNED_FROM base_model (continued pretraining)
    MERGED_FROM = "MERGED_FROM"        # merged_model MERGED_FROM adapter/base_model
    INCLUDES = "INCLUDES"              # base_model INCLUDES tokenizer
    DEPENDS_ON = "DEPENDS_ON"          # generic dependency
    SOURCED_FROM = "SOURCED_FROM"      # dataset SOURCED_FROM dataset (a mix/subset relationship)


class License(str, Enum):
    APACHE_2_0 = "Apache-2.0"
    MIT = "MIT"
    LLAMA_2_COMMUNITY = "Llama2-Community-License"
    LLAMA_3_COMMUNITY = "Llama3-Community-License"
    CC_BY_4_0 = "CC-BY-4.0"
    CC_BY_SA_4_0 = "CC-BY-SA-4.0"
    CC_BY_NC_4_0 = "CC-BY-NC-4.0"
    CC0_1_0 = "CC0-1.0"
    OPENRAIL_M = "OpenRAIL-M"
    GPL_3_0 = "GPL-3.0"
    PROPRIETARY = "Proprietary"
    UNKNOWN = "UNKNOWN"
    OTHER = "OTHER"


# ---------------------------------------------------------------------------
# Supporting value objects
# ---------------------------------------------------------------------------

@dataclass
class Checksum:
    algorithm: str          # e.g. "sha256"
    value: str               # hex digest

    def as_dict(self) -> dict:
        return {"algorithm": self.algorithm, "value": self.value}

    @staticmethod
    def from_dict(d: dict) -> Checksum:
        return Checksum(algorithm=d["algorithm"], value=d["value"])


@dataclass
class ExternalRef:
    """A pointer to where the artifact actually lives (registry, URL, etc.)."""
    ref_type: str            # "huggingface" | "url" | "s3" | "git" | "internal_registry" | "other"
    uri: str
    revision: str | None = None   # commit sha / tag / dataset version string

    def as_dict(self) -> dict:
        d = {"ref_type": self.ref_type, "uri": self.uri}
        if self.revision:
            d["revision"] = self.revision
        return d

    @staticmethod
    def from_dict(d: dict) -> ExternalRef:
        return ExternalRef(ref_type=d["ref_type"], uri=d["uri"], revision=d.get("revision"))


# ---------------------------------------------------------------------------
# Components
# ---------------------------------------------------------------------------

@dataclass
class Component:
    """Base fields shared by every component type."""
    id: str
    type: ComponentType
    name: str
    version: str
    supplier: str = "unknown"
    license: License = License.UNKNOWN
    license_note: str = ""
    checksum: Checksum | None = None
    external_refs: list[ExternalRef] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    notes: str = ""
    # Free-form bag for type-specific fields (parameter_count, rank, etc.)
    properties: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.type.value,
            "name": self.name,
            "version": self.version,
            "supplier": self.supplier,
            "license": self.license.value,
            "license_note": self.license_note,
            "checksum": self.checksum.as_dict() if self.checksum else None,
            "external_refs": [r.as_dict() for r in self.external_refs],
            "created_at": self.created_at,
            "notes": self.notes,
            "properties": self.properties,
        }

    @staticmethod
    def from_dict(d: dict) -> Component:
        return Component(
            id=d["id"],
            type=ComponentType(d["type"]),
            name=d["name"],
            version=d["version"],
            supplier=d.get("supplier", "unknown"),
            license=License(d.get("license", "UNKNOWN")),
            license_note=d.get("license_note", ""),
            checksum=Checksum.from_dict(d["checksum"]) if d.get("checksum") else None,
            external_refs=[ExternalRef.from_dict(r) for r in d.get("external_refs", [])],
            created_at=d.get("created_at", datetime.now(timezone.utc).isoformat()),
            notes=d.get("notes", ""),
            properties=d.get("properties", {}),
        )


def new_component_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


# ---------------------------------------------------------------------------
# Relationships (the provenance graph edges)
# ---------------------------------------------------------------------------

@dataclass
class Relationship:
    source_id: str            # the derived/dependent component
    target_id: str            # what it was derived from / trained on / depends on
    type: RelationshipType
    note: str = ""

    def as_dict(self) -> dict:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "type": self.type.value,
            "note": self.note,
        }

    @staticmethod
    def from_dict(d: dict) -> Relationship:
        return Relationship(
            source_id=d["source_id"],
            target_id=d["target_id"],
            type=RelationshipType(d["type"]),
            note=d.get("note", ""),
        )


# ---------------------------------------------------------------------------
# Top-level document
# ---------------------------------------------------------------------------

SBOM_FORMAT = "ModelSBOM"
SBOM_SPEC_VERSION = "1.0.0"


@dataclass
class ModelSBOMMetadata:
    tool_name: str = "model-sbom"
    tool_version: str = "1.0.0"
    authors: list[str] = field(default_factory=list)
    organization: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    description: str = ""

    def as_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> ModelSBOMMetadata:
        return ModelSBOMMetadata(
            tool_name=d.get("tool_name", "model-sbom"),
            tool_version=d.get("tool_version", "1.0.0"),
            authors=d.get("authors", []),
            organization=d.get("organization", ""),
            timestamp=d.get("timestamp", datetime.now(timezone.utc).isoformat()),
            description=d.get("description", ""),
        )


@dataclass
class ModelSBOM:
    bom_format: str = SBOM_FORMAT
    spec_version: str = SBOM_SPEC_VERSION
    serial_number: str = field(default_factory=lambda: f"urn:uuid:{uuid.uuid4()}")
    version: int = 1
    metadata: ModelSBOMMetadata = field(default_factory=ModelSBOMMetadata)
    components: list[Component] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)

    # -- lookups -----------------------------------------------------
    def get_component(self, component_id: str) -> Component | None:
        for c in self.components:
            if c.id == component_id:
                return c
        return None

    def component_ids(self) -> set[str]:
        return {c.id for c in self.components}

    # -- serialization -------------------------------------------------
    def as_dict(self) -> dict:
        return {
            "bom_format": self.bom_format,
            "spec_version": self.spec_version,
            "serial_number": self.serial_number,
            "version": self.version,
            "metadata": self.metadata.as_dict(),
            "components": [c.as_dict() for c in self.components],
            "relationships": [r.as_dict() for r in self.relationships],
        }

    @staticmethod
    def from_dict(d: dict) -> ModelSBOM:
        return ModelSBOM(
            bom_format=d.get("bom_format", SBOM_FORMAT),
            spec_version=d.get("spec_version", SBOM_SPEC_VERSION),
            serial_number=d.get("serial_number", f"urn:uuid:{uuid.uuid4()}"),
            version=d.get("version", 1),
            metadata=ModelSBOMMetadata.from_dict(d.get("metadata", {})),
            components=[Component.from_dict(c) for c in d.get("components", [])],
            relationships=[Relationship.from_dict(r) for r in d.get("relationships", [])],
        )

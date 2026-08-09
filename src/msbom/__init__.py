"""
msbom — Model Supply Chain SBOM
=================================
A schema, builder, validator, and lineage-analysis toolkit for tracking
base-model provenance, fine-tuning data lineage, and adapter (LoRA/QLoRA/
etc.) provenance across an ML training pipeline.
"""
__version__ = "1.0.0"

from .builder import SBOMBuilder
from .models import (
    Checksum,
    Component,
    ComponentType,
    ExternalRef,
    License,
    ModelSBOM,
    ModelSBOMMetadata,
    Relationship,
    RelationshipType,
)

__all__ = [
    "Checksum", "Component", "ComponentType", "ExternalRef", "License",
    "ModelSBOM", "ModelSBOMMetadata", "Relationship", "RelationshipType",
    "SBOMBuilder",
]

"""
builder.py
==========
Fluent API for constructing a ModelSBOM without hand-building dataclasses
and relationship edges yourself. This is the recommended entry point for
generating an SBOM as part of a training/fine-tuning pipeline.

Example
-------
    from msbom.builder import SBOMBuilder

    b = SBOMBuilder(organization="Acme Corp", authors=["ml-platform-team"])

    base = b.add_base_model(
        name="Llama-3-8B", version="3.0",
        supplier="Meta", license="Llama3-Community-License",
        parameter_count=8_000_000_000,
        external_ref=("huggingface", "meta-llama/Meta-Llama-3-8B", "main"),
    )

    ds = b.add_dataset(
        name="internal-support-tickets-clean", version="2026-06-01",
        license="Proprietary",
        lineage_stage="pii_scrubbed",
        record_count=48213,
        source_uri="s3://acme-ml-data/support-tickets/clean/",
    )

    adapter = b.add_adapter(
        name="acme-support-lora", version="v3",
        method="LoRA", base_model_id=base.id, dataset_ids=[ds.id],
        rank=16, alpha=32, target_modules=["q_proj", "v_proj"],
        trainer="acme-ml-platform", training_date="2026-07-15",
    )

    sbom = b.build()
"""
from __future__ import annotations

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
    new_component_id,
)


def _license(value: str | License) -> License:
    if isinstance(value, License):
        return value
    try:
        return License(value)
    except ValueError:
        return License.OTHER


class SBOMBuilder:
    def __init__(self, organization: str = "", authors: list[str] | None = None,
                 description: str = ""):
        self._components: list[Component] = []
        self._relationships: list[Relationship] = []
        self._metadata = ModelSBOMMetadata(
            organization=organization,
            authors=authors or [],
            description=description,
        )

    # -- generic -------------------------------------------------------
    def add_relationship(self, source_id: str, target_id: str,
                          rel_type: str | RelationshipType, note: str = "") -> SBOMBuilder:
        rt = rel_type if isinstance(rel_type, RelationshipType) else RelationshipType(rel_type)
        self._relationships.append(Relationship(source_id, target_id, rt, note))
        return self

    def _add_external_ref(self, ref: tuple[str, str, str | None] | None) -> list[ExternalRef]:
        if not ref:
            return []
        ref_type, uri, *rest = ref
        revision = rest[0] if rest else None
        return [ExternalRef(ref_type=ref_type, uri=uri, revision=revision)]

    # -- base model ------------------------------------------------------
    def add_base_model(
        self, name: str, version: str, *,
        supplier: str = "unknown",
        license: str | License = License.UNKNOWN,
        license_note: str = "",
        parameter_count: int | None = None,
        architecture: str = "",
        training_data_cutoff: str = "",
        checksum_sha256: str | None = None,
        external_ref: tuple | None = None,
        fine_tuned_from_id: str | None = None,
        notes: str = "",
        component_id: str | None = None,
    ) -> Component:
        comp = Component(
            id=component_id or new_component_id("basemodel"),
            type=ComponentType.BASE_MODEL,
            name=name, version=version, supplier=supplier,
            license=_license(license), license_note=license_note,
            checksum=Checksum("sha256", checksum_sha256) if checksum_sha256 else None,
            external_refs=self._add_external_ref(external_ref),
            notes=notes,
            properties={
                "parameter_count": parameter_count,
                "architecture": architecture,
                "training_data_cutoff": training_data_cutoff,
            },
        )
        self._components.append(comp)
        if fine_tuned_from_id:
            self.add_relationship(comp.id, fine_tuned_from_id, RelationshipType.FINE_TUNED_FROM)
        return comp

    # -- dataset ---------------------------------------------------------
    def add_dataset(
        self, name: str, version: str, *,
        supplier: str = "unknown",
        license: str | License = License.UNKNOWN,
        license_note: str = "",
        lineage_stage: str = "",
        record_count: int | None = None,
        pii_reviewed: bool | None = None,
        source_uri: str = "",
        checksum_sha256: str | None = None,
        external_ref: tuple | None = None,
        derived_from_dataset_ids: list[str] | None = None,
        notes: str = "",
        component_id: str | None = None,
    ) -> Component:
        comp = Component(
            id=component_id or new_component_id("dataset"),
            type=ComponentType.DATASET,
            name=name, version=version, supplier=supplier,
            license=_license(license), license_note=license_note,
            checksum=Checksum("sha256", checksum_sha256) if checksum_sha256 else None,
            external_refs=self._add_external_ref(external_ref),
            notes=notes,
            properties={
                "lineage_stage": lineage_stage,
                "record_count": record_count,
                "pii_reviewed": pii_reviewed,
                "source_uri": source_uri,
            },
        )
        self._components.append(comp)
        for parent_id in (derived_from_dataset_ids or []):
            self.add_relationship(comp.id, parent_id, RelationshipType.SOURCED_FROM)
        return comp

    # -- adapter -----------------------------------------------------------
    def add_adapter(
        self, name: str, version: str, *,
        method: str = "LoRA",
        base_model_id: str | None = None,
        dataset_ids: list[str] | None = None,
        supplier: str = "unknown",
        license: str | License = License.UNKNOWN,
        license_note: str = "",
        rank: int | None = None,
        alpha: float | None = None,
        target_modules: list[str] | None = None,
        trainer: str = "",
        training_date: str = "",
        hyperparameters: dict | None = None,
        checksum_sha256: str | None = None,
        external_ref: tuple | None = None,
        notes: str = "",
        component_id: str | None = None,
    ) -> Component:
        comp = Component(
            id=component_id or new_component_id("adapter"),
            type=ComponentType.ADAPTER,
            name=name, version=version, supplier=supplier,
            license=_license(license), license_note=license_note,
            checksum=Checksum("sha256", checksum_sha256) if checksum_sha256 else None,
            external_refs=self._add_external_ref(external_ref),
            notes=notes,
            properties={
                "method": method,
                "rank": rank,
                "alpha": alpha,
                "target_modules": target_modules or [],
                "trainer": trainer,
                "training_date": training_date,
                "hyperparameters": hyperparameters or {},
            },
        )
        self._components.append(comp)
        if base_model_id:
            self.add_relationship(comp.id, base_model_id, RelationshipType.DERIVED_FROM)
        for ds_id in (dataset_ids or []):
            self.add_relationship(comp.id, ds_id, RelationshipType.TRAINED_ON)
        return comp

    # -- merged model --------------------------------------------------
    def add_merged_model(
        self, name: str, version: str, *,
        merged_from_ids: list[str],
        supplier: str = "unknown",
        license: str | License = License.UNKNOWN,
        license_note: str = "",
        quantization: str = "",
        checksum_sha256: str | None = None,
        external_ref: tuple | None = None,
        notes: str = "",
        component_id: str | None = None,
    ) -> Component:
        comp = Component(
            id=component_id or new_component_id("merged"),
            type=ComponentType.MERGED_MODEL,
            name=name, version=version, supplier=supplier,
            license=_license(license), license_note=license_note,
            checksum=Checksum("sha256", checksum_sha256) if checksum_sha256 else None,
            external_refs=self._add_external_ref(external_ref),
            notes=notes,
            properties={"quantization": quantization},
        )
        self._components.append(comp)
        for parent_id in merged_from_ids:
            self.add_relationship(comp.id, parent_id, RelationshipType.MERGED_FROM)
        return comp

    # -- tokenizer ---------------------------------------------------------
    def add_tokenizer(
        self, name: str, version: str, *,
        included_in_id: str | None = None,
        vocab_size: int | None = None,
        supplier: str = "unknown",
        license: str | License = License.UNKNOWN,
        checksum_sha256: str | None = None,
        external_ref: tuple | None = None,
        notes: str = "",
        component_id: str | None = None,
    ) -> Component:
        comp = Component(
            id=component_id or new_component_id("tokenizer"),
            type=ComponentType.TOKENIZER,
            name=name, version=version, supplier=supplier,
            license=_license(license),
            checksum=Checksum("sha256", checksum_sha256) if checksum_sha256 else None,
            external_refs=self._add_external_ref(external_ref),
            notes=notes,
            properties={"vocab_size": vocab_size},
        )
        self._components.append(comp)
        if included_in_id:
            self.add_relationship(included_in_id, comp.id, RelationshipType.INCLUDES)
        return comp

    # -- finalize ------------------------------------------------------
    def build(self) -> ModelSBOM:
        return ModelSBOM(
            metadata=self._metadata,
            components=list(self._components),
            relationships=list(self._relationships),
        )

from msbom.builder import SBOMBuilder
from msbom.models import ComponentType, License, RelationshipType


def test_builder_produces_expected_component_counts(sample_sbom):
    sbom, _comps = sample_sbom
    assert len(sbom.components) == 5
    types = {c.type for c in sbom.components}
    assert types == {
        ComponentType.BASE_MODEL, ComponentType.DATASET,
        ComponentType.ADAPTER, ComponentType.MERGED_MODEL,
    }


def test_adapter_creates_derived_from_and_trained_on_relationships(sample_sbom):
    sbom, comps = sample_sbom
    adapter_id = comps["adapter"].id
    rels = [r for r in sbom.relationships if r.source_id == adapter_id]
    types = {r.type for r in rels}
    assert RelationshipType.DERIVED_FROM in types
    assert RelationshipType.TRAINED_ON in types

    derived = next(r for r in rels if r.type == RelationshipType.DERIVED_FROM)
    assert derived.target_id == comps["base"].id

    trained = next(r for r in rels if r.type == RelationshipType.TRAINED_ON)
    assert trained.target_id == comps["clean_ds"].id


def test_dataset_sourced_from_creates_relationship(sample_sbom):
    sbom, comps = sample_sbom
    rels = [r for r in sbom.relationships if r.source_id == comps["clean_ds"].id]
    assert any(
        r.type == RelationshipType.SOURCED_FROM and r.target_id == comps["raw_ds"].id
        for r in rels
    )


def test_merged_model_creates_merged_from_relationships(sample_sbom):
    sbom, comps = sample_sbom
    rels = [r for r in sbom.relationships if r.source_id == comps["merged"].id]
    targets = {r.target_id for r in rels if r.type == RelationshipType.MERGED_FROM}
    assert comps["base"].id in targets
    assert comps["adapter"].id in targets


def test_add_base_model_with_fine_tuned_from_creates_relationship():
    b = SBOMBuilder()
    parent = b.add_base_model(name="Llama-3-8B-base", version="1.0")
    child = b.add_base_model(
        name="Llama-3-8B-continued-pretrain", version="1.1",
        fine_tuned_from_id=parent.id,
    )
    sbom = b.build()
    rels = [r for r in sbom.relationships if r.source_id == child.id]
    assert any(r.type == RelationshipType.FINE_TUNED_FROM and r.target_id == parent.id for r in rels)


def test_tokenizer_includes_relationship_direction():
    b = SBOMBuilder()
    base = b.add_base_model(name="Model", version="1.0")
    tok = b.add_tokenizer(name="tokenizer", version="1.0", included_in_id=base.id, vocab_size=32000)
    sbom = b.build()
    rel = next(r for r in sbom.relationships if r.type == RelationshipType.INCLUDES)
    assert rel.source_id == base.id
    assert rel.target_id == tok.id


def test_unknown_license_string_falls_back_to_other():
    b = SBOMBuilder()
    comp = b.add_base_model(name="M", version="1.0", license="Some-Nonstandard-License")
    assert comp.license == License.OTHER


def test_builder_metadata_is_applied():
    b = SBOMBuilder(organization="Acme", authors=["a", "b"], description="desc")
    sbom = b.build()
    assert sbom.metadata.organization == "Acme"
    assert sbom.metadata.authors == ["a", "b"]
    assert sbom.metadata.description == "desc"


def test_explicit_component_id_is_respected():
    b = SBOMBuilder()
    comp = b.add_dataset(name="ds", version="1.0", component_id="my-fixed-id")
    assert comp.id == "my-fixed-id"

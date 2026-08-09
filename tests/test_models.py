from msbom.models import (
    Checksum,
    Component,
    ComponentType,
    ExternalRef,
    License,
    ModelSBOM,
    Relationship,
    RelationshipType,
    new_component_id,
)


def test_new_component_id_has_expected_prefix():
    cid = new_component_id("basemodel")
    assert cid.startswith("basemodel-")
    assert len(cid) == len("basemodel-") + 12


def test_checksum_round_trip():
    c = Checksum(algorithm="sha256", value="a" * 64)
    d = c.as_dict()
    c2 = Checksum.from_dict(d)
    assert c2 == c


def test_external_ref_round_trip_with_and_without_revision():
    r1 = ExternalRef(ref_type="huggingface", uri="meta-llama/Meta-Llama-3-8B", revision="main")
    assert ExternalRef.from_dict(r1.as_dict()) == r1

    r2 = ExternalRef(ref_type="s3", uri="s3://bucket/path/")
    d2 = r2.as_dict()
    assert "revision" not in d2
    assert ExternalRef.from_dict(d2).revision is None


def test_component_round_trip(sample_sbom):
    _sbom, comps = sample_sbom
    base = comps["base"]
    d = base.as_dict()
    restored = Component.from_dict(d)
    assert restored.id == base.id
    assert restored.type == ComponentType.BASE_MODEL
    assert restored.license == License.LLAMA_3_COMMUNITY
    assert restored.properties["parameter_count"] == 8_000_000_000


def test_relationship_round_trip():
    r = Relationship("adapter-1", "basemodel-1", RelationshipType.DERIVED_FROM, note="test")
    r2 = Relationship.from_dict(r.as_dict())
    assert r2 == r


def test_full_sbom_round_trip(sample_sbom):
    sbom, _ = sample_sbom
    d = sbom.as_dict()
    restored = ModelSBOM.from_dict(d)

    assert restored.bom_format == sbom.bom_format
    assert restored.spec_version == sbom.spec_version
    assert len(restored.components) == len(sbom.components)
    assert len(restored.relationships) == len(sbom.relationships)
    assert restored.as_dict() == d


def test_get_component_returns_none_for_missing_id(sample_sbom):
    sbom, _ = sample_sbom
    assert sbom.get_component("does-not-exist") is None


def test_get_component_finds_existing(sample_sbom):
    sbom, comps = sample_sbom
    found = sbom.get_component(comps["adapter"].id)
    assert found is not None
    assert found.name == "acme-support-lora"


def test_component_ids_returns_all_ids(sample_sbom):
    sbom, comps = sample_sbom
    ids = sbom.component_ids()
    assert comps["base"].id in ids
    assert comps["adapter"].id in ids
    assert len(ids) == len(sbom.components)


def test_unknown_license_falls_back_gracefully():
    d = {
        "id": "x-1", "type": "dataset", "name": "n", "version": "1",
        "created_at": "2026-01-01T00:00:00Z",
    }
    comp = Component.from_dict(d)
    assert comp.license == License.UNKNOWN

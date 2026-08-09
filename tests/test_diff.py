from msbom.builder import SBOMBuilder
from msbom.diff import diff_sboms


def test_identical_sboms_have_no_diff(sample_sbom):
    sbom, _ = sample_sbom
    d = diff_sboms(sbom, sbom)
    assert not d.has_changes


def test_added_component_detected(sample_sbom):
    sbom, _comps = sample_sbom
    b = SBOMBuilder()
    b._components = list(sbom.components)
    b._relationships = list(sbom.relationships)
    b.add_dataset(name="new-dataset", version="1.0")
    new_sbom = b.build()

    d = diff_sboms(sbom, new_sbom)
    assert len(d.added_components) == 1
    assert d.added_components[0].name == "new-dataset"
    assert not d.removed_components
    assert not d.changed_components


def test_removed_component_detected(sample_sbom):
    sbom, comps = sample_sbom
    b = SBOMBuilder()
    kept = [c for c in sbom.components if c.id != comps["merged"].id]
    kept_ids = {c.id for c in kept}
    b._components = kept
    b._relationships = [
        r for r in sbom.relationships
        if r.source_id in kept_ids and r.target_id in kept_ids
    ]
    new_sbom = b.build()

    d = diff_sboms(sbom, new_sbom)
    assert len(d.removed_components) == 1
    assert d.removed_components[0].id == comps["merged"].id


def test_checksum_change_detected(sample_sbom):
    sbom, comps = sample_sbom
    b = SBOMBuilder()
    new_components = []
    for c in sbom.components:
        if c.id == comps["adapter"].id:
            import dataclasses

            from msbom.models import Checksum
            c = dataclasses.replace(c, checksum=Checksum("sha256", "f" * 64))
        new_components.append(c)
    b._components = new_components
    b._relationships = list(sbom.relationships)
    new_sbom = b.build()

    d = diff_sboms(sbom, new_sbom)
    assert d.has_checksum_changes
    changed = next(c for c in d.changed_components if c.component_id == comps["adapter"].id)
    assert changed.checksum_changed
    _old_val, new_val = changed.changed_fields["checksum"]
    assert new_val == "f" * 64


def test_relationship_added_and_removed(sample_sbom):
    sbom, comps = sample_sbom
    b = SBOMBuilder()
    b._components = list(sbom.components)
    kept_rels = [r for r in sbom.relationships if r.source_id != comps["merged"].id]
    b._relationships = kept_rels
    from msbom.models import RelationshipType
    b.add_relationship(comps["merged"].id, comps["adapter"].id, RelationshipType.DEPENDS_ON)
    new_sbom = b.build()

    d = diff_sboms(sbom, new_sbom)
    assert len(d.added_relationships) == 1
    assert len(d.removed_relationships) == 2  # merged->base and merged->adapter (MERGED_FROM) removed


def test_summary_mentions_checksum_warning(sample_sbom):
    sbom, comps = sample_sbom
    b = SBOMBuilder()
    import dataclasses

    from msbom.models import Checksum
    new_components = [
        dataclasses.replace(c, checksum=Checksum("sha256", "f" * 64)) if c.id == comps["base"].id else c
        for c in sbom.components
    ]
    b._components = new_components
    b._relationships = list(sbom.relationships)
    new_sbom = b.build()

    d = diff_sboms(sbom, new_sbom)
    summary = d.summary()
    assert "checksum changed" in summary

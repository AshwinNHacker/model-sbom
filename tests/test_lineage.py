from msbom.builder import SBOMBuilder
from msbom.lineage import LineageGraph
from msbom.models import RelationshipType


def test_ancestors_of_adapter_includes_base_and_dataset(sample_sbom):
    sbom, comps = sample_sbom
    graph = LineageGraph(sbom)
    ancestors = graph.ancestors(comps["adapter"].id)
    assert comps["base"].id in ancestors
    assert comps["clean_ds"].id in ancestors
    # transitively via clean_ds SOURCED_FROM raw_ds
    assert comps["raw_ds"].id in ancestors


def test_descendants_of_raw_dataset_includes_adapter_and_merged(sample_sbom):
    sbom, comps = sample_sbom
    graph = LineageGraph(sbom)
    descendants = graph.descendants(comps["raw_ds"].id)
    assert comps["clean_ds"].id in descendants
    assert comps["adapter"].id in descendants
    assert comps["merged"].id in descendants


def test_descendants_of_base_model_includes_adapter_and_merged(sample_sbom):
    sbom, comps = sample_sbom
    graph = LineageGraph(sbom)
    descendants = graph.descendants(comps["base"].id)
    assert comps["adapter"].id in descendants
    assert comps["merged"].id in descendants


def test_direct_dependencies_and_dependents(sample_sbom):
    sbom, comps = sample_sbom
    graph = LineageGraph(sbom)
    direct_deps = graph.direct_dependencies(comps["adapter"].id)
    assert len(direct_deps) == 2  # DERIVED_FROM base + TRAINED_ON dataset

    direct_dependents = graph.direct_dependents(comps["base"].id)
    dependent_ids = {r.source_id for r in direct_dependents}
    assert comps["adapter"].id in dependent_ids
    assert comps["merged"].id in dependent_ids


def test_no_cycles_in_well_formed_sbom(sample_sbom):
    sbom, _ = sample_sbom
    graph = LineageGraph(sbom)
    assert graph.find_cycles() == []


def test_cycle_detection_catches_circular_provenance():
    b = SBOMBuilder()
    a = b.add_base_model(name="A", version="1.0")
    c = b.add_base_model(name="C", version="1.0", fine_tuned_from_id=a.id)
    # Manually introduce a cycle: A "fine_tuned_from" C, closing the loop.
    b.add_relationship(a.id, c.id, RelationshipType.FINE_TUNED_FROM)
    sbom = b.build()
    graph = LineageGraph(sbom)
    cycles = graph.find_cycles()
    assert len(cycles) >= 1


def test_path_finds_shortest_chain(sample_sbom):
    sbom, comps = sample_sbom
    graph = LineageGraph(sbom)
    path = graph.path(comps["adapter"].id, comps["raw_ds"].id)
    assert path is not None
    # adapter -> clean_ds -> raw_ds
    assert path[0].source_id == comps["adapter"].id
    assert path[-1].target_id == comps["raw_ds"].id


def test_path_returns_none_when_unreachable(sample_sbom):
    sbom, comps = sample_sbom
    graph = LineageGraph(sbom)
    # raw_ds does not derive from adapter (wrong direction)
    path = graph.path(comps["raw_ds"].id, comps["adapter"].id)
    assert path is None


def test_path_same_node_returns_empty_list(sample_sbom):
    sbom, comps = sample_sbom
    graph = LineageGraph(sbom)
    assert graph.path(comps["base"].id, comps["base"].id) == []


def test_dangling_references_detected():
    b = SBOMBuilder()
    a = b.add_base_model(name="A", version="1.0")
    b.add_relationship(a.id, "does-not-exist", RelationshipType.DERIVED_FROM)
    sbom = b.build()
    graph = LineageGraph(sbom)
    dangling = graph.dangling_references()
    assert len(dangling) == 1
    assert dangling[0].target_id == "does-not-exist"

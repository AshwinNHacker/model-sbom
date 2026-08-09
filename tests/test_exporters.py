import hashlib

from msbom.exporters import to_cyclonedx, to_dot, to_mermaid
from msbom.hashing import (
    canonical_json,
    document_hash,
    sha256_bytes,
    sha256_dir,
    sha256_file,
    verify_checksum,
)


def test_to_mermaid_contains_all_component_names(sample_sbom):
    sbom, _comps = sample_sbom
    output = to_mermaid(sbom)
    assert "flowchart TD" in output
    for c in sbom.components:
        assert c.name in output


def test_to_mermaid_contains_relationship_labels(sample_sbom):
    sbom, _ = sample_sbom
    output = to_mermaid(sbom)
    assert "DERIVED_FROM" in output
    assert "TRAINED_ON" in output


def test_to_mermaid_direction_is_configurable(sample_sbom):
    sbom, _ = sample_sbom
    assert "flowchart LR" in to_mermaid(sbom, direction="LR")


def test_to_dot_contains_digraph_and_all_nodes(sample_sbom):
    sbom, _comps = sample_sbom
    output = to_dot(sbom)
    assert output.startswith("digraph ModelSBOM {")
    for c in sbom.components:
        assert c.id in output


def test_to_cyclonedx_has_required_envelope_fields(sample_sbom):
    sbom, _ = sample_sbom
    doc = to_cyclonedx(sbom)
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"
    assert doc["serialNumber"] == sbom.serial_number
    assert len(doc["components"]) == len(sbom.components)


def test_to_cyclonedx_maps_component_types_correctly(sample_sbom):
    sbom, comps = sample_sbom
    doc = to_cyclonedx(sbom)
    by_ref = {c["bom-ref"]: c for c in doc["components"]}
    assert by_ref[comps["base"].id]["type"] == "machine-learning-model"
    assert by_ref[comps["clean_ds"].id]["type"] == "data"


def test_to_cyclonedx_includes_hashes_when_present(sample_sbom):
    sbom, comps = sample_sbom
    doc = to_cyclonedx(sbom)
    by_ref = {c["bom-ref"]: c for c in doc["components"]}
    assert by_ref[comps["base"].id]["hashes"][0]["content"] == "a" * 64


def test_to_cyclonedx_dependencies_reflect_relationships(sample_sbom):
    sbom, comps = sample_sbom
    doc = to_cyclonedx(sbom)
    dep_entry = next(d for d in doc["dependencies"] if d["ref"] == comps["adapter"].id)
    assert comps["base"].id in dep_entry["dependsOn"]
    assert comps["clean_ds"].id in dep_entry["dependsOn"]


# -- hashing ------------------------------------------------------------

def test_sha256_bytes_matches_stdlib():
    data = b"hello world"
    assert sha256_bytes(data) == hashlib.sha256(data).hexdigest()


def test_sha256_file_matches_stdlib(tmp_path):
    p = tmp_path / "f.txt"
    p.write_bytes(b"some file content" * 1000)
    assert sha256_file(p) == hashlib.sha256(p.read_bytes()).hexdigest()


def test_sha256_dir_is_order_independent(tmp_path):
    d = tmp_path / "d"
    d.mkdir()
    (d / "a.txt").write_text("alpha")
    (d / "b.txt").write_text("beta")
    (d / "sub").mkdir()
    (d / "sub" / "c.txt").write_text("gamma")

    h1 = sha256_dir(d)

    d2 = tmp_path / "d2"
    d2.mkdir()
    (d2 / "sub").mkdir()
    (d2 / "sub" / "c.txt").write_text("gamma")
    (d2 / "b.txt").write_text("beta")
    (d2 / "a.txt").write_text("alpha")

    h2 = sha256_dir(d2)
    assert h1 == h2


def test_sha256_dir_changes_when_content_changes(tmp_path):
    d = tmp_path / "d"
    d.mkdir()
    (d / "a.txt").write_text("alpha")
    h1 = sha256_dir(d)
    (d / "a.txt").write_text("ALPHA-MODIFIED")
    h2 = sha256_dir(d)
    assert h1 != h2


def test_verify_checksum_true_for_matching_file(tmp_path):
    p = tmp_path / "f.txt"
    p.write_bytes(b"content")
    expected = sha256_file(p)
    assert verify_checksum(p, "sha256", expected) is True


def test_verify_checksum_false_for_mismatched_file(tmp_path):
    p = tmp_path / "f.txt"
    p.write_bytes(b"content")
    assert verify_checksum(p, "sha256", "f" * 64) is False


def test_verify_checksum_rejects_unsupported_algorithm(tmp_path):
    p = tmp_path / "f.txt"
    p.write_bytes(b"content")
    try:
        verify_checksum(p, "md5", "x")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_canonical_json_is_key_order_independent():
    a = canonical_json({"b": 1, "a": 2})
    b = canonical_json({"a": 2, "b": 1})
    assert a == b


def test_document_hash_ignores_timestamp(sample_sbom):
    sbom, _ = sample_sbom
    d1 = sbom.as_dict()
    d2 = sbom.as_dict()
    d2["metadata"]["timestamp"] = "2099-01-01T00:00:00Z"
    assert document_hash(d1) == document_hash(d2)


def test_document_hash_changes_when_content_changes(sample_sbom):
    sbom, _ = sample_sbom
    d1 = sbom.as_dict()
    d2 = sbom.as_dict()
    d2["components"][0]["name"] = "renamed"
    assert document_hash(d1) != document_hash(d2)

from msbom.builder import SBOMBuilder
from msbom.models import RelationshipType
from msbom.validator import validate, validate_schema


def test_well_formed_sbom_has_no_errors(sample_sbom):
    sbom, _ = sample_sbom
    report = validate(sbom)
    assert report.is_valid, report


def test_missing_checksum_produces_warning():
    b = SBOMBuilder()
    b.add_base_model(name="M", version="1.0", license="MIT",
                      external_ref=("huggingface", "org/model"))
    sbom = b.build()
    report = validate(sbom)
    assert any(i.code == "MISSING_CHECKSUM" for i in report.warnings)
    assert report.is_valid  # warning, not error


def test_unknown_license_produces_warning():
    b = SBOMBuilder()
    b.add_base_model(name="M", version="1.0", checksum_sha256="a" * 64,
                      external_ref=("huggingface", "org/model"))
    sbom = b.build()
    report = validate(sbom)
    assert any(i.code == "UNKNOWN_LICENSE" for i in report.warnings)


def test_adapter_without_base_model_is_an_error():
    b = SBOMBuilder()
    ds = b.add_dataset(name="ds", version="1.0")
    b.add_adapter(name="orphan-adapter", version="1.0", dataset_ids=[ds.id])
    sbom = b.build()
    report = validate(sbom)
    assert not report.is_valid
    assert any(i.code == "ADAPTER_MISSING_BASE_MODEL" for i in report.errors)


def test_adapter_without_training_data_is_a_warning():
    b = SBOMBuilder()
    base = b.add_base_model(name="base", version="1.0")
    b.add_adapter(name="adapter", version="1.0", base_model_id=base.id)
    sbom = b.build()
    report = validate(sbom)
    assert any(i.code == "ADAPTER_MISSING_TRAINING_DATA" for i in report.warnings)


def test_dangling_reference_is_an_error():
    b = SBOMBuilder()
    a = b.add_base_model(name="A", version="1.0")
    b.add_relationship(a.id, "ghost-id", RelationshipType.DERIVED_FROM)
    sbom = b.build()
    report = validate(sbom)
    assert not report.is_valid
    assert any(i.code == "DANGLING_REFERENCE" for i in report.errors)


def test_provenance_cycle_is_an_error():
    b = SBOMBuilder()
    a = b.add_base_model(name="A", version="1.0")
    c = b.add_base_model(name="C", version="1.0", fine_tuned_from_id=a.id)
    b.add_relationship(a.id, c.id, RelationshipType.FINE_TUNED_FROM)
    sbom = b.build()
    report = validate(sbom)
    assert not report.is_valid
    assert any(i.code == "PROVENANCE_CYCLE" for i in report.errors)


def test_duplicate_component_id_is_an_error():
    b = SBOMBuilder()
    b.add_base_model(name="A", version="1.0", component_id="dup-id")
    b.add_dataset(name="B", version="1.0", component_id="dup-id")
    sbom = b.build()
    report = validate(sbom)
    assert not report.is_valid
    assert any(i.code == "DUPLICATE_ID" for i in report.errors)


def test_final_training_set_without_pii_flag_is_a_warning():
    b = SBOMBuilder()
    b.add_dataset(name="ds", version="1.0", lineage_stage="final_training_set")
    sbom = b.build()
    report = validate(sbom)
    assert any(i.code == "PII_REVIEW_UNSET" for i in report.warnings)


def test_final_training_set_with_pii_flag_set_false_does_not_warn():
    b = SBOMBuilder()
    b.add_dataset(name="ds", version="1.0", lineage_stage="final_training_set", pii_reviewed=False)
    sbom = b.build()
    report = validate(sbom)
    assert not any(i.code == "PII_REVIEW_UNSET" for i in report.warnings)


def test_validation_report_str_contains_issue_details():
    b = SBOMBuilder()
    b.add_base_model(name="A", version="1.0")
    report = validate(b.build())
    text = str(report)
    assert "WARNING" in text


def test_empty_report_str():
    from msbom.validator import ValidationReport
    r = ValidationReport()
    assert str(r) == "No issues found."


def test_validate_schema_without_jsonschema_installed_is_graceful(sample_sbom, monkeypatch):
    """
    Simulate jsonschema not being installed by making the import fail, and
    confirm we get a warning (not a crash) and validate() results remain
    trustworthy on their own.
    """
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "jsonschema":
            raise ImportError("simulated missing dependency")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    sbom, _ = sample_sbom
    report = validate_schema(sbom.as_dict())
    assert report.is_valid  # missing dep is a warning, not an error
    assert any(i.code == "JSONSCHEMA_UNAVAILABLE" for i in report.warnings)


def test_validate_schema_with_jsonschema_installed_passes_for_valid_doc(sample_sbom):
    try:
        import jsonschema  # noqa: F401
    except ImportError:
        import pytest
        pytest.skip("jsonschema not installed")
    sbom, _ = sample_sbom
    report = validate_schema(sbom.as_dict())
    assert report.is_valid, report


def test_validate_schema_catches_invalid_doc():
    try:
        import jsonschema  # noqa: F401
    except ImportError:
        import pytest
        pytest.skip("jsonschema not installed")
    bad_doc = {"bom_format": "NotModelSBOM"}
    report = validate_schema(bad_doc)
    assert not report.is_valid

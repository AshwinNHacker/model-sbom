import pytest

from msbom.builder import SBOMBuilder


@pytest.fixture
def sample_sbom():
    b = SBOMBuilder(organization="Acme Corp", authors=["ml-platform-team"],
                     description="Test fixture SBOM")

    base = b.add_base_model(
        name="Llama-3-8B", version="3.0",
        supplier="Meta", license="Llama3-Community-License",
        parameter_count=8_000_000_000,
        architecture="transformer-decoder",
        training_data_cutoff="2024-03",
        checksum_sha256="a" * 64,
        external_ref=("huggingface", "meta-llama/Meta-Llama-3-8B", "main"),
    )

    raw_ds = b.add_dataset(
        name="support-tickets-raw", version="2026-05-01",
        license="Proprietary",
        lineage_stage="raw_collection",
        record_count=52000,
        source_uri="s3://acme-ml-data/support-tickets/raw/",
        checksum_sha256="b" * 64,
        external_ref=("s3", "s3://acme-ml-data/support-tickets/raw/"),
    )

    clean_ds = b.add_dataset(
        name="support-tickets-clean", version="2026-06-01",
        license="Proprietary",
        lineage_stage="final_training_set",
        record_count=48213,
        pii_reviewed=True,
        source_uri="s3://acme-ml-data/support-tickets/clean/",
        checksum_sha256="c" * 64,
        external_ref=("s3", "s3://acme-ml-data/support-tickets/clean/"),
        derived_from_dataset_ids=[raw_ds.id],
    )

    adapter = b.add_adapter(
        name="acme-support-lora", version="v3",
        method="LoRA", base_model_id=base.id, dataset_ids=[clean_ds.id],
        rank=16, alpha=32, target_modules=["q_proj", "v_proj"],
        trainer="acme-ml-platform", training_date="2026-07-15",
        license="Apache-2.0",
        checksum_sha256="d" * 64,
        external_ref=("internal_registry", "registry.acme.internal/adapters/support-lora/v3"),
    )

    merged = b.add_merged_model(
        name="acme-support-model-merged", version="v3",
        merged_from_ids=[base.id, adapter.id],
        license="Llama3-Community-License",
        quantization="int8",
        checksum_sha256="e" * 64,
    )

    return b.build(), {
        "base": base, "raw_ds": raw_ds, "clean_ds": clean_ds,
        "adapter": adapter, "merged": merged,
    }

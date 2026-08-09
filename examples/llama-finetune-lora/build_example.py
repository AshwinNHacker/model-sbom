#!/usr/bin/env python3
"""
build_example.py
=================
Builds a realistic, end-to-end example ModelSBOM: a base model, a raw ->
cleaned dataset lineage chain, a LoRA adapter trained on the clean
dataset, and a final int8-quantized merged model — the same shape as a
typical enterprise fine-tuning pipeline.

Run:
    python examples/llama-finetune-lora/build_example.py

Writes examples/llama-finetune-lora/sbom.json, sbom.mmd (Mermaid lineage
diagram), and sbom.cdx.json (CycloneDX-inspired export).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from msbom import io as msbom_io
from msbom.builder import SBOMBuilder
from msbom.exporters import to_cyclonedx, to_mermaid
from msbom.validator import validate

OUT_DIR = Path(__file__).resolve().parent


def build() -> None:
    b = SBOMBuilder(
        organization="Acme Corp",
        authors=["ml-platform-team@acme.example"],
        description=(
            "Support-ticket triage assistant: Llama-3-8B base model, "
            "fine-tuned with a LoRA adapter on cleaned internal support "
            "ticket data, then merged and quantized for deployment."
        ),
    )

    # -- base model -------------------------------------------------------
    base = b.add_base_model(
        name="Llama-3-8B",
        version="3.0",
        supplier="Meta",
        license="Llama3-Community-License",
        license_note="Redistribution of derivatives requires the 'Built with Llama 3' notice per Meta's community license.",
        parameter_count=8_000_000_000,
        architecture="transformer-decoder, GQA, 8B params, 8K context",
        training_data_cutoff="2024-03",
        checksum_sha256="6255887a756104cf94678d4c476b56dbec74e3713d1453de823e905937b58527",
        external_ref=("huggingface", "meta-llama/Meta-Llama-3-8B", "main"),
        notes="Downloaded and pinned to a specific commit revision for reproducibility.",
    )

    b.add_tokenizer(
        name="llama-3-tokenizer",
        version="3.0",
        included_in_id=base.id,
        vocab_size=128256,
        supplier="Meta",
        license="Llama3-Community-License",
        external_ref=("huggingface", "meta-llama/Meta-Llama-3-8B", "main"),
    )

    # -- dataset lineage: raw -> filtered -> pii-scrubbed -> final -------
    raw_ds = b.add_dataset(
        name="support-tickets-raw-export",
        version="2026-05-01",
        supplier="Acme Corp (internal)",
        license="Proprietary",
        license_note="Internal data; not for external distribution.",
        lineage_stage="raw_collection",
        record_count=52104,
        source_uri="s3://acme-ml-data/support-tickets/raw/2026-05-01/",
        checksum_sha256="4163fb4ab9e1e0a51709a51bc7e13ab6792907905960145c722d2c1479caac42",
        external_ref=("s3", "s3://acme-ml-data/support-tickets/raw/2026-05-01/"),
        notes="Direct export from the support ticketing system, unfiltered.",
    )

    filtered_ds = b.add_dataset(
        name="support-tickets-filtered",
        version="2026-05-10",
        supplier="Acme Corp (internal)",
        license="Proprietary",
        lineage_stage="filtered",
        record_count=49850,
        source_uri="s3://acme-ml-data/support-tickets/filtered/2026-05-10/",
        checksum_sha256="2545f7706a6a945c9f1f8caea28c0c5ac971afc55e5e91e5bab5736329e55ff7",
        external_ref=("s3", "s3://acme-ml-data/support-tickets/filtered/2026-05-10/"),
        derived_from_dataset_ids=[raw_ds.id],
        notes="Removed non-English tickets, spam, and duplicate submissions.",
    )

    clean_ds = b.add_dataset(
        name="support-tickets-clean-final",
        version="2026-06-01",
        supplier="Acme Corp (internal)",
        license="Proprietary",
        lineage_stage="final_training_set",
        record_count=48213,
        pii_reviewed=True,
        source_uri="s3://acme-ml-data/support-tickets/clean/2026-06-01/",
        checksum_sha256="79ae95b1694411619d984687b93692614069e2aee5fea36a30042660de8b237e",
        external_ref=("s3", "s3://acme-ml-data/support-tickets/clean/2026-06-01/"),
        derived_from_dataset_ids=[filtered_ds.id],
        notes="PII-scrubbed (customer names/emails/phone numbers redacted) and reviewed by the data governance team on 2026-06-02.",
    )

    # -- adapter -----------------------------------------------------------
    adapter = b.add_adapter(
        name="acme-support-triage-lora",
        version="3",
        method="LoRA",
        base_model_id=base.id,
        dataset_ids=[clean_ds.id],
        supplier="Acme Corp (internal)",
        license="Apache-2.0",
        license_note="Adapter weights only; base model retains its own Meta community license.",
        rank=16,
        alpha=32,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
        trainer="acme-ml-platform (Ray + PEFT 0.11)",
        training_date="2026-07-15",
        hyperparameters={"learning_rate": 2e-4, "epochs": 3, "batch_size": 32, "warmup_ratio": 0.03},
        checksum_sha256="991da788b329ca78ea2fc326611736a45c816f98fdbea577304ea8a27074909d",
        external_ref=("internal_registry", "registry.acme.internal/adapters/support-triage-lora/v3"),
        notes="Third training run for this adapter line; v1/v2 are archived, not included in this SBOM.",
    )

    # -- merged, quantized deployment artifact ----------------------------
    b.add_merged_model(
        name="acme-support-triage-model-deploy",
        version="3",
        merged_from_ids=[base.id, adapter.id],
        supplier="Acme Corp (internal)",
        license="Llama3-Community-License",
        license_note="Inherits base model license terms; 'Built with Llama 3' notice included in model card.",
        quantization="int8 (bitsandbytes)",
        checksum_sha256="69c5ca4b914f58e4faea352d47e3193dda0a8ff88d7be187152b5f7b17827d82",
        external_ref=("internal_registry", "registry.acme.internal/models/support-triage/v3"),
        notes="Deployed to production inference cluster on 2026-07-20.",
    )

    sbom = b.build()

    # -- validate before writing anything ---------------------------------
    report = validate(sbom)
    print(report)
    print()
    print(f"{len(report.errors)} error(s), {len(report.warnings)} warning(s)")
    if not report.is_valid:
        raise SystemExit("Example SBOM failed validation — fix build_example.py")

    # -- write outputs ------------------------------------------------------
    msbom_io.save(sbom, OUT_DIR / "sbom.json")
    (OUT_DIR / "sbom.mmd").write_text(to_mermaid(sbom, direction="LR"), encoding="utf-8")

    import json
    (OUT_DIR / "sbom.cdx.json").write_text(
        json.dumps(to_cyclonedx(sbom), indent=2), encoding="utf-8"
    )

    print(f"\nWrote {OUT_DIR / 'sbom.json'}")
    print(f"Wrote {OUT_DIR / 'sbom.mmd'}")
    print(f"Wrote {OUT_DIR / 'sbom.cdx.json'}")


if __name__ == "__main__":
    build()

# model-sbom

**Model supply chain SBOM: base model provenance, fine-tuning data lineage, and adapter provenance — as a schema, a builder API, and a validator/lineage/diff toolkit.**

[![CI](https://github.com/AshwinNHacker/model-sbom/actions/workflows/ci.yml/badge.svg)](https://github.com/AshwinNHacker/model-sbom/actions/workflows/ci.yml)
![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![Spec version](https://img.shields.io/badge/spec-v1.0.0-orange.svg)

A deployed LLM is rarely one artifact — it's a base model (trained on data
you probably didn't collect), one or more fine-tuning datasets with their
own collection/filtering/PII-review history, and often an adapter (LoRA,
QLoRA, a full fine-tune) layered on top, sometimes merged into a final
deployable checkpoint. **model-sbom** gives that chain an explicit,
machine-readable, git-diffable record — so questions like *"what license
governs everything in this deployed model?"* or *"which deployed models
are downstream of this dataset?"* have a real answer instead of relying on
institutional memory.

## What's in the box

- **A document format** (`ModelSBOM`, `schema/model-sbom.schema.json`)
  with five component types (`base_model`, `dataset`, `adapter`,
  `merged_model`, `tokenizer`) and seven typed provenance relationships
  (`DERIVED_FROM`, `TRAINED_ON`, `FINE_TUNED_FROM`, `MERGED_FROM`,
  `INCLUDES`, `SOURCED_FROM`, `DEPENDS_ON`).
- **A fluent Python builder API** so generating an SBOM is a natural part
  of a training/fine-tuning pipeline, not a manual afterthought.
- **A lineage graph engine** — ancestors, descendants, cycle detection,
  shortest-path — so you can answer "what was this built from" or "what
  depends on this" in one call.
- **A validator** — zero-dependency structural/business-rule checks
  (dangling references, provenance cycles, missing checksums/licenses,
  adapters with no recorded base model or training data, datasets marked
  as final training sets with no PII-review flag) plus optional full JSON
  Schema validation.
- **A diff engine** — compare two SBOM versions; checksum changes (the
  most security-relevant kind) are called out specially.
- **Integrity verification** — sha256 checksums for files or whole
  checkpoint directories, and a CLI command to verify an artifact on disk
  still matches what the SBOM recorded.
- **Exporters** — Mermaid (renders natively in GitHub Markdown), Graphviz
  DOT, and a CycloneDX-inspired JSON mapping for interop.
- **A CLI** (`msbom`) and a **realistic worked example**
  (Llama-3-8B → 3-stage dataset lineage → LoRA adapter → merged/quantized
  deployment artifact).

## Quickstart

```bash
git clone https://github.com/AshwinNHacker/model-sbom.git
cd model-sbom
pip install -e .

python examples/llama-finetune-lora/build_example.py
msbom summary examples/llama-finetune-lora/sbom.json
```

```
ModelSBOM ModelSBOM v1.0.0  (doc version 1)
Organization: Acme Corp

Components:
  adapter         1
  base_model      1
  dataset         3
  merged_model    1
  tokenizer       1
Relationships: 7
```

No installation of anything beyond the standard library required — the
core (data model, builder, validator's structural checks, lineage graph,
diff engine, hashing, Mermaid/DOT/CycloneDX exporters) has **zero
required third-party dependencies**.

### Trace a full provenance chain

```bash
msbom lineage examples/llama-finetune-lora/sbom.json --component <merged-model-id>
```

```
Ancestors (6) — everything this was built from:
  - acme-support-triage-lora v3 [adapter]
  - Llama-3-8B v3.0 [base_model]
  - support-tickets-clean-final v2026-06-01 [dataset]
  - support-tickets-raw-export v2026-05-01 [dataset]
  - support-tickets-filtered v2026-05-10 [dataset]
  - llama-3-tokenizer v3.0 [tokenizer]
```

That's the whole chain — base model, every dataset stage, tokenizer, and
adapter — traced transitively from a single deployed-artifact ID.

## Generating an SBOM as part of your pipeline

```python
from msbom.builder import SBOMBuilder
from msbom import io as msbom_io
from msbom.validator import validate

b = SBOMBuilder(organization="Acme Corp", authors=["ml-platform-team"])

base = b.add_base_model(
    name="Llama-3-8B", version="3.0",
    supplier="Meta", license="Llama3-Community-License",
    parameter_count=8_000_000_000,
    external_ref=("huggingface", "meta-llama/Meta-Llama-3-8B", "main"),
)

clean_ds = b.add_dataset(
    name="support-tickets-clean", version="2026-06-01",
    license="Proprietary", lineage_stage="final_training_set",
    pii_reviewed=True, record_count=48213,
)

adapter = b.add_adapter(
    name="acme-support-lora", version="3",
    method="LoRA", base_model_id=base.id, dataset_ids=[clean_ds.id],
    rank=16, alpha=32, trainer="acme-ml-platform",
)

sbom = b.build()

report = validate(sbom)
assert report.is_valid, report

msbom_io.save(sbom, "sbom.json")
```

`add_adapter(base_model_id=..., dataset_ids=[...])` automatically creates
the `DERIVED_FROM` and `TRAINED_ON` relationship edges — you describe
*what came from what* once, and the lineage graph, validator, and
exporters all work off the same edges.

## CLI reference

```
msbom validate <sbom.json> [--schema]     # structural checks; --schema adds full JSON Schema validation
msbom summary <sbom.json>                 # component counts, org, generated-at
msbom lineage <sbom.json> --component ID  # ancestors + descendants of one component
msbom diff <old.json> <new.json> [-v] [--fail-on-checksum-change]
msbom export <sbom.json> --format {mermaid,dot,cyclonedx} [--out FILE]
msbom verify <sbom.json> --component-id ID --artifact-path PATH   # recompute sha256, compare to recorded checksum
```

## Validation you get for free

Every SBOM is checked for real supply-chain hygiene issues, not just
schema shape:

| Check | Severity | Catches |
|---|---|---|
| `DANGLING_REFERENCE` | error | A relationship points at a component ID that doesn't exist |
| `PROVENANCE_CYCLE` | error | Circular derivation (A derived from B derived from A) |
| `DUPLICATE_ID` | error | Two components sharing an ID |
| `ADAPTER_MISSING_BASE_MODEL` | error | An adapter with no recorded base model |
| `ADAPTER_MISSING_TRAINING_DATA` | warning | An adapter with no recorded training dataset |
| `UNKNOWN_LICENSE` | warning | A component with no license recorded |
| `MISSING_CHECKSUM` | warning | A component whose integrity can't be verified |
| `MISSING_SOURCE_REF` | warning | A component with no recorded external source |
| `PII_REVIEW_UNSET` | warning | A final-training-set dataset with no explicit PII-review flag |

Full rationale for every field and check: [`docs/spec.md`](docs/spec.md).

## Project structure

```
model-sbom/
├── schema/model-sbom.schema.json     # JSON Schema for the document format
├── src/msbom/
│   ├── models.py                     # Component, Relationship, ModelSBOM dataclasses
│   ├── builder.py                    # SBOMBuilder fluent API
│   ├── lineage.py                    # ancestors/descendants/cycles/path graph traversal
│   ├── validator.py                  # structural checks + optional JSON Schema validation
│   ├── diff.py                       # compare two SBOM documents
│   ├── hashing.py                    # file/dir sha256, deterministic document hashing
│   ├── io.py                         # load/save SBOM JSON files
│   ├── exporters/
│   │   ├── mermaid.py                # GitHub-renderable lineage flowchart
│   │   ├── graphviz_dot.py           # .dot lineage graph
│   │   └── cyclonedx.py              # CycloneDX-inspired interop export
│   └── cli.py                        # `msbom` entry point
├── examples/llama-finetune-lora/     # realistic worked example + generated SBOM
├── tests/                            # 79-test pytest suite
├── docs/spec.md                      # full field-by-field specification
├── .github/workflows/ci.yml          # lint + test + example build/validate
├── CHANGELOG.md
└── CONTRIBUTING.md
```

## Scope note

This project defines its own lightweight ModelSBOM format, modeled on
concepts from CycloneDX's ML-BOM profile and SPDX 3.0's AI/dataset
profiles but not a certified implementation of either. The bundled
CycloneDX exporter is documented as a best-effort interop mapping — see
the note at the top of `src/msbom/exporters/cyclonedx.py` before relying
on it for strict compliance requirements.

## License

[MIT](LICENSE)

2026

# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/) for
both the **code** (`src/msbom`, CLI) and the **spec**
(`docs/spec.md` + `schema/model-sbom.schema.json`), which are versioned
together in v1.x since the schema is small enough that code and spec
changes are currently released in lockstep. If they diverge in the
future, this file will call that out explicitly per entry.

## [Unreleased]

### Planned
- Cryptographic signing integration (Sigstore/cosign) for SBOM documents,
  layered on top of the existing `hashing.document_hash()` content hash.
- Additional checksum algorithms beyond sha256 (e.g. BLAKE3 for large
  checkpoint directories).
- A `msbom scan` command that walks a Hugging Face-style model directory
  and auto-populates checksums/external_refs from `config.json` /
  `adapter_config.json` where present.
- SPDX 3.0 AI-profile export, alongside the existing CycloneDX-inspired one.

## [1.0.0] - 2026-08-06

### Added
- Core data model (`src/msbom/models.py`): `Component` (base_model,
  dataset, adapter, merged_model, tokenizer), `Relationship` (7 typed
  edges: DERIVED_FROM, TRAINED_ON, FINE_TUNED_FROM, MERGED_FROM, INCLUDES,
  SOURCED_FROM, DEPENDS_ON), `Checksum`, `ExternalRef`, and the top-level
  `ModelSBOM` document.
- Fluent builder API (`src/msbom/builder.py`) with type-specific
  `add_base_model` / `add_dataset` / `add_adapter` / `add_merged_model` /
  `add_tokenizer` methods that auto-create the relevant provenance
  relationships.
- Lineage graph traversal (`src/msbom/lineage.py`): ancestors,
  descendants, cycle detection, shortest-path, dangling-reference
  detection.
- Structural validator (`src/msbom/validator.py`) with zero required
  dependencies, covering referential integrity, cycle detection, license/
  checksum/source-ref hygiene, adapter provenance completeness, and a
  PII-review-flag check for datasets marked as final training sets.
  Optional full JSON Schema validation via `jsonschema` (graceful
  degradation if not installed).
- Diff engine (`src/msbom/diff.py`) comparing two SBOM documents:
  added/removed/changed components (checksum changes flagged specially)
  and added/removed relationships.
- Hashing utilities (`src/msbom/hashing.py`): file and order-independent
  directory sha256, deterministic document-content hashing (ignores
  regeneration timestamp), and artifact-vs-SBOM checksum verification.
- Exporters (`src/msbom/exporters/`): Mermaid flowchart, Graphviz DOT, and
  a CycloneDX-inspired JSON mapping (documented as best-effort interop,
  not certified spec compliance).
- CLI (`msbom`): `validate`, `summary`, `lineage`, `diff`, `export`,
  `verify` subcommands.
- JSON Schema (`schema/model-sbom.schema.json`) and full specification
  document (`docs/spec.md`).
- Realistic worked example (`examples/llama-finetune-lora/`): a Llama-3-8B
  base model, a 3-stage dataset lineage chain (raw → filtered → clean),
  a LoRA adapter, and a merged/quantized deployment artifact.
- GitHub Actions CI: lint, full test suite (Python 3.10–3.12), example
  SBOM build + validation, and example-SBOM artifact upload.
- 79-test pytest suite covering the data model, builder, lineage graph,
  validator, diff engine, exporters, hashing, and CLI.

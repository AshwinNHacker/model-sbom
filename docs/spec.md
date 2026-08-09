# ModelSBOM Specification (v1.0.0)

## Purpose

An ML model shipped to production is a supply chain, not a single
artifact: a base model (itself trained on data you probably didn't
collect), one or more fine-tuning datasets with their own collection/
filtering/PII-review history, and often one or more adapters (LoRA,
QLoRA, full fine-tunes) layered on top, sometimes merged into a final
deployable artifact. **ModelSBOM** is a document format for recording
that chain explicitly, so questions like:

- "What license governs everything that went into this deployed model?"
- "If dataset X is found to contain a data-quality problem, which
  deployed models are downstream of it?"
- "Has this adapter's training data ever had a documented PII review?"
- "Did the weights we're about to deploy actually match what was
  recorded at SBOM-generation time, or has the artifact changed since?"

...can be answered mechanically instead of by institutional memory.

## Document structure

```
ModelSBOM
├── bom_format: "ModelSBOM"
├── spec_version: "1.0.0"
├── serial_number: "urn:uuid:..."   (stable identity for this document)
├── version: 1                       (bumped each time the doc is regenerated)
├── metadata: { tool_name, tool_version, authors, organization, timestamp, description }
├── components: [ Component, ... ]
└── relationships: [ Relationship, ... ]
```

### Components

Every artifact in the supply chain is a `Component` with a `type`:

| Type | Represents |
|---|---|
| `base_model` | A pretrained foundation model, either third-party (Llama, Mistral, ...) or an internally pretrained model. |
| `dataset` | Any dataset used at any lineage stage — raw collection, filtered, deduplicated, PII-scrubbed, labeled, synthetic, or the final training set. |
| `adapter` | A parameter-efficient fine-tune layered on a base model: LoRA, QLoRA, prompt/prefix tuning, or (recorded here for convenience even though it isn't literally an "adapter") a full fine-tune / RLHF / DPO run. |
| `merged_model` | A deployable artifact produced by merging a base model with one or more adapters, optionally quantized. |
| `tokenizer` | Recorded separately from its base model because tokenizers sometimes have independent versioning/licensing (e.g. a custom-trained tokenizer bundled with a fine-tune). |

Every component carries:

- **`id`** — a stable, unique string (the builder generates
  `<type>-<12-hex-chars>` by default; you can also assign your own).
- **`name` / `version`** — human-readable identity.
- **`supplier`** — who produced this artifact (a company, a team, "unknown").
- **`license` / `license_note`** — from a closed enum of common ML
  licenses (see `models.py::License`) plus `OTHER`/`UNKNOWN` escape
  hatches, with a free-text `license_note` for nuance (e.g. attribution
  requirements, field-of-use restrictions).
- **`checksum`** — currently sha256 only, either a single-file hash
  (`hashing.sha256_file`) or an order-independent whole-directory hash
  (`hashing.sha256_dir`, useful for a full model checkpoint directory).
- **`external_refs`** — where the artifact actually lives: a Hugging Face
  repo + revision, an S3 URI, a git commit, an internal model registry
  path, or a generic URL.
- **`properties`** — a free-form bag for type-specific fields that don't
  need their own top-level schema slot: `parameter_count`,
  `training_data_cutoff`, and `architecture` for base models;
  `lineage_stage`, `record_count`, `pii_reviewed`, and `source_uri` for
  datasets; `method`, `rank`, `alpha`, `target_modules`, `trainer`,
  `training_date`, and `hyperparameters` for adapters; `quantization` for
  merged models; `vocab_size` for tokenizers.

### Relationships (the provenance graph)

Provenance is expressed as explicit directed edges rather than only
nested references, so it can be traversed in either direction:

| Relationship | Meaning | Typical source → target |
|---|---|---|
| `DERIVED_FROM` | "built on top of" | adapter/merged_model → base_model |
| `TRAINED_ON` | "used this data during training" | adapter/base_model → dataset |
| `FINE_TUNED_FROM` | "continued-pretraining parent" | base_model → base_model |
| `MERGED_FROM` | "one of the inputs to a merge" | merged_model → base_model/adapter |
| `INCLUDES` | "bundles this as a sub-component" | base_model → tokenizer |
| `SOURCED_FROM` | "this dataset was derived/filtered/mixed from that one" | dataset → dataset |
| `DEPENDS_ON` | generic catch-all dependency | any → any |

`src/msbom/lineage.py::LineageGraph` treats these as forward edges
(source depends-on/derived-from target) and provides:

- `ancestors(id)` — everything transitively upstream (what was this built from).
- `descendants(id)` — everything transitively downstream (what depends on this).
- `find_cycles()` — provenance graphs must be acyclic; a cycle is a data-entry
  error (or a real, worrying claim) and is always a validation **error**.
- `path(a, b)` — a concrete chain of edges explaining *how* a is derived from b.

## Validation

`src/msbom/validator.py::validate()` runs structural/business-rule checks
with zero dependencies:

**Errors** (block a release / fail CI):
- `DANGLING_REFERENCE` — a relationship points at a component ID that
  doesn't exist in the document.
- `DUPLICATE_ID` — two components share an ID.
- `PROVENANCE_CYCLE` — the relationship graph is not acyclic.
- `ADAPTER_MISSING_BASE_MODEL` — an adapter has no `DERIVED_FROM` edge to
  any base model.

**Warnings** (should be looked at, don't block by default):
- `UNKNOWN_LICENSE` — a component's license wasn't recorded.
- `MISSING_CHECKSUM` — a component has no checksum, so its integrity
  can't be verified against the artifact on disk.
- `MISSING_SOURCE_REF` — a component has no external reference recording
  where it actually lives.
- `ADAPTER_MISSING_TRAINING_DATA` — an adapter has no `TRAINED_ON` edge to
  any dataset, so its fine-tuning data lineage is incomplete.
- `PII_REVIEW_UNSET` — a dataset marked `lineage_stage=final_training_set`
  has no explicit `pii_reviewed` (True/False) value set.

`validate_schema()` layers full JSON Schema validation
(`schema/model-sbom.schema.json`) on top when the optional `jsonschema`
package is installed; it degrades to a single informational warning
(not an error) when it isn't, so CI can still gate on the structural
checks without the extra dependency.

## Integrity verification

`msbom verify <sbom.json> --component-id <id> --artifact-path <path>`
recomputes the sha256 of the artifact on disk (file or whole directory)
and compares it against the checksum recorded in the SBOM, exiting
non-zero on mismatch. This is the mechanism for catching "the weights
that got deployed aren't actually the weights the SBOM describes" —
whether from an honest mistake or a supply-chain tamper.

`hashing.document_hash()` produces a deterministic hash of an entire SBOM
document's *content* (excluding the regeneration timestamp), so two SBOM
files can be compared for meaningful equality without diffing JSON
key-order noise.

## Diffing

`msbom diff old.json new.json` reports components added/removed/changed
(field-by-field, with checksum changes called out specially since
they're the most security-relevant kind of change) and relationships
added/removed. `--fail-on-checksum-change` gates CI on any component's
recorded checksum changing between two SBOM versions.

## Versioning

The **spec** (this document + `schema/model-sbom.schema.json`) is
versioned independently of any individual SBOM **document**. A document's
own `version` field is a simple integer you bump each time you regenerate
it for the same underlying pipeline (see `CHANGELOG.md` for how the
project itself is versioned).

## Non-goals / known limitations

- This is not a certified implementation of CycloneDX ML-BOM or SPDX 3.0
  AI profiles. `exporters/cyclonedx.py` provides a best-effort interop
  mapping; see the accuracy note in that module before relying on it for
  strict compliance.
- Checksums are sha256-only in v1.0.0.
- There is no built-in cryptographic signing of SBOM documents in
  v1.0.0 (no Sigstore/cosign integration); `document_hash()` gives you a
  stable content hash to sign with your own tooling (e.g.
  `cosign sign-blob`) as a pipeline step outside this project's scope.
- License enum coverage is intentionally curated (common OSS + common ML
  community licenses) rather than exhaustive (SPDX has hundreds); use
  `OTHER` + `license_note` for anything not listed, and open a PR to add
  genuinely common licenses.

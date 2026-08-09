# Example: Llama-3-8B fine-tune with a LoRA adapter

`build_example.py` builds a complete, realistic ModelSBOM for a typical
enterprise fine-tuning pipeline shape:

```
support-tickets-raw-export  (raw_collection)
        │  SOURCED_FROM
        ▼
support-tickets-filtered    (filtered)
        │  SOURCED_FROM
        ▼
support-tickets-clean-final (final_training_set, pii_reviewed=True)
        │  TRAINED_ON
        ▼
Llama-3-8B (base_model) ──DERIVED_FROM──▶ acme-support-triage-lora (adapter, LoRA r=16)
        │  MERGED_FROM                            │  MERGED_FROM
        └───────────────────┬────────────────────┘
                             ▼
        acme-support-triage-model-deploy (merged_model, int8 quantized)
```

Run it:

```bash
python examples/llama-finetune-lora/build_example.py
```

This writes three files into this directory:

- **`sbom.json`** — the native ModelSBOM document.
- **`sbom.mmd`** — a Mermaid lineage diagram (paste into a GitHub Markdown
  ` ```mermaid ` code fence to render it, or view it directly below).
- **`sbom.cdx.json`** — a CycloneDX-inspired export for interop with other
  SBOM tooling (see the accuracy note in
  `src/msbom/exporters/cyclonedx.py`).

Then explore it with the CLI:

```bash
msbom summary examples/llama-finetune-lora/sbom.json
msbom validate examples/llama-finetune-lora/sbom.json
msbom lineage examples/llama-finetune-lora/sbom.json --component <adapter-id>
```

(Get a component's ID from `msbom summary` output or by opening
`sbom.json` — IDs are regenerated with a random suffix each time the
script runs, so they aren't hardcoded here.)

## Lineage diagram

```mermaid
flowchart LR
    basemodel(["Llama-3-8B\nv3.0"])
    tokenizer{{"llama-3-tokenizer\nv3.0"}}
    raw[("support-tickets-raw-export\nv2026-05-01")]
    filtered[("support-tickets-filtered\nv2026-05-10")]
    clean[("support-tickets-clean-final\nv2026-06-01")]
    adapter[/"acme-support-triage-lora\nv3"/]
    merged[["acme-support-triage-model-deploy\nv3"]]

    basemodel -- INCLUDES --> tokenizer
    filtered -- SOURCED_FROM --> raw
    clean -- SOURCED_FROM --> filtered
    adapter -- DERIVED_FROM --> basemodel
    adapter -- TRAINED_ON --> clean
    merged -- MERGED_FROM --> basemodel
    merged -- MERGED_FROM --> adapter

    classDef baseModel fill:#dbeafe,stroke:#1d4ed8,color:#1e3a8a;
    classDef dataset fill:#dcfce7,stroke:#15803d,color:#14532d;
    classDef adapter fill:#fef3c7,stroke:#b45309,color:#78350f;
    classDef mergedModel fill:#ede9fe,stroke:#6d28d9,color:#4c1d95;
    classDef tokenizer fill:#fee2e2,stroke:#b91c1c,color:#7f1d1d;
    class basemodel baseModel;
    class tokenizer tokenizer;
    class raw dataset;
    class filtered dataset;
    class clean dataset;
    class adapter adapter;
    class merged mergedModel;
```

(This copy is hand-simplified with stable node names for the README; the
generated `sbom.mmd` uses the real component IDs.)

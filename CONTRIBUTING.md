# Contributing

## Development setup

```bash
git clone https://github.com/AshwinNHacker/model-sbom.git
cd model-sbom
pip install -e .
pip install -r requirements-dev.txt
pytest
ruff check src tests examples scripts
```

## Adding a new component type

1. Add the value to `ComponentType` in `src/msbom/models.py`.
2. Add a matching `add_<type>()` method to `SBOMBuilder` in
   `src/msbom/builder.py`, wiring up whatever relationships make sense by
   default (see `add_adapter()` for the pattern: it auto-creates
   `DERIVED_FROM` and `TRAINED_ON` edges from the IDs you pass in).
3. Add the new type to the `enum` in `schema/model-sbom.schema.json`
   (`definitions.component.properties.type.enum`).
4. Add a shape/color mapping in both
   `src/msbom/exporters/mermaid.py` and `graphviz_dot.py`, and a CycloneDX
   type mapping in `exporters/cyclonedx.py`.
5. Add validator hygiene checks if the new type has its own required
   relationships (see the `ADAPTER_MISSING_BASE_MODEL` check in
   `validator.py` as a template).
6. Update `docs/spec.md`'s component table and add tests in
   `tests/test_builder.py` / `tests/test_validator.py`.

## Adding a new relationship type

1. Add the value to `RelationshipType` in `models.py`.
2. Add it to the schema enum
   (`definitions.relationship.properties.type.enum`).
3. Document its meaning in the table in `docs/spec.md`.
4. If it should be auto-created by a builder method, wire that in.

## Adding a new license to the enum

`License` in `models.py` is intentionally curated, not exhaustive. Before
adding one, prefer using `OTHER` + a `license_note` unless the license is
genuinely common in ML model/dataset distribution (e.g. widely-used OSS
licenses, or a foundation model's own community license). Add it to both
`models.py::License` and the schema enum in the same PR — they must stay
in sync, and `tests/test_validator.py` / the schema-validation tests will
catch drift.

## Adding a new exporter

Create `src/msbom/exporters/<format>.py` with a `to_<format>(sbom: ModelSBOM) -> ...`
function, export it from `exporters/__init__.py`, wire a `--format` choice
into `cli.py::_cmd_export`, and add tests in `tests/test_exporters.py`.
If the target format has its own accuracy/compliance caveats (as
`cyclonedx.py` does), document them in the module docstring — don't
imply certification you can't back.

## Pull request checklist

- [ ] `pytest` passes locally
- [ ] `ruff check src tests examples scripts` passes
- [ ] `python examples/llama-finetune-lora/build_example.py` still runs
      cleanly (0 validation errors) if you touched the builder, validator,
      or models
- [ ] `CHANGELOG.md` updated
- [ ] `docs/spec.md` updated if you changed the schema/data model
- [ ] New fields/types/relationships have accompanying tests

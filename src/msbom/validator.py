"""
validator.py
=============
Two layers of validation:

1. **Structural/business-rule validation** (`validate()`) — always
   available, zero dependencies. Checks referential integrity (no
   dangling relationship endpoints), acyclic provenance graph, and
   supply-chain hygiene rules (missing checksums, UNKNOWN licenses,
   adapters with no base model, datasets marked as final training data
   with no PII review flag set, etc). Returns a `ValidationReport` of
   errors (block a release) and warnings (should be looked at).

2. **JSON Schema validation** (`validate_schema()`) — optional, requires
   the `jsonschema` package, validates the raw document dict against
   `schema/model-sbom.schema.json`. Skipped with a clear message if the
   dependency isn't installed, matching the graceful-degradation pattern
   used for optional guardrail adapters in the sibling
   prompt-injection-benchmark project.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .lineage import LineageGraph
from .models import ComponentType, License, ModelSBOM, RelationshipType

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCHEMA_PATH = REPO_ROOT / "schema" / "model-sbom.schema.json"


@dataclass
class ValidationIssue:
    severity: str          # "error" | "warning"
    code: str
    message: str
    component_id: str | None = None

    def __str__(self) -> str:
        loc = f" [{self.component_id}]" if self.component_id else ""
        return f"{self.severity.upper()} {self.code}{loc}: {self.message}"


@dataclass
class ValidationReport:
    issues: list[ValidationIssue] = field(default_factory=list)

    @property
    def errors(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.severity == "error"]

    @property
    def warnings(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.severity == "warning"]

    @property
    def is_valid(self) -> bool:
        return len(self.errors) == 0

    def add(self, severity: str, code: str, message: str, component_id: str | None = None) -> None:
        self.issues.append(ValidationIssue(severity, code, message, component_id))

    def __str__(self) -> str:
        if not self.issues:
            return "No issues found."
        return "\n".join(str(i) for i in self.issues)


def validate(sbom: ModelSBOM) -> ValidationReport:
    report = ValidationReport()
    graph = LineageGraph(sbom)

    # -- referential integrity ------------------------------------------
    for rel in graph.dangling_references():
        report.add(
            "error", "DANGLING_REFERENCE",
            f"Relationship {rel.source_id} -{rel.type.value}-> {rel.target_id} "
            f"references a component ID not present in this document.",
        )

    # -- duplicate component IDs -----------------------------------------
    seen_ids: set[str] = set()
    for c in sbom.components:
        if c.id in seen_ids:
            report.add("error", "DUPLICATE_ID", f"Component ID '{c.id}' appears more than once.", c.id)
        seen_ids.add(c.id)

    # -- cycles -----------------------------------------------------------
    cycles = graph.find_cycles()
    for cycle in cycles:
        report.add(
            "error", "PROVENANCE_CYCLE",
            f"Circular provenance detected: {' -> '.join(cycle)}. "
            f"A component cannot be (transitively) derived from itself.",
        )

    # -- per-component hygiene checks --------------------------------------
    for c in sbom.components:
        if c.license == License.UNKNOWN:
            report.add(
                "warning", "UNKNOWN_LICENSE",
                f"Component '{c.name}' ({c.type.value}) has no license recorded. "
                f"Downstream consumers cannot assess redistribution rights.",
                c.id,
            )
        if c.checksum is None:
            report.add(
                "warning", "MISSING_CHECKSUM",
                f"Component '{c.name}' ({c.type.value}) has no checksum recorded, "
                f"so its integrity cannot be verified against the artifact on disk.",
                c.id,
            )
        if not c.external_refs:
            report.add(
                "warning", "MISSING_SOURCE_REF",
                f"Component '{c.name}' ({c.type.value}) has no external reference "
                f"(registry URL, dataset URI, etc.) recording where it actually lives.",
                c.id,
            )

        if c.type == ComponentType.ADAPTER:
            outgoing = graph.direct_dependencies(c.id)
            has_base = any(r.type == RelationshipType.DERIVED_FROM for r in outgoing)
            has_training_data = any(r.type == RelationshipType.TRAINED_ON for r in outgoing)
            if not has_base:
                report.add(
                    "error", "ADAPTER_MISSING_BASE_MODEL",
                    f"Adapter '{c.name}' has no DERIVED_FROM relationship to a base model. "
                    f"Adapter provenance is incomplete without knowing what it was trained on top of.",
                    c.id,
                )
            if not has_training_data:
                report.add(
                    "warning", "ADAPTER_MISSING_TRAINING_DATA",
                    f"Adapter '{c.name}' has no TRAINED_ON relationship to any dataset. "
                    f"Fine-tuning data lineage cannot be established for this adapter.",
                    c.id,
                )

        if c.type == ComponentType.DATASET:
            stage = c.properties.get("lineage_stage")
            pii_reviewed = c.properties.get("pii_reviewed")
            if stage == "final_training_set" and pii_reviewed is None:
                report.add(
                    "warning", "PII_REVIEW_UNSET",
                    f"Dataset '{c.name}' is marked as a final training set but "
                    f"`pii_reviewed` is not set (True/False). Record an explicit "
                    f"determination rather than leaving it implicit.",
                    c.id,
                )

    return report


def validate_schema(sbom_dict: dict, schema_path: str | Path | None = None) -> ValidationReport:
    """
    Validate the raw SBOM dict against the JSON Schema. Requires the
    optional `jsonschema` package; returns a report with a single
    informational warning (not an error) if it isn't installed, so callers
    can still rely on `validate()` for CI gating without the extra
    dependency.
    """
    report = ValidationReport()
    try:
        import jsonschema
    except ImportError:
        report.add(
            "warning", "JSONSCHEMA_UNAVAILABLE",
            "The 'jsonschema' package is not installed; skipped full JSON Schema "
            "validation. Install with `pip install jsonschema` or "
            "`pip install -e .[schema]` to enable it. Structural validate() "
            "checks still ran.",
        )
        return report

    import json
    schema_file = Path(schema_path) if schema_path else SCHEMA_PATH
    with open(schema_file, encoding="utf-8") as f:
        schema = json.load(f)

    validator_cls = jsonschema.validators.validator_for(schema)
    validator_cls.check_schema(schema)
    v = validator_cls(schema)
    for error in sorted(v.iter_errors(sbom_dict), key=lambda e: list(e.path)):
        loc = "/".join(str(p) for p in error.path) or "<root>"
        report.add("error", "SCHEMA_VIOLATION", f"{loc}: {error.message}")

    return report

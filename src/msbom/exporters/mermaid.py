"""
mermaid.py
==========
Renders a ModelSBOM's provenance graph as a Mermaid flowchart, which
GitHub renders natively inside Markdown code fences (```mermaid). Useful
for embedding a lineage diagram directly in a README or PR description.
"""
from __future__ import annotations

from ..models import ComponentType, ModelSBOM

_SHAPE_BY_TYPE = {
    ComponentType.BASE_MODEL: ("([", "])"),      # stadium
    ComponentType.DATASET: ("[(", ")]"),          # cylinder
    ComponentType.ADAPTER: ("[/", "/]"),           # parallelogram
    ComponentType.MERGED_MODEL: ("[[", "]]"),     # subroutine
    ComponentType.TOKENIZER: ("{{", "}}"),         # hexagon
}

_STYLE_CLASS_BY_TYPE = {
    ComponentType.BASE_MODEL: "baseModel",
    ComponentType.DATASET: "dataset",
    ComponentType.ADAPTER: "adapter",
    ComponentType.MERGED_MODEL: "mergedModel",
    ComponentType.TOKENIZER: "tokenizer",
}

_CLASS_DEFS = """
    classDef baseModel fill:#dbeafe,stroke:#1d4ed8,color:#1e3a8a;
    classDef dataset fill:#dcfce7,stroke:#15803d,color:#14532d;
    classDef adapter fill:#fef3c7,stroke:#b45309,color:#78350f;
    classDef mergedModel fill:#ede9fe,stroke:#6d28d9,color:#4c1d95;
    classDef tokenizer fill:#fee2e2,stroke:#b91c1c,color:#7f1d1d;
""".strip("\n")


def _safe_id(component_id: str) -> str:
    return component_id.replace("-", "_")


def _label(name: str, version: str) -> str:
    escaped = name.replace('"', "'")
    return f'"{escaped}\\nv{version}"'


def to_mermaid(sbom: ModelSBOM, direction: str = "TD") -> str:
    """
    direction: mermaid flowchart direction, e.g. "TD" (top-down) or "LR"
    (left-right, often more readable for wide/shallow lineage graphs).
    """
    lines = [f"flowchart {direction}"]

    for comp in sbom.components:
        node_id = _safe_id(comp.id)
        open_shape, close_shape = _SHAPE_BY_TYPE.get(comp.type, ("[", "]"))
        label = _label(comp.name, comp.version)
        lines.append(f"    {node_id}{open_shape}{label}{close_shape}")

    for rel in sbom.relationships:
        src, tgt = _safe_id(rel.source_id), _safe_id(rel.target_id)
        lines.append(f"    {src} -- {rel.type.value} --> {tgt}")

    lines.append("")
    for comp in sbom.components:
        css_class = _STYLE_CLASS_BY_TYPE.get(comp.type)
        if css_class:
            lines.append(f"    class {_safe_id(comp.id)} {css_class};")

    lines.append(_CLASS_DEFS)
    return "\n".join(lines)

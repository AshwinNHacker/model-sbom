"""
graphviz_dot.py
================
Renders a ModelSBOM's provenance graph as Graphviz DOT, for teams that
prefer `dot -Tpng` / `dot -Tsvg` pipelines over Mermaid (e.g. for
generating a static image to attach to a compliance document).
"""
from __future__ import annotations

from ..models import ComponentType, ModelSBOM

_COLOR_BY_TYPE = {
    ComponentType.BASE_MODEL: "#1d4ed8",
    ComponentType.DATASET: "#15803d",
    ComponentType.ADAPTER: "#b45309",
    ComponentType.MERGED_MODEL: "#6d28d9",
    ComponentType.TOKENIZER: "#b91c1c",
}

_SHAPE_BY_TYPE = {
    ComponentType.BASE_MODEL: "box3d",
    ComponentType.DATASET: "cylinder",
    ComponentType.ADAPTER: "parallelogram",
    ComponentType.MERGED_MODEL: "component",
    ComponentType.TOKENIZER: "hexagon",
}


def _escape(s: str) -> str:
    return s.replace('"', '\\"')


def to_dot(sbom: ModelSBOM, rankdir: str = "TB") -> str:
    lines = [
        "digraph ModelSBOM {",
        f'    rankdir="{rankdir}";',
        '    node [fontname="Helvetica", style=filled, fillcolor=white];',
        '    edge [fontname="Helvetica", fontsize=10];',
        "",
    ]

    for comp in sbom.components:
        color = _COLOR_BY_TYPE.get(comp.type, "#374151")
        shape = _SHAPE_BY_TYPE.get(comp.type, "box")
        label = f"{_escape(comp.name)}\\nv{_escape(comp.version)}\\n({comp.type.value})"
        lines.append(
            f'    "{comp.id}" [label="{label}", shape={shape}, color="{color}"];'
        )

    lines.append("")
    for rel in sbom.relationships:
        lines.append(
            f'    "{rel.source_id}" -> "{rel.target_id}" [label="{rel.type.value}"];'
        )

    lines.append("}")
    return "\n".join(lines)

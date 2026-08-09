"""
diff.py
=======
Compares two ModelSBOM documents (e.g. two versions of the same pipeline's
output, or "before" vs "after" a retraining run) and reports what changed:
components added/removed, components whose fields changed (including
checksum changes — the most security-relevant kind of change), and
relationships added/removed.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .models import Component, ModelSBOM, Relationship


@dataclass
class ComponentChange:
    component_id: str
    name: str
    changed_fields: dict[str, tuple]  # field_name -> (old_value, new_value)

    @property
    def checksum_changed(self) -> bool:
        return "checksum" in self.changed_fields


@dataclass
class SBOMDiff:
    added_components: list[Component] = field(default_factory=list)
    removed_components: list[Component] = field(default_factory=list)
    changed_components: list[ComponentChange] = field(default_factory=list)
    added_relationships: list[Relationship] = field(default_factory=list)
    removed_relationships: list[Relationship] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(
            self.added_components or self.removed_components or self.changed_components
            or self.added_relationships or self.removed_relationships
        )

    @property
    def has_checksum_changes(self) -> bool:
        return any(c.checksum_changed for c in self.changed_components)

    def summary(self) -> str:
        lines = []
        lines.append(f"+{len(self.added_components)} components added")
        lines.append(f"-{len(self.removed_components)} components removed")
        lines.append(f"~{len(self.changed_components)} components changed")
        lines.append(f"+{len(self.added_relationships)} relationships added")
        lines.append(f"-{len(self.removed_relationships)} relationships removed")
        if self.has_checksum_changes:
            changed_names = [c.name for c in self.changed_components if c.checksum_changed]
            lines.append(f"⚠ checksum changed for: {', '.join(changed_names)}")
        return "\n".join(lines)


_COMPARABLE_FIELDS = [
    "name", "version", "supplier", "license", "license_note", "notes",
]


def _relationship_key(r: Relationship) -> tuple:
    return (r.source_id, r.target_id, r.type.value)


def diff_sboms(old: ModelSBOM, new: ModelSBOM) -> SBOMDiff:
    result = SBOMDiff()

    old_by_id = {c.id: c for c in old.components}
    new_by_id = {c.id: c for c in new.components}

    for cid, comp in new_by_id.items():
        if cid not in old_by_id:
            result.added_components.append(comp)

    for cid, comp in old_by_id.items():
        if cid not in new_by_id:
            result.removed_components.append(comp)

    for cid in set(old_by_id) & set(new_by_id):
        old_c, new_c = old_by_id[cid], new_by_id[cid]
        changed: dict[str, tuple] = {}

        for field_name in _COMPARABLE_FIELDS:
            old_val = getattr(old_c, field_name)
            new_val = getattr(new_c, field_name)
            if old_val != new_val:
                changed[field_name] = (old_val, new_val)

        old_checksum = old_c.checksum.value if old_c.checksum else None
        new_checksum = new_c.checksum.value if new_c.checksum else None
        if old_checksum != new_checksum:
            changed["checksum"] = (old_checksum, new_checksum)

        if old_c.properties != new_c.properties:
            changed["properties"] = (old_c.properties, new_c.properties)

        if changed:
            result.changed_components.append(ComponentChange(cid, new_c.name, changed))

    old_rel_keys = {_relationship_key(r): r for r in old.relationships}
    new_rel_keys = {_relationship_key(r): r for r in new.relationships}

    for key, rel in new_rel_keys.items():
        if key not in old_rel_keys:
            result.added_relationships.append(rel)
    for key, rel in old_rel_keys.items():
        if key not in new_rel_keys:
            result.removed_relationships.append(rel)

    return result

"""
lineage.py
==========
Treats `ModelSBOM.relationships` as a directed graph (edge: source
DERIVED_FROM/TRAINED_ON/etc. -> target) and provides traversal utilities:

  - ancestors(component_id): everything this component was (transitively)
    built from — e.g. for an adapter: its base model, and every dataset
    that fed it or any upstream base model.
  - descendants(component_id): everything (transitively) built from this
    component — e.g. for a dataset: every adapter/model trained on it.
  - find_cycles(): supply-chain graphs must be acyclic; a cycle indicates
    a data-entry error (or a genuinely worrying circular-provenance claim)
    and validator.py treats it as an error.
  - path(a, b): a concrete chain of relationships connecting two
    components, if one exists, for human-readable provenance explanations.
"""
from __future__ import annotations

from collections import deque

from .models import ModelSBOM, Relationship


class LineageGraph:
    def __init__(self, sbom: ModelSBOM):
        self.sbom = sbom
        # outgoing[x] = edges leaving x (x -> y meaning "x derived from y")
        self.outgoing: dict[str, list[Relationship]] = {}
        # incoming[y] = edges arriving at y
        self.incoming: dict[str, list[Relationship]] = {}
        for rel in sbom.relationships:
            self.outgoing.setdefault(rel.source_id, []).append(rel)
            self.incoming.setdefault(rel.target_id, []).append(rel)

    def ancestors(self, component_id: str) -> set[str]:
        """Every component (transitively) reachable by following edges forward
        (source -> target), i.e. everything `component_id` was built from."""
        seen: set[str] = set()
        queue = deque([component_id])
        while queue:
            current = queue.popleft()
            for rel in self.outgoing.get(current, []):
                if rel.target_id not in seen:
                    seen.add(rel.target_id)
                    queue.append(rel.target_id)
        return seen

    def descendants(self, component_id: str) -> set[str]:
        """Every component (transitively) that depends on `component_id`."""
        seen: set[str] = set()
        queue = deque([component_id])
        while queue:
            current = queue.popleft()
            for rel in self.incoming.get(current, []):
                if rel.source_id not in seen:
                    seen.add(rel.source_id)
                    queue.append(rel.source_id)
        return seen

    def direct_dependencies(self, component_id: str) -> list[Relationship]:
        return list(self.outgoing.get(component_id, []))

    def direct_dependents(self, component_id: str) -> list[Relationship]:
        return list(self.incoming.get(component_id, []))

    def find_cycles(self) -> list[list[str]]:
        """Return a list of cycles (each a list of component IDs), if any exist."""
        WHITE, GRAY, BLACK = 0, 1, 2
        color = {c.id: WHITE for c in self.sbom.components}
        cycles: list[list[str]] = []
        stack_path: list[str] = []

        def visit(node: str) -> None:
            color[node] = GRAY
            stack_path.append(node)
            for rel in self.outgoing.get(node, []):
                nxt = rel.target_id
                if color.get(nxt, WHITE) == GRAY:
                    cycle_start = stack_path.index(nxt)
                    cycles.append(stack_path[cycle_start:] + [nxt])
                elif color.get(nxt, WHITE) == WHITE:
                    visit(nxt)
            stack_path.pop()
            color[node] = BLACK

        for comp in self.sbom.components:
            if color[comp.id] == WHITE:
                visit(comp.id)
        return cycles

    def path(self, source_id: str, target_id: str) -> list[Relationship] | None:
        """BFS shortest chain of relationships from source to target (forward edges only)."""
        if source_id == target_id:
            return []
        visited = {source_id}
        queue = deque([(source_id, [])])
        while queue:
            node, path_so_far = queue.popleft()
            for rel in self.outgoing.get(node, []):
                if rel.target_id == target_id:
                    return path_so_far + [rel]
                if rel.target_id not in visited:
                    visited.add(rel.target_id)
                    queue.append((rel.target_id, path_so_far + [rel]))
        return None

    def dangling_references(self) -> list[Relationship]:
        """Relationships pointing to component IDs that don't exist in the document."""
        ids = self.sbom.component_ids()
        return [r for r in self.sbom.relationships if r.source_id not in ids or r.target_id not in ids]

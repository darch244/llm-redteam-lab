"""Attack Knowledge Graph (AKG) models.

Represents attack primitives, techniques, required target capabilities,
defenses, and bypass relationships as a semantic reasoning graph.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class KnowledgeNodeType(StrEnum):
    """Semantic category of a node in the attack knowledge graph."""

    ATTACK_FAMILY = "attack_family"
    TECHNIQUE = "technique"
    PRIMITIVE = "primitive"
    CAPABILITY = "capability"
    DEFENSE = "defense"
    BYPASS_STRATEGY = "bypass_strategy"
    CONFIRMATION_STRATEGY = "confirmation_strategy"


class KnowledgeEdgeType(StrEnum):
    """Semantic relationship linking knowledge concepts."""

    REQUIRES = "requires"
    ENABLES = "enables"
    BLOCKS = "blocks"
    BYPASSES = "bypasses"
    COMPOSES_WITH = "composes_with"
    CONFIRMED_BY = "confirmed_by"
    CORRELATES_WITH = "correlates_with"


class KnowledgeNode(BaseModel):
    """A semantic concept within the attack knowledge graph."""

    id: str
    node_type: KnowledgeNodeType
    name: str
    description: str = ""
    atlas_id: str | None = None
    properties: dict[str, Any] = Field(default_factory=dict)


class KnowledgeEdge(BaseModel):
    """A typed relationship connecting two concepts in the AKG."""

    source_id: str
    target_id: str
    edge_type: KnowledgeEdgeType
    weight: float = 1.0
    rationale: str = ""


class AttackKnowledgeGraph(BaseModel):
    """Semantic graph enabling path-based reasoning about attack opportunities."""

    nodes: dict[str, KnowledgeNode] = Field(default_factory=dict)
    edges: list[KnowledgeEdge] = Field(default_factory=list)

    def add_node(
        self,
        node_id: str,
        node_type: KnowledgeNodeType,
        name: str,
        description: str = "",
        atlas_id: str | None = None,
        properties: dict[str, Any] | None = None,
    ) -> KnowledgeNode:
        node = KnowledgeNode(
            id=node_id,
            node_type=node_type,
            name=name,
            description=description,
            atlas_id=atlas_id,
            properties=properties or {},
        )
        self.nodes[node_id] = node
        return node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: KnowledgeEdgeType,
        weight: float = 1.0,
        rationale: str = "",
    ) -> KnowledgeEdge:
        if source_id not in self.nodes:
            raise ValueError(f"Source node '{source_id}' does not exist")
        if target_id not in self.nodes:
            raise ValueError(f"Target node '{target_id}' does not exist")

        edge = KnowledgeEdge(
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            weight=weight,
            rationale=rationale,
        )
        self.edges.append(edge)
        return edge

    def get_prerequisites(self, concept_id: str) -> list[KnowledgeNode]:
        """Get capabilities or primitives required by this attack concept."""
        req_ids = [
            e.target_id for e in self.edges if e.source_id == concept_id and e.edge_type == KnowledgeEdgeType.REQUIRES
        ]
        return [self.nodes[rid] for rid in req_ids if rid in self.nodes]

    def get_bypasses_for_defense(self, defense_id: str) -> list[KnowledgeNode]:
        """Find attack techniques or strategies known to bypass a specific defense."""
        bypass_ids = [
            e.source_id for e in self.edges if e.target_id == defense_id and e.edge_type == KnowledgeEdgeType.BYPASSES
        ]
        return [self.nodes[bid] for bid in bypass_ids if bid in self.nodes]

    def get_compositions(self, primitive_id: str) -> list[KnowledgeNode]:
        """Find compatible primitives that compose with the specified primitive."""
        comp_ids = [
            e.target_id
            for e in self.edges
            if e.source_id == primitive_id and e.edge_type == KnowledgeEdgeType.COMPOSES_WITH
        ]
        return [self.nodes[cid] for cid in comp_ids if cid in self.nodes]


__all__ = [
    "AttackKnowledgeGraph",
    "KnowledgeEdge",
    "KnowledgeEdgeType",
    "KnowledgeNode",
    "KnowledgeNodeType",
]

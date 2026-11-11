"""First-class evidence graph model supporting cryptographic lineage and traceability.

Implements an append-only Directed Acyclic Graph (DAG) connecting:
Target -> Campaign -> Attack -> Attempt -> Response -> Observation -> Evidence ->
Judge -> Confirmation -> Finding -> Follow-up.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(UTC)


class NodeType(StrEnum):
    """Semantic category of an entity in the evidence graph."""

    TARGET = "target"
    CAMPAIGN = "campaign"
    ATTACK = "attack"
    ATTEMPT = "attempt"
    RESPONSE = "response"
    OBSERVATION = "observation"
    EVIDENCE = "evidence"
    JUDGE_DECISION = "judge_decision"
    CONFIRMATION = "confirmation"
    FINDING = "finding"
    FOLLOW_UP = "follow_up"


class EdgeType(StrEnum):
    """Causal or evidentiary relationship between nodes."""

    TARGETS = "targets"
    EXECUTES = "executes"
    PRODUCES = "produces"
    OBSERVES = "observes"
    YIELDS_EVIDENCE = "yields_evidence"
    EVALUATES = "evaluates"
    CONFIRMS = "confirms"
    DISPROVES = "disproves"
    GENERATES_FINDING = "generates_finding"
    TRIGGERS_FOLLOW_UP = "triggers_follow_up"
    CORROBORATES = "corroborates"
    CONTRADICTS = "contradicts"


class EvidenceNode(BaseModel):
    """Immutable node within the evidence DAG."""

    id: str
    node_type: NodeType
    payload: dict[str, Any] = Field(default_factory=dict)
    parent_ids: list[str] = Field(default_factory=list)
    sha256: str
    timestamp: datetime = Field(default_factory=_utcnow)


class EvidenceEdge(BaseModel):
    """Directed edge encoding causal relationship."""

    source_id: str
    target_id: str
    edge_type: EdgeType
    metadata: dict[str, Any] = Field(default_factory=dict)


def compute_node_hash(node_type: NodeType | str, payload: dict[str, Any], parent_ids: list[str]) -> str:
    """Compute deterministic cryptographic SHA-256 for a node and its lineage."""
    hasher = hashlib.sha256()
    type_str = node_type.value if hasattr(node_type, "value") else str(node_type)
    hasher.update(type_str.encode())
    payload_str = json.dumps(payload, sort_keys=True, default=str)
    hasher.update(payload_str.encode())
    for pid in sorted(parent_ids):
        hasher.update(pid.encode())
    return hasher.hexdigest()


class EvidenceGraph(BaseModel):
    """Append-only evidence DAG with full causal lineage and tamper verification."""

    nodes: dict[str, EvidenceNode] = Field(default_factory=dict)
    edges: list[EvidenceEdge] = Field(default_factory=list)

    def add_node(
        self,
        node_type: NodeType | str,
        payload: dict[str, Any],
        parent_ids: list[str] | None = None,
        edge_type: EdgeType | None = None,
        edge_metadata: dict[str, Any] | None = None,
        custom_id: str | None = None,
    ) -> EvidenceNode:
        """Add a new verified node and connect it to its parents."""
        nt = NodeType(node_type) if not isinstance(node_type, NodeType) else node_type
        parents = list(parent_ids or [])
        # Verify parents exist
        for pid in parents:
            if pid not in self.nodes:
                raise ValueError(f"Parent node '{pid}' does not exist in graph")

        sha256 = compute_node_hash(nt, payload, parents)
        node_id = custom_id or f"{nt.value[:3]}-{sha256[:12]}"

        # Prevent duplicate insertion collisions
        if node_id in self.nodes:
            existing = self.nodes[node_id]
            if existing.sha256 == sha256:
                return existing
            node_id = f"{node_id}-{len(self.nodes)}"

        node = EvidenceNode(
            id=node_id,
            node_type=nt,
            payload=payload,
            parent_ids=parents,
            sha256=sha256,
        )
        self.nodes[node.id] = node

        if edge_type and parents:
            for pid in parents:
                self.edges.append(
                    EvidenceEdge(
                        source_id=pid,
                        target_id=node.id,
                        edge_type=edge_type,
                        metadata=edge_metadata or {},
                    )
                )

        return node

    def get_lineage(self, node_id: str) -> list[EvidenceNode]:
        """Compute the full ancestor causal path for a given node back to root."""
        if node_id not in self.nodes:
            raise KeyError(f"Node '{node_id}' not found in evidence graph")

        visited: set[str] = set()
        lineage: list[EvidenceNode] = []
        queue = [node_id]

        while queue:
            current_id = queue.pop(0)
            if current_id in visited:
                continue
            visited.add(current_id)
            node = self.nodes.get(current_id)
            if node:
                lineage.append(node)
                queue.extend(node.parent_ids)

        return sorted(lineage, key=lambda n: n.timestamp)

    def get_children(self, node_id: str) -> list[EvidenceNode]:
        """Return all direct child nodes connected from node_id."""
        child_ids = [e.target_id for e in self.edges if e.source_id == node_id]
        return [self.nodes[cid] for cid in child_ids if cid in self.nodes]

    def verify_integrity(self) -> tuple[bool, str]:
        """Verify the cryptographic hash integrity of the entire evidence graph."""
        for nid, node in self.nodes.items():
            expected_hash = compute_node_hash(node.node_type, node.payload, node.parent_ids)
            if node.sha256 != expected_hash:
                return False, f"Hash mismatch on node '{nid}': expected {expected_hash}, got {node.sha256}"
        return True, "Evidence graph integrity verified: all node hashes valid"

    def to_dot(self) -> str:
        """Render evidence graph in Graphviz DOT format for visual auditing."""
        lines = ["digraph EvidenceGraph {", '  rankdir="TB";', '  node [shape=box, style=rounded, fontname="Arial"];']
        for nid, node in self.nodes.items():
            color = "#4a90e2"
            if node.node_type == NodeType.FINDING:
                color = "#d9534f"
            elif node.node_type == NodeType.CONFIRMATION:
                color = "#5cb85c" if node.payload.get("status") == "confirmed" else "#f0ad4e"
            label = f"{node.node_type.value}\\n{nid}\\nsha:{node.sha256[:8]}"
            lines.append(f'  "{nid}" [label="{label}", color="{color}"];')
        for edge in self.edges:
            lines.append(f'  "{edge.source_id}" -> "{edge.target_id}" [label="{edge.edge_type.value}"];')
        lines.append("}")
        return "\n".join(lines)


__all__ = [
    "EdgeType",
    "EvidenceEdge",
    "EvidenceGraph",
    "EvidenceNode",
    "NodeType",
    "compute_node_hash",
]

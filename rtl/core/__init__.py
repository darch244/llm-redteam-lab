"""Core architectural models: Evidence Graph and Confirmation Engine."""

from rtl.core.confirmation import (
    ConfirmationEngine,
    ConfirmationResult,
    ConfirmationStatus,
)
from rtl.core.evidence_graph import (
    EdgeType,
    EvidenceEdge,
    EvidenceGraph,
    EvidenceNode,
    NodeType,
    compute_node_hash,
)

__all__ = [
    "ConfirmationEngine",
    "ConfirmationResult",
    "ConfirmationStatus",
    "EdgeType",
    "EvidenceEdge",
    "EvidenceGraph",
    "EvidenceNode",
    "NodeType",
    "compute_node_hash",
]

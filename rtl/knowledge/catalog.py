"""Default Attack Knowledge Graph populated with MITRE ATLAS mappings and attack semantics."""

from __future__ import annotations

from functools import lru_cache

from rtl.evaluation.atlas import ATLAS_MAP
from rtl.knowledge.models import (
    AttackKnowledgeGraph,
    KnowledgeEdgeType,
    KnowledgeNodeType,
)
from rtl.profiler.models import CapabilityName


@lru_cache(maxsize=1)
def get_default_knowledge_graph() -> AttackKnowledgeGraph:
    """Build and return the cached default Attack Knowledge Graph."""
    akg = AttackKnowledgeGraph()

    # 1. Register Capabilities
    for cap in CapabilityName:
        akg.add_node(
            node_id=f"cap:{cap.value}",
            node_type=KnowledgeNodeType.CAPABILITY,
            name=cap.value.replace("_", " ").title(),
            description=f"Target capability: {cap.value}",
        )

    # 2. Register Common Defenses
    akg.add_node(
        node_id="def:keyword_refusal",
        node_type=KnowledgeNodeType.DEFENSE,
        name="Keyword Refusal Guardrail",
        description="Simple pattern or keyword matching refusing restricted strings",
    )
    akg.add_node(
        node_id="def:system_prompt_guard",
        node_type=KnowledgeNodeType.DEFENSE,
        name="System Prompt Confidentiality Rule",
        description="Instruction directing model never to disclose its system prompt",
    )
    akg.add_node(
        node_id="def:tool_execution_boundary",
        node_type=KnowledgeNodeType.DEFENSE,
        name="Tool Parameter Sandbox / Scope Limit",
        description="Validation schema restricting tool input parameters",
    )

    # 3. Register Core Attack Families (aligned with ATLAS)
    families = [
        ("fam:direct_injection", "Direct Prompt Injection", "AML.T0051.000"),
        ("fam:indirect_injection", "Indirect Prompt Injection", "AML.T0051.001"),
        ("fam:jailbreak", "Jailbreak / Roleplay Bypass", "AML.T0054"),
        ("fam:system_prompt_extraction", "System Prompt Extraction", "AML.T0056"),
        ("fam:data_exfiltration", "Data Exfiltration via Ingestion/Tools", "AML.T0057"),
    ]
    for fid, fname, atlas_id in families:
        atlas_info = ATLAS_MAP.get(atlas_id, {})
        akg.add_node(
            node_id=fid,
            node_type=KnowledgeNodeType.ATTACK_FAMILY,
            name=fname,
            description=atlas_info.get("name", fname),
            atlas_id=atlas_id,
        )

    # 4. Register Primitives & Bypass Strategies
    akg.add_node(
        node_id="prim:roleplay_hypothetical",
        node_type=KnowledgeNodeType.PRIMITIVE,
        name="Hypothetical / Fiction Framing",
        description="Encapsulates forbidden query inside fictional or security-research context",
    )
    akg.add_node(
        node_id="prim:authority_spoofing",
        node_type=KnowledgeNodeType.PRIMITIVE,
        name="System / Developer Override Spoofing",
        description="Claims developer, admin, or debug authority to supersede system instructions",
    )
    akg.add_node(
        node_id="prim:encoding_obfuscation",
        node_type=KnowledgeNodeType.PRIMITIVE,
        name="Base64 / ROT13 / Cipher Encoding",
        description="Encodes trigger words to bypass shallow string-level filters",
    )
    akg.add_node(
        node_id="prim:delimiter_collision",
        node_type=KnowledgeNodeType.PRIMITIVE,
        name="Delimiter / Structured Marker Injection",
        description="Uses XML or markdown tags (<system>, </user>) to escape prompt boundaries",
    )

    # 5. Connect Relationships (Edges)
    # Indirect injection requires retrieval or browsing capabilities
    akg.add_edge(
        "fam:indirect_injection",
        f"cap:{CapabilityName.RETRIEVAL.value}",
        KnowledgeEdgeType.REQUIRES,
        rationale="Indirect injection requires a retrieval channel to ingest untrusted data",
    )
    akg.add_edge(
        "fam:indirect_injection",
        f"cap:{CapabilityName.BROWSER_ACCESS.value}",
        KnowledgeEdgeType.REQUIRES,
        rationale="Agentic web injection requires browser fetching capabilities",
    )

    # Data exfiltration through tools requires tool access
    akg.add_edge(
        "fam:data_exfiltration",
        f"cap:{CapabilityName.TOOL_ACCESS.value}",
        KnowledgeEdgeType.REQUIRES,
        rationale="Exfiltration via tool execution requires tool calling capabilities",
    )

    # Bypasses
    akg.add_edge(
        "prim:roleplay_hypothetical",
        "def:keyword_refusal",
        KnowledgeEdgeType.BYPASSES,
        weight=0.75,
        rationale="Hypothetical framing frequently circumvents keyword decline filters",
    )
    akg.add_edge(
        "prim:encoding_obfuscation",
        "def:keyword_refusal",
        KnowledgeEdgeType.BYPASSES,
        weight=0.85,
        rationale="Cipher/Base64 encoding evades static keyword detection",
    )
    akg.add_edge(
        "prim:authority_spoofing",
        "def:system_prompt_guard",
        KnowledgeEdgeType.BYPASSES,
        weight=0.65,
        rationale="Fake admin commands test instruction hierarchy priority",
    )

    # Compositions
    akg.add_edge(
        "prim:roleplay_hypothetical",
        "prim:delimiter_collision",
        KnowledgeEdgeType.COMPOSES_WITH,
        rationale="Fictional framing composes naturally with structured delimiter formatting",
    )
    akg.add_edge(
        "prim:authority_spoofing",
        "prim:encoding_obfuscation",
        KnowledgeEdgeType.COMPOSES_WITH,
        rationale="Admin overrides can be obfuscated to bypass both guardrails and log filters",
    )

    return akg


__all__ = ["get_default_knowledge_graph"]

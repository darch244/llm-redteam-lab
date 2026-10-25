# MITRE ATLAS Mapping

Every finding produced by this lab is tagged with a MITRE ATLAS technique ID.
Technique names below follow the ATLAS registry (v5.x) as mirrored in
`rtl/evaluation/atlas.py`; the registry is the single source of truth used for
severity scoring, the ATLAS crosswalk in reports, and ID validation.

## Techniques emitted by single-shot probes (110 probes)

| ATLAS ID | Technique | Tactic | Probe category | Probes |
|----------|-----------|--------|----------------|-------:|
| `AML.T0051.000` | Direct Prompt Injection | Execution | `direct_injection` | 22 |
| `AML.T0051.001` | Indirect Prompt Injection | Execution | `indirect_injection` | 21 |
| `AML.T0054` | LLM Jailbreak | Defense Evasion | `jailbreak` | 22 |
| `AML.T0056` | **Extract LLM System Prompt** | Exfiltration | `system_prompt_extraction` | 25 |
| `AML.T0057` | LLM Data Leakage | Exfiltration | `data_exfiltration` | 16 |
| `AML.T0086` | Exfiltration via AI Agent Tool Invocation | Exfiltration | `data_exfiltration` (tool/DB) | 4 |

> Note: ATLAS renamed the system-prompt technique to **Extract LLM System
> Prompt** (`AML.T0056`). Older write-ups sometimes call it "LLM Meta Prompt
> Extraction"; this lab uses the current name.

## Techniques emitted by multi-step scenarios

| Scenario | ATLAS IDs |
|----------|-----------|
| `agent_browsing` | `AML.T0051.001`, `AML.T0051.002` (Triggered Prompt Injection), `AML.T0054` |
| `rag_poisoning` | `AML.T0070` (RAG Poisoning), `AML.T0051.001` |
| `multimodal` | `AML.T0051.001`, `AML.T0043` (Craft Adversarial Data) |

## Registry-only IDs (defined for reference / future probes)

These are present in `ATLAS_MAP` so the registry is complete and IDs validate,
but no current probe or scenario emits them:

- `AML.T0024` — Exfiltration via AI Inference API
- `AML.T0024.000` — Infer Training Data Membership
- `AML.T0080` — AI Agent Context Poisoning
- `AML.T0110` — AI Agent Tool Poisoning
- `AML.T0051` — LLM Prompt Injection (parent of the `.000/.001/.002` sub-techniques)

## Adding a probe

1. Tag the probe with an `atlas` ID that exists in `rtl/evaluation/atlas.py`.
2. If the ID is new, add its metadata row to `ATLAS_MAP` and, where it belongs
   to a category, to `CATEGORY_TO_ATLAS`.
3. Keep the mapping semantically honest — map to the technique the probe
   actually measures, not the nearest familiar one. Tests assert that every
   probe's ID is valid and included in its category's technique list.

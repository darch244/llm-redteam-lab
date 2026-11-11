MISSION: Design the next milestone for a production-minded Adaptive AI Red
Teaming Engine in the existing llm-redteam-lab repository.

THIS PHASE IS DESIGN AND AUDIT ONLY. DO NOT IMPLEMENT THE ENGINE YET.

PRESERVATION RULES:
- Preserve all existing tracked and untracked files and modifications.
- Never commit, push, merge, reset, clean, or rewrite Git history.
- Do not overwrite existing roadmap or milestone documents.
- Inspect the actual repository before proposing architecture.
- Do not claim features exist unless verified in source code and tests.

OBJECTIVE:
Move beyond static probes and simple keyword-based follow-ups toward a
bounded, evidence-driven adaptive attack planner for authorized AI security
testing.

AUDIT THESE EXISTING COMPONENTS:
- rtl/runner.py
- rtl/evaluation/judge.py
- rtl/evaluation/harness.py
- rtl/scenarios/conversation_jailbreak/
- rtl/scenarios/agent_browsing/
- rtl/scenarios/rag_poisoning/
- rtl/scenarios/tool_poisoning/
- rtl/scenarios/memory_poisoning/
- rtl/agents/
- rtl/tools/
- rtl/targets/
- existing probe models, reporting models, datasets, and tests

DESIGN REQUIREMENTS:

1. Adaptive planning
- Select the next attack strategy based on prior responses, verdicts, evidence,
  and remaining budget.
- Define explicit strategy interfaces and typed inputs/outputs.
- Distinguish strategy selection from attack execution and result evaluation.
- Support deterministic replay with a fixed seed.
- Include a baseline static strategy for comparison.
- Avoid pretending keyword matching alone is advanced reasoning.

2. Evidence-driven decisions
- Use existing Judge and evidence models where appropriate.
- Never treat a blocked attempt, refusal, textual mention, or unsupported claim
  as a confirmed vulnerability.
- Record why a strategy was selected and which evidence informed that choice.
- Preserve the complete chain of probe, response, evidence, verdict, and finding.

3. Bounded execution
- Enforce total probe, turn, time, and token/cost budgets before dispatch.
- Ensure denied or over-budget actions cannot reach execution handlers.
- Keep mock tests fully offline and side-effect-free.
- Require explicit opt-in for any live target testing; respect target scope.
- No real exfiltration, destructive actions, credential theft, or unauthorized
  access.

4. Evaluation and benchmarks
- Design a benchmark that separates planner quality from Judge accuracy.
- Prevent data leakage between tuning and held-out evaluation cases.
- Measure confirmed detection precision/recall, false-positive rate, attack
  efficiency, budget use, and reproducibility where applicable.
- Include static baseline comparisons and ablation tests.
- Never claim benchmark metrics represent real-world performance without
  supporting validation.

5. Extensibility
- Define how new strategies, attack families, target adapters, and evaluators
  can be added without changing the central runner.
- Reuse existing abstractions where possible; avoid unnecessary dependencies.
- Include graceful handling of timeouts, malformed responses, and target errors.

6. Reporting
- Specify a structured strategy trace with selected strategy, rationale,
  budget remaining, probe identifiers, observations, evidence references,
  verdict, and termination reason.
- Keep secrets out of logs and reports.
- Preserve compatibility with existing JSON/HTML/PDF reporting.

DELIVERABLE:
Create a new document named docs/ADAPTIVE_ENGINE_DESIGN.md (create docs/ if
necessary). Do not modify implementation code in this phase.

The document must include:
- Current architecture findings with file/function references.
- A proposed component diagram and data flow.
- Typed interfaces and example data structures.
- Planner decision lifecycle and stopping conditions.
- Budget enforcement points and threat model.
- Integration plan with the existing runner, Judge, and reports.
- Test plan, including deterministic replay and adversarial edge cases.
- Benchmark design and baseline comparison methodology.
- A staged implementation roadmap with small independently verifiable steps.
- Risks, assumptions, and explicit non-goals.
- A list of claims verified from code versus questions that remain unresolved.

VALIDATION:
- Inspect git status before and after.
- Confirm implementation files were not modified by this design-only phase.
- Run git diff --check.
- Report the document path, files inspected, commands run, and any uncertainty.
- Do not commit or push anything.

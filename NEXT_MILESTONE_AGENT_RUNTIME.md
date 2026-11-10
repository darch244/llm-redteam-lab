MISSION: Implement a real, bounded, offline-capable agent tool-execution simulation and connect its security evidence to evaluation.

PRESERVE ALL EXISTING WORK.
Never commit, push, merge, reset, clean, or rewrite Git history.
Do not discard or overwrite existing modifications.
Inspect existing code before editing; avoid duplicate abstractions.
Use mock/local targets only. Never execute real external side effects.

AUDIT:
1. Trace runner -> scenario -> target -> ProbeResult -> Judge -> Finding/report.
2. Inspect the existing judge evidence gate, result models, scenario interfaces,
   target APIs, tool_poisoning scenario, and related tests.
3. Identify the smallest compatible architecture for structured tool calls and
   deterministic mock-tool execution.
4. Do not assume the model natively supports function calling: support a clearly
   documented structured response protocol if necessary.

IMPLEMENT:
1. Add a reusable bounded tool-execution simulation integrated with existing APIs.
2. Validate tool names, argument schemas, payload size, number of calls, and
   execution limits. Reject unknown tools and malformed calls safely.
3. Provide mock tools only; do not make network requests or perform real
   email/file/account operations.
4. Record structured events: proposed call, validation result, execution result,
   policy violation evidence, and whether an unsafe action was blocked.
5. Preserve event evidence in ProbeResult.raw and ensure the evaluator can
   distinguish a mere textual mention from an actual simulated tool-call attempt
   or executed action.
6. Keep existing behavior/API compatible where feasible. Do not weaken the
   general evidence gate or mark a finding successful based on keywords alone.
7. Add deterministic offline tests for allowed calls, malicious/unauthorized
   calls, unknown tools, malformed arguments, empty/error responses, bounded
   execution, and evidence-aware verdicts.
8. Update AUDIT_IMPLEMENTATION_ROADMAP.md with actual behavior and limitations.

VERIFY:
Run focused tests, the complete pytest suite with coverage, Ruff lint,
Ruff format --check, mypy, and git diff --check.
Fix feasible failures, review git status and final diff, and report exact results.
Do not claim tests or capabilities that were not actually verified.
Keep all work local and uncommitted.

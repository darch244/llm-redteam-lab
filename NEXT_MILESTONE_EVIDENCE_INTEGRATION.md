MISSION: Fix bounded tool execution and integrate structured security evidence
into the existing evaluation pipeline without breaking existing behavior.

SAFETY:
- Preserve all existing work and local modifications.
- Never commit, push, merge, reset, clean, or rewrite Git history.
- Mock/offline tools only. No real network, shell, file, email, or account side effects.
- Inspect code before editing; do not duplicate existing abstractions.

FINDINGS TO ADDRESS:
1. AgentRuntime currently applies the per-turn limit after execute_calls()
   in the non-explicit-format path. Enforce the limit BEFORE execution.
   Ensure every proposed call beyond the limit is logged as blocked.
2. Audit ToolExecutor validation. Ensure call-limit violations, dangerous tools,
   malformed arguments, missing required fields, excessive payloads, and
   excessive nesting always prevent execution.
3. Check that schema parameter types and unexpected argument names are validated.
   Add these checks compatibly, with deterministic tests.
4. Keep all mock execution deterministic and side-effect-free.
5. runner.py currently calls judge.evaluate(prompt, response, category, canary=...)
   without structured ProbeResult.raw evidence.
   Design a backward-compatible evidence-aware evaluation path.
6. Structured tool evidence must distinguish:
   - mere textual mention of a tool,
   - proposed tool-call attempt,
   - blocked unauthorized/dangerous call,
   - successful simulated execution,
   - actual policy-violating simulated behavior.
   Do not treat every blocked attack attempt as a successful compromise.
7. Never mark a vulnerability successful based only on keywords or on the
   mere existence of a tool-call event. Require evidence that matches the
   security claim. Do not weaken the existing general evidence gate.

TESTS:
- Per-turn and total-call limits block excess calls before execution.
- max_calls=0 blocks all proposed calls.
- Dangerous calls, malformed JSON, unknown tools, missing/invalid/wrong-type
  arguments, extra arguments, oversized payloads, and excessive nesting.
- A normal tool mention does not count as a tool call.
- A blocked dangerous call is not mislabeled as a successful compromise.
- A simulated unauthorized execution, if representable, produces the intended
  evidence-aware verdict.
- Integration test through scenario -> runner -> judge -> Finding, verifying
  structured evidence survives and affects verdict appropriately.
- Existing tests remain compatible.

VERIFY:
Run focused tests, the complete pytest suite with coverage, Ruff lint,
Ruff format --check, mypy, and git diff --check.
Inspect final diff and git status.
Report exact commands/results, remaining limitations, and any checks not run.
Do not claim unverified functionality.
Keep all work local and uncommitted.

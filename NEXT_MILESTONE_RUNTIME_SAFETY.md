MISSION: Correct AgentRuntime tool-limit enforcement and prove that blocked
calls cannot execute. Preserve the existing architecture where practical.

SAFETY:
- Preserve all current modifications and untracked files.
- Do not commit, push, merge, reset, clean, or rewrite Git history.
- Mock/offline tools only. No real network, shell, filesystem, email, or
  account side effects.
- Inspect the existing executor event model before changing it.
- Do not merely change an event's reason after execution and call that blocking.

CRITICAL BUG:
In rtl/agents/runtime.py, excess per-turn calls are passed to
ToolExecutor.execute_calls() before being marked as blocked. This can execute
otherwise permitted tools beyond the per-turn limit. The explicit-format and
non-explicit-format branches both need auditing.

REQUIREMENTS:
1. Enforce max_tool_calls_per_turn BEFORE execution.
2. Excess calls must be recorded as blocked without passing them through
   the execution path. Preserve proposed-call evidence and record a clear
   turn_limit_exceeded reason.
3. Ensure blocked calls never increment executed_count or appear as successful
   executions. Preserve accurate proposed/blocked/executed event accounting.
4. Enforce max_total_tool_calls consistently across turns. A max of zero must
   execute no calls. Do not accidentally consume the execution budget twice
   while logging rejected calls.
5. Enforce max_turns: once the configured maximum is reached, further
   processing must not execute tools. Define and test the expected behavior
   for rejected extra turns.
6. Audit ToolExecutor's dangerous-tool, malformed-input, argument validation,
   and total-call-limit paths. A blocked or invalid call must never be reported
   as a successful execution.
7. Check whether parsing the same response in AgentRuntime and ToolExecutor
   can change call counts, duplicate events, or lose source/raw evidence.
8. Keep all mock execution deterministic and side-effect-free.
9. Ensure the Judge distinguishes an attempted call, a blocked call, and a
   successful simulated execution. A blocked attack attempt alone is not a
   successful compromise.
10. Avoid broad rewrites and preserve backward compatibility where reasonable.

TESTS:
- Per-turn limit of 1 with 3 safe calls: exactly 1 executes; 2 are blocked
  and none of the blocked calls reaches the execution handler.
- Repeat the same test with require_explicit_tool_format=True.
- max_tool_calls_per_turn=0 and max_total_tool_calls=0 execute nothing.
- Total-call limit remains enforced across multiple turns.
- After max_turns is reached, further calls cannot execute.
- Dangerous, unknown, malformed, invalid-typed, missing-argument, extra-argument,
  oversized, and excessively nested calls cannot execute.
- A blocked call cannot increase executed_count or be classified as success.
- Integration test verifies accurate evidence and verdict through
  scenario -> runner -> judge -> Finding where practical.
- Existing tests continue to pass.

VERIFY:
Run focused tests, full pytest with coverage, ruff check ., ruff format --check,
mypy rtl, and git diff --check. Inspect git status and final diff.
Report exact results and remaining limitations. Keep changes local/uncommitted.

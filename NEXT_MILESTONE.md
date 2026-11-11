MISSION: Build llm-redteam-lab into a genuinely advanced AI Red Teaming platform.

Inspect the existing implementation before making changes. Preserve all current work and uncommitted modifications.

RULES:
- Never commit, push, merge, reset, clean, or rewrite Git history.
- Do not discard or overwrite existing changes.
- Keep normal tests offline; do not require paid API keys.
- Use mock/local targets only unless an explicitly authorized target is already configured.
- Do not claim a capability works unless implemented and verified.

STEP 1 — AUDIT:
- Inspect git status, the current diff, and AUDIT_IMPLEMENTATION_ROADMAP.md.
- Trace the real attack path from scenario generation through target execution, evidence collection, judging, and reporting.
- Identify the highest-impact missing or weak attack capability.
- Determine whether existing multi-turn attacks, adaptive follow-ups, prompt injection, jailbreak, RAG poisoning, and agent/tool attacks are implemented or stubs.
- Avoid duplicating existing features.

STEP 2 — IMPLEMENT:
Choose ONE substantial, high-value attack capability based on the audit. Do not merely add tests or documentation.

Prefer a reusable multi-turn or adaptive attack strategy if the architecture supports it. Otherwise, implement the most important confirmed missing capability.

Requirements:
- Integrate with existing interfaces and preserve public API compatibility where feasible.
- Include bounded turns, retries, runtime, and payload size.
- Handle refusals, empty responses, malformed output, and target errors.
- Preserve attack-step history and evidence using existing result models where possible.
- Use the existing evidence/judge pipeline; never classify success based on a keyword alone.
- Add deterministic offline regression tests for success, refusal, errors, malformed results, and stopping limits.
- Do not weaken existing assertions or quality gates.
- Update AUDIT_IMPLEMENTATION_ROADMAP.md with actual implementation details and limitations.

STEP 3 — VERIFY:
Run focused tests, then the full pytest suite with coverage, Ruff lint, Ruff format --check, mypy, and git diff --check.
Fix failures where feasible and report any remaining failures honestly.
Review the final diff for accidental changes.

FINAL REPORT:
1. Confirmed capability gap and why it matters.
2. Actual capability implemented and how it works.
3. Exact changed-file list.
4. Actual verification results.
5. Remaining limitations and next highest-priority milestone.

Keep all changes local and uncommitted. Do not stop after writing a plan; implement and verify the selected capability.

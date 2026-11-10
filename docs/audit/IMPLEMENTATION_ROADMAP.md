# Implementation Roadmap — llm-redteam-lab

Companion to `docs/audit/TECHNICAL_AUDIT.md` (findings referenced by ID, e.g. F-06).
Written 2026-10-23 from a read-only Stage-A audit; all sequencing assumes the
constraints in the engagement brief: dedicated branch per phase, regression test
per fix, offline-deterministic core tests, mock-target validation, no weakening
of authorization/ethics guards.

Waves are ordered by **severity + leverage**, not by the original P0–P4 labels —
but they intersect: Wave 1 ≈ P0 core, Wave 2 ≈ P1, Wave 3 ≈ P2, Wave 4 ≈ P3.

Effort: **S** (<1 day), **M** (1–3 days), **L** (>3 days) — relative estimates.

---

## Wave 1 — Correctness, reproducibility, honest reporting  (audit P0)

> Goal: every number a report shows corresponds to something that actually ran, deterministically.

| # | Item | Fixes | Effort | Acceptance criteria (measurable) |
|---|------|-------|--------|----------------------------------|
| 1.1 | Create dev venv; run and record the real baseline: `make test`, `make lint`, `make typecheck`, `pytest --cov`. | F-25 | S | All four commands executed with exact outputs recorded in the audit doc; every baseline failure triaged into a Wave-1 ticket. Coverage gate raised only to a value that is measured `≥` (not assumed). |
| 1.2 | Outcome states end-to-end: `confirmed / suspected / failed / inconclusive` on every finding; runner records failed probes (prompt, exception, retries) instead of dropping them; `summary.failed` + attempt coverage in `ScanSummary`. | F-06, F-14(sub) | M | `rtl scan --target mock` over `full.yaml`: `total == len(resolve(...))` with all outcomes represented; a target that raises mid-run yields findings with `failed` status + error text, test proves it. |
| 1.3 | Evidence capture on every finding: prompt, response excerpt, judge rationale, heuristic rule that fired, `expected` evidence hit/miss persisted in `raw`. | F-08, F-09(sub) | M | JSON report round-trip preserves evidence fields; ≥90% heuristic verdicts include the triggering rule name. |
| 1.4 | Honor `--offline` (skip judge target + engines); honor or remove `judge_max_retries`, `JudgeConfig.temperature`, `ScanOptions.redact`, `ScanOptions.parallel`. | F-02, F-11 | S | Regression tests: `--offline --judge-model X` performs zero LLM calls (spy target); every remaining flag demonstrably changes behavior or is gone from CLI/YAML surface. |
| 1.5 | Fix `_check_status` classification: retry only 5xx/408/429; permanent `TargetError` for other 4xx. | F-04 | S | `httpx.MockTransport` tests: HTTP 400 → no second attempt; HTTP 500 → exactly `max_retries` attempts; 429 with `Retry-After` honored. |
| 1.6 | Update provider defaults: Anthropic → active model (e.g. `claude-haiku-4-5-20251001`); refresh README examples; re-verify OpenAI/Ollama defaults against vendor docs with an “as of” date stamp. | F-01 | S | `rtl target anthropic` default resolves to a model listed as *Active* in vendor deprecation page (accessed date recorded); config test asserts default not in retired list. |
| 1.7 | Fix CI: `.[dev,pyrit]` → `.[dev]` (missing extra); add `--cov-fail-under` consistent with measured coverage; matrix stays 3.11/3.12. | F-03(sub), F-25 | S | CI YAML installs only existing extras; a grep-based check (or CI run when unblocked) confirms no nonexistent extras. |
| 1.8 | Escape model/attack text before reportlab `Paragraph` (`xml.sax.saxutils.escape`); add SRI + graceful degrade for Chart.js; scrub credentials embedded in `base_url` (userinfo) in fingerprints/reports. | F-28, F-15 | S | Tests: finding response containing `<` and `&` renders a valid PDF path without raising (needs reportlab env — otherwise unit-test the escaping function); HTML contains `integrity=` attribute; `https://u:p@host` fingerprints redact userinfo. |
| 1.9 | Stable test-case IDs: content-derived slugs (e.g. `DI-a1b2`) with legacy positional IDs as aliases; rewrite `build_probe()` to a deterministic slug. | F-13, F-20 | M | Same probe set yields identical ID tables across two fresh processes (`PYTHONHASHSEED` varied); suite YAMLs updated; deprecation note in CHANGELOG. |
| 1.10 | Fix docs/facts: `docs/reporting.md` filenames, `--scenarios` docstring, judge-mode validation, IMPLEMENTATION_NOTES coverage-gate wording (only measure-backed claims), `ATLAS_MAP` T0080 tactic → Persistence, T0024 name → “ML Inference API”. | F-23, F-24, F-19 | S | No doc statement remains that is contradicted by code (spot-check list reproduced in PR description). |
| 1.11 | Address packaging: ship `suites/` as package data, resolve via `importlib.resources`; keep repo-relative override. | F-21 | S | Wheel built (`python -m build`), installed into a clean temp venv, `rtl scan --target mock` runs from `/tmp` (home dir ≠ repo) without `FileNotFoundError`. (Wheel-build env needed — if blocked, static change + documented build check in CI.) |
| 1.12 | `CHANGELOG.md` (Keep-a-Changelog format) seeded from this audit; prepare v0.1.0 metadata (right version bump only when Wave-1 lands). | — | S | Version string single-sourced from `rtl/_version.py`; changelog lists each Wave-1 change; `pyproject` build succeeds. |

**Wave-1 exit condition:** `make test lint typecheck cov` all green on the phase branch, with a recorded run; all Confirmed bugs from the audit fixed or explicitly deferred with a ticket; every fix carries a regression test.

---

## Wave 2 — Evidence-based, calibrated scoring  (audit P1)

> Goal: when a report says “success”, it means positive evidence existed.

| # | Item | Fixes | Effort | Acceptance criteria |
|---|------|-------|--------|---------------------|
| 2.1 | Category-specific success evidence in the heuristic judge (sentinel/echo checks per probe) instead of “no refusal ⇒ success”; injection findings default to `suspected` until positive evidence. | F-07 | M | Against `mock:cooperative` (which paraphrases rather than complies structurally), injection-category “confirmed” rates drop measurably (assert exact expected outcomes for the mock corpus in tests); ambiguous findings no longer counted as `succeeded`. |
| 2.2 | `expected` field on probes + runner wiring; scenario runners emit their own deterministic checks (system-prompt leak markers for agent_browsing; injected phrasing for rag_poisoning). | F-08, F-10 | M | All DE/indirect probes define `expected`; `rtl scan --target mock --suite suites/quick.yaml` reports evidence-hit status per finding; scenario verdicts test the scenario objective, not just non-refusal. |
| 2.3 | Labeled judge dataset `tests/judge_eval/`: ≥100 synthetic positive+negative cases across all 5 categories (+scenarios), with held-out gold labels. | F-09 | M | Dataset committed with a manifest (category, expected label, evidence); count verified by a test (`>=100`). |
| 2.4 | `rtl eval-judge`: precision/recall/F1 for heuristic and (mock) LLM judges; CI gate fails below threshold; **only measured numbers reported**. | F-09 | M | Command runs fully offline with deterministic mock attacker/judge; README/CHANGELOG state only the measured metrics (actual values quoted from the run, no estimates); CI step added. |
| 2.5 | Reconcile heuristic vs LLM-judge verdicts (deterministic check wins on conflict or flags `contested`); store judge rationale text; never treat LLM verdict as sole ground truth. | F-09 | M | Conflict test: stub LLM says SUCCESS, deterministic check says no-evidence → finding labeled contested/suspected with both rationales stored. |
| 2.6 | Bounded concurrency + budgets: semaphore-bounded probe fan-out, per-scan timeout & retry budget, prompt-truncation flagged in `raw`/rationale, cancellation-friendly run loop (cooperative cancel points). | F-16, F-17 | M | Suite of 110 mock probes with 50ms delay completes ≪ sequential wall time; concurrent cap verified by observed peak in a spy target; SIGINT test (or CancelledError unit test) leaves a truncated-but-valid report. |

**Wave-2 exit condition:** judge metrics measured and reported from `rtl eval-judge` (exact numbers, from an actual run, recorded in docs); no `success` verdict without stored positive evidence; mock-target e2e suite passes.

---

## Wave 3 — Adaptive attacks and agent scenarios  (audit P2)

> Goal: agentic behaviors judged from observable artifacts (mock tool logs, not text vibes).

| # | Item | Fixes | Effort | Acceptance criteria |
|---|------|-------|--------|---------------------|
| 3.1 | Converter/mutation layer: base64, leetspeak, translation, role-play wrappers, payload splitting, homoglyph/zero-width (already implicit in probes) applied behind a `strategy:` field in suite YAML. | — | M | Each converter has unit tests (encode/decode universal properties); suite YAML with strategies resolves deterministically; mock target validates strategy ordering. |
| 3.2 | Multi-turn strategies: Crescendo-style escalation and a PAIR/TAP-style attacker loop with configurable attacker model + deterministic mock attacker for CI. | — | L | Offline CI path uses the mock attacker (no network); loop terminates by budget; every turn recorded as evidence (request/response transcript). |
| 3.3 | Mock tool infrastructure: sandboxed local-only tools (fetch/email/HTTP sink) whose logs are part of `raw` evidence; tool-poisoning, tool-call hijacking, cross-agent injection, markdown-render exfil scenarios only against mock tools. | F-12 | L | Every agent-scenario finding cites a tool-call log line as its decisive evidence; zero tests/CI paths reach real network (validated by forbidden-socket test guard). |
| 3.4 | Probes/metadata for T0080 (context poisoning), T0110 (tool poisoning), T0043 (adversarial data) or explicit “registry-only, not probed” annotation in reports. | F-19 | M | ATLAS crosswalk in reports distinguishes probed vs registered-only techniques. |
| 3.5 | RAG/agent data boundaries: per-scenario fixture allowlists and provenance labels on retrieved docs surfaced in findings. | F-12 | S | A finding for rag_poisoning identifies which retrieved docs were poisoned vs normal; tamper attempts on fixture paths raise ScenarioError (test). |

---

## Wave 4 — Benchmarking, reporting, extensibility  (audit P3/P4)

| # | Item | Fixes | Effort | Acceptance criteria |
|---|------|-------|--------|---------------------|
| 4.1 | Benchmark metadata: full resolved config snapshot, provider+model IDs, UTC timestamps, stable IDs in every artifact; `rtl compare old.json new.json` for regression diffs across runs/models. | F-11(sub) | M | Diff command output only mentions measured deltas; artifact contains no undocumented fields. |
| 4.2 | OWASP LLM Top 10 (2026 edition) mapping alongside ATLAS in code + reports, with edition + access-date stamped in docs; never claim full coverage from keyword overlap. | F-22 | S | Category→OWASP table committed with source URL + date; reports show both mappings. |
| 4.3 | SARIF output + ready-to-use GitHub Action (SARIF upload path). | — | M | SARIF validates against the schema; Action runs the quick suite against mock in CI (self-target, no keys). |
| 4.4 | HTML/PDF executive summary with measured performance metrics (throughput, duration, error rate — real values from the scan). | F-14 | S | Scenario outcomes rendered in HTML; summary numbers derived from the artifact, test asserts field provenance. |
| 4.5 | Engine integration honored from `Suite.engines` (optional deps, graceful unavailability, results as `engine_results` + report section); CI smoke for engines only when deps present. | F-03 | M | `engines: [garak]` in a suite: with garak installed → results recorded; without → `engine_results` entry reporting unavailability, scan continues; suite docs updated. |
| 4.6 | (Optional) HTTP application target: authenticated, env-based secrets, redacted everywhere, explicit `--i-am-authorized` confirmation flag; plugin interfaces for targets/probes/scorers/reporters. | — | L | Default scan refuses non-mock network targets without the authorization flag; secrets never appear in reports/logs (test with injected fake secret); interface draft doc. |

---

## Sequencing note

Wave 1 is the prerequisite for Waves 2–4 only in parts 1.1–1.3 and 1.9 (outcome
states, evidence capture, stable IDs). Waves 2 and 3 can partially proceed in
parallel on separate branches once 1.2/1.3 land; Wave 4's OWASP/SARIF work is
independent and could slot into any branch.

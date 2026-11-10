# Technical Audit — llm-redteam-lab

- **Date:** 2026-10-23
- **Branch:** `audit/stage-a-read-only` (clean working tree at commit `62f5860`)
- **Scope:** read-only audit of packaging, config, CLI, targets, attack libraries, scenarios, scoring, reporting, engines, tests, CI, docs.
- **Method:** full source review of every module under `rtl/`, all 9 test files, suites, CI workflow, docs, and example artifacts; static verification of every quantitative README claim; live verification of external framework references (MITRE ATLAS, OWASP) against authoritative sources.

Every finding is tagged:

- **[Confirmed]** — backed by source/code evidence and, where applicable, a failed or blocked external check.
- **[Hypothesis]** — plausible defect or risk inferred from code; **not** verified by execution in this environment.

---

## 1. Checks executed in this environment (exact record)

Environment: Linux, Python 3.14.8 (`python3 --version`). The system interpreter has **no third-party packages and no test tooling**; there is **no `.venv`** in the repo, and `Makefile` targets depend on `./.venv/bin/...`.

| Command | Exit status | Result |
|---|---|---|
| `python3 -m pytest --version` | 1 | `No module named pytest` |
| `make test` | 2 (make error 127) | `./.venv/bin/python: No such file or directory` |
| `ruff check rtl tests` | 127 | `ruff: command not found` |
| `mypy rtl` | 127 | `mypy: command not found` |
| `rtl version` | 127 | `rtl: command not found` |

Per the Stage-A constraints, no dependencies were installed, so **pytest, ruff, mypy, coverage, and any runtime command (e.g. `rtl list-attacks`, `rtl scan --target mock`) are BLOCKED in this environment**. All runtime/quality-gate claims in this audit were therefore verified statically (source reading + grep), not by execution. Numbers are marked accordingly (§3 F-25).

Statically verified claims: probe counts and per-category test-count claims below were derived with `grep -c` over the source and are exact for the current tree.

---

## 2. External framework references verified against authoritative sources

Framework sources used (accessed **2026-10-23**):

1. **MITRE ATLAS** — current data (web version v5.6-era, 2025-11+ sub-technique structure). Verified via MITRE's own D3FEND mirror of ATLAS techniques (d3fend.mitre.org/offensive-technique/attack/AML.Txxxx) and the ATLAS layering in community-trained mirrors; IDs confirmed:
   - `AML.T0043`, `AML.T0024`, `AML.T0024.000`, `AML.T0051`, `AML.T0051.000`, `AML.T0051.001`, **`AML.T0051.002` (Triggered — exists; created 2025-11-04)**, `AML.T0054`, `AML.T0056`, `AML.T0057`, **`AML.T0070` (RAG Poisoning — exists)**, **`AML.T0080` (AI Agent Context Poisoning — Persistence tactic)**, **`AML.T0086` (Exfiltration via AI Agent Tool Invocation)**, **`AML.T0110` (AI Agent Tool Poisoning)**.
   - Result: all 14 IDs in `rtl/evaluation/atlas.py` are real ATLAS techniques. Two metadata inaccuracies found (F-19).
2. **OWASP Top 10 for LLM Applications** — current edition is **“OWASP GenAI LLM Top 10 2026” (v1.0, published 2026-08-04)** (source: https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/ and the OWASP project GitHub, which states “Current release: OWASP GenAI LLM Top 10 2026 — published August 4, 2026”). Item list per the official PDF (genai.owasp.org/download/56857): LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM03 Excessive Agency, LLM04 Supply Chain, LLM05 Data and Model Poisoning, LLM06 Unbounded Consumption, LLM07 Misinformation, LLM08 Hidden Context Exposure, LLM09 Vector and Embedding Weaknesses, LLM10 Improper Output Handling. Prior edition (2025, v2.0, 2024-11-18): same names, with System Prompt Leakage at #7, Excessive Agency #6, Improper Output Handling #5.
3. **Anthropic model deprecations** (docs.claude.com/en/docs/about-claude/model-deprecations, accessed 2026-10-23): `claude-3-5-haiku-20241022` was deprecated 2025-12-19 and **retired 2026-02-19**.

**The repo currently has NO OWASP mapping of any kind** — only ATLAS (`docs/atlas-mapping.md` lists 5 ATLAS IDs; nothing else in code or docs mentions OWASP). Any OWASP coverage statement would therefore be false today; the gap is tracked as F-22.

---

## 3. Findings

Severity scale: **Critical / High / Medium / Low**. IDs are stable for referencing.

### 3.1 Environment and process

**[F-25] All quality gates unverified in this environment — BLOCKED [Confirmed environment limit]**
- Severity: Medium (audit limitation, not a repo defect).
- Evidence: §1 command record; `Makefile:14,22-23,31`; `pyproject.toml:53-88`; repo has no `.venv`.
- Impact: `pytest` (claimed “68 passing”), coverage (claimed “≥55% total; ≥80% on config, evaluation, reporting”), `ruff`, `mypy`, and a real `rtl scan` run could not be executed here. None of those claims are confirmed runnable *today*; they are only verifiable statically.
- Recommendation: Stage B must start by creating the dev venv (per `Makefile setup`) and re-running all gates to establish a measured baseline before any fixes.

### 3.2 Target adapters

**[F-01] Default Anthropic model is retired by the vendor [Confirmed]**
- Severity: High.
- Evidence: `rtl/config.py:31` (`"anthropic": "claude-3-5-haiku"`); `rtl/README.md:64` example `anthropic:claude-3-5-sonnet`; Anthropic deprecations page (accessed 2026-10-23): `claude-3-5-haiku-20241022` retired 2026-02-19; current active members include `claude-sonnet-5-5`, `claude-opus-5-5`, `claude-haiku-5-5`, `claude-haiku-4-5-20251001`.
- Impact: any user running `rtl target anthropic` / default suite against Anthropic gets 4xx-class errors from the provider every time (misclassified as non-retriable `TargetError`, so also F-04 noise).
- Recommendation: update `DEFAULT_MODELS` to a currently active model (e.g. `claude-haiku-4-5-20251001` for the cheap default); update README examples; note OpenAI (`gpt-4o-mini`) and Ollama (`llama3.1`) defaults are old but still generally valid — refresh opportunistically and pin model IDs in docs with an “as of” date.

**[F-04] Every unexpected HTTP status is treated as transient and retried [Confirmed]**
- Severity: Medium.
- Evidence: `rtl/targets/base.py:165-185` — `_check_status` raises `TransientTargetError` for **any** status other than 2xx, 401/403, 404, 429. A 400/409/413/422 (permanent client errors) triggers 3 retries plus exponential backoff+sleep (base.py:109-126, 198-200) — up to ~4 attempts and multi-second stalls per probe, all wasted.
- Impact: fast deterministic failures become slow nondeterministic ones; on a 110-probe full suite a persistent misconfiguration is retried hundreds of times.
- Recommendation: retry only 5xx (and 408/409 at most); classify other 4xx as permanent `TargetError`. Regression test with a fake transport returning 400.

**[F-05] Provider response parse errors can escape as unclassified exceptions [Hypothesis]**
- Severity: Low.
- Evidence: `openai_target.py:80` and `anthropic_target.py:75` call `response.json()` outside any `try`; a 200 response with invalid JSON raises `json.JSONDecodeError` (not a `TargetError`) which `send()` does not classify; it reaches `runner.py:65` and is swallowed into a silent probe drop (see F-06). Content-type filtering (`openai_target.py:77`) reduces but does not eliminate this.
- Recommendation: wrap `.json()` in the classified error envelope.

**[F-18] Retry-After parsing handles only numeric values [Hypothesis]**
- Severity: Low.
- Evidence: `base.py:175-184` — HTTP-date `Retry-After` values raise `ValueError` and become `None` (falls back to backoff). Acceptable, worth a comment/test.

### 3.3 Runner / scan orchestration

**[F-06] Failed probes vanish from reports; no error outcome state [Confirmed]**
- Severity: High (measurement integrity).
- Evidence: `rtl/runner.py:65-67` — any exception from `target.asend()` logs an error and `continue`. The probe produces **no finding**, and there is no outcome state for “could not run”. `ScanSummary` (models.py:132-143) has no `failed` counter; `finding.verdict_label` validation (models.py:107-112) admits only success/refused/ambiguous.
- Impact: a scan where the provider went down mid-run looks like a clean short scan. `summary.total` counts only probes that produced a response; downstream consumers cannot distinguish “20 probes passed” from “80 probes couldn't be executed”. Denominator is lost.
- Recommendation: add an explicit `error`/`inconclusive` outcome persisted per resolved probe (prompt, exception class/message, retries-observed), include it in `summary`, and surface it in HTML. This is also the precondition for Stage-B outcome states (confirmed/suspected/failed/inconclusive).

**[F-02] `--offline` is documented but never enforced [Confirmed]**
- Severity: High.
- Evidence: `rtl/cli.py:47` (“Skip LLM judge and engines”) and `Makefile:38-39` (the `ollama` target uses `--offline`), `examples/demo_against_ollama.sh:31` uses it; but `ScanOptions.offline` (`config.py:156`) is **read nowhere** — `grep -rn "offline" rtl/` shows only its definition and passing. The runner builds and uses the LLM judge purely from `judge.mode`/`judge.model` (`runner.py:46-51`).
- Impact: a user running `--offline --judge-model ollama:x` still makes LLM-judge calls to that server. The one documented lever for controlling live-model usage does nothing.
- Recommendation: honor `options.offline` in the runner (skip judge target construction and any engine dispatch); add regression test.

**[F-11] Five configuration options are dead no-ops [Confirmed]**
- Severity: Medium (trust/reproducibility).
- Evidence:
  - `ScanOptions.parallel` — `config.py:158`; grep shows zero consumers.
  - `ScanOptions.redact` — `config.py:157`; set by CLI (`cli.py:75`) but `run_scan` always calls `write_json` with its own default `redact=True` (`runner.py:106`, `json_reporter.py:16-26`). (Fail-safe direction, but `--no-redact` is silently ignored.)
  - `ScanOptions.judge_max_retries` — `config.py:160`; zero consumers.
  - `JudgeConfig.temperature` — `config.py:146`; `runner.py:51` constructs `Judge(judge_target=..., mode=...)` without it.
  - `Suite.engines` — `config.py:123`; loaded from YAML (suites/full.yaml declares `engines: [garak, pyrit]`) and never consumed anywhere; `rtl/engines/build_engine` (`rtl/engines/__init__.py:29-33`) has zero callers outside its definition. See F-03.
- Impact: suite/CLI options that appear to change behavior don't. This directly prevents honest reproducibility (P1 “config in benchmark output”).
- Recommendation: either implement (wire temperature, retries, engine dispatch, parallel) or remove the flags from CLI/YAML surface until implemented. Removing dead options from YAML examples is a public-interface change — coordinate with the user.

**[F-03] garak/PyRIT “engines” are never reachable from any scan path [Confirmed]**
- Severity: Medium-High (feature-claim gap).
- Evidence: engine classes and `ENGINE_REGISTRY`/`build_engine` exist (`rtl/engines/__init__.py:17-33`) but `runner.py`/`cli.py` never reference them; `Suite.engines` is ignored (F-11). Also `pyproject.toml:34-42` defines only `dev`/`pdf` extras, yet **CI installs `.[dev,pyrit]`** (`.github/workflows/ci.yml:22`) — a nonexistent extra; pip proceeds with a warning, but PyRIT is never actually installed, and the PyRIT wrapper imports `pyrit.*` APIs (`pyrit_engine.py:46-54`) that cannot be validated in this environment (no pyrit available; also its imperative-`memory=` usage matches older PyRIT APIs — API-drift hypothesis).
- Impact: README “Optional engines: wrappers around garak and PyRIT” implies a user can run them; today the only way is hand-writing Python against those classes. `full.yaml` advertising `engines: [garak, pyrit]` quietly ignores the field.
- Recommendation: implement dispatch in the runner against `ENGINE_REGISTRY` (guarded, optional, error reported as `engine_results`), and fix CI's nonexistent extra (`.github/workflows/ci.yml:22`) to `.[dev]` (or `.[dev,pdf]` as needed).

**[F-16] No concurrency, pacing, or cost controls are operative [Confirmed]**
- Severity: Medium.
- Evidence: probes run strictly sequentially (`runner.py:54` `for` loop); `asend` off-loads sync httpx to a thread (`base.py:128-132`) rather than using async I/O; no rate-limit pacing beyond honoring `Retry-After` (`base.py:202-206`); no request/token/cost budget exists; no cancellation hook (no signal/except-handler around the loop); `ScanOptions.parallel` dead (F-11). The only cost lever is `--max_prompt_len` truncation (`runner.py:56-57`) which silently truncates attack payloads (changing probe semantics without flagging it in the report).
- Impact: long-running/full scans cannot be bounded or safely interrupted; docs admit this (“~1h+” for full.yaml, README.md:73).
- Recommendation: P1/P2 roadmap items — bounded concurrency with a semaphore, configurable timeouts/retry budgets per scan, prompt-truncation flagged in the finding when it occurs.

**[F-17] `max_prompt_len` silently mutates attack payloads [Confirmed]**
- Severity: Low-Medium.
- Evidence: `runner.py:56-57`; the finding stores the truncated prompt, but nothing distinguishes “full probe” from “truncated probe”, and no rationale notes the mutation. Multi-line encoded payloads (base64, zero-width) break when truncated.
- Recommendation: mark `prompt_truncated: true` in `raw` + rationale when truncation occurs.

### 3.4 Scoring

**[F-07] Heuristic judge reports injection/jailbreak “success” for any non-refusing response [Confirmed]**
- Severity: High (false-positive by design; measurement integrity).
- Evidence: `rtl/evaluation/judge.py:232-248` — for `direct_injection`, `indirect_injection`, and `jailbreak`, any response that doesn't match refusal/deflection substrings gets `label="success"`, `success=True`, confidence 0.6/0.5. There is no check that the response actually reflects the attack effect. The jailbreak library itself documents the weakness (“weak signal for jailbreaks; confirm with LLM judge or human”, jailbreak.py:20-22) and the severity model partially compensates (`severity.py:93-94` adds a caveat below 0.6 confidence — but 0.5/0.6 are ≥0.6 for injection).
- Impact: against a *normal, helpfully answering* assistant, essentially every injection probe is “successful”, inflating `succeeded` counts (see shipped `examples/sample_report.json`: 15/15 probes → mostly “success”). Severity auto-rates injection success as medium/high → misleading engagement findings.
- Recommendation: require category-specific positive evidence before `success=True` (e.g. the exact one-word echo for DI-01, sentinel tokens embedded in injected directives, leak markers for extraction); otherwise report `suspected`/`inconclusive`. Labeled dataset to quantify (Stage-B P1).

**[F-08] Per-probe `expected` evidence is defined in the judge contract but never supplied [Confirmed]**
- Severity: High (false negatives).
- Evidence: `Judge.evaluate(..., expected: list[str] | None)` (`judge.py:130-131`) is the only path to high-confidence exfil detection (`judge.py:200-207`), but `runner.py:69` and `runner.py:149` never pass `expected`, and `AttackPrompt` (`model.py:8-35`) has no field for it. Scenario probes do define observable evidence in `raw` (`agent_browsing/scenario.py:110-117`, `rag_poisoning/scenario.py:129-136`) but it is not used for judging.
- Impact: data-exfiltration probes are scored only by weak markers (`judge.py:208-230`): e.g. a probe asking to “render a markdown image beacon” judged as ambiguous unless the reply happens to contain `EXFIL`/`@attacker` markers. Success/failure of the actual objective is unevaluated.
- Recommendation: add `expected` (sentinel strings) to the probe schema, populate for all DE/indirect probes, pass through the runner; prefer simulated reliable evidence (synthetic URL/tool logs) per Stage-B P1.

**[F-09] LLM-judge verdict is treated as ground truth with fixed confidence [Confirmed]**
- Severity: Medium.
- Evidence: `judge.py:278-297` — any judge output that `startswith SUCCESS/REFUSED/AMBIGUOUS` is converted to a verdict with **hard-coded confidence** 0.85/0.8, no rationale capture from the judge, no evaluation of the judge against labeled data, and no combination with the deterministic heuristic verdict (the heuristic result is computed then discarded whenever an LLM verdict parses, `judge.py:143-151`).
- Impact: judge bias/sloppiness (a model that answers “SUCCESS” for everything) flows straight into severity (`severity.py:87-100`), and the report presents `judge: llm` as authoritative. There is **no labeled dataset anywhere** (`tests/judge_eval/` does not exist) to measure precision/recall of the heuristic or LLM judge.
- Recommendation: keep both verdicts, reconcile (deterministic wins on conflict or produces a “contested” flag), capture judge rationale text into `raw`, and build the labeled set + `rtl eval-judge` gate (Stage-B P1, ≥100 cases).

**[F-10] Scenario findings are judged with a judge branch that cannot test the scenario's objective [Confirmed]**
- Severity: Medium-High.
- Evidence: `agent_browsing` and `rag_poisoning` probes are labeled `category="indirect_injection"` (`agent_browsing/scenario.py:86`, `rag_poisoning/scenario.py:106`) and judged via `judge.evaluate(pr.probe.prompt, pr.response, pr.probe.category)` (`runner.py:149`). The `indirect_injection` heuristic branch (judge.py:232-239) returns success for *any non-refusal* — it contains no leak-marker or poisoned-answer checks. The scenario's stated objective — “leaks its own system prompt” (agent_browsing/scenario.py:87-97) — is never actually evaluated.
- Impact: on the leaky mock, a scenario “success” doesn't mean the leak occurred; on a defensive target that politely answers the support question while declining the hidden instruction, the answer may still read as generic and be counted ambiguous/success — both FP and FN.
- Recommendation: judge scenario results against scenario-specific evidence (e.g. system-prompt leak markers for agent_browsing; injected refund email/90-days phrasing for rag_poisoning) with deterministic checks in the scenario runner.

### 3.5 Scenarios, evidence, data boundaries

**[F-12] Scenario evidence is observational, not tool-call based; boundary isolation not enforced [Confirmed gap vs mission, by design today]**
- Severity: Medium (structural gap; the roadmap addresses it in Wave 3).
- Evidence: both scenarios send one composed prompt and evaluate a text reply (`agent_browsing/scenario.py:83`, `rag_poisoning/scenario.py:103`); `raw` records fixture provenance (file names, sizes) but there is no simulated tool surface (no sandboxed fetch/email/HTTP tool logs), so exfil-via-tool outcomes like the DE probes (`data_exfiltration.py:47-126` — email/curl/fetch/beacon probes have no mock tool sink to prove the exfil happened) rely purely on response text. RAG boundary: `retrieve_docs` (`rag_poisoning/scenario.py:56-68`) mixes poisoned + normal docs with no provenance labels surfaced in the report beyond `poisoned_doc_retrieved`.
- Impact: no reported finding from the current pipeline can be backed by an *observable controlled* artifact for tool- or retrieval-mediated behaviors; every such finding is a text-match diagnosis.
- Recommendation: Stage-B P2 — introduce isolated mock tools (local-only, synthetic data, deterministic) and judge from their logs; enforce per-scenario data boundaries (fixture allowlists).

**[F-13] `build_probe()` generates hash-derived, run-unstable attack IDs [Confirmed]**
- Severity: Low (currently unused; API risk).
- Evidence: `rtl/scenarios/base.py:66` — `attack_id=f"SC-{category[:3].upper()}-{abs(hash(name)) % 1000:04d}"`. Python string hash is randomized per process (`PYTHONHASHSEED`), so IDs differ between runs/processes, and bare `%1000` invites collisions.
- Impact: the exported helper cannot be used to build reproducible test-case IDs (a Stage-B requirement). Actual shipped scenarios use fixed IDs (`SC-AGT-0001` etc.), so today this is latent only.
- Recommendation: replace with a deterministic slug of `category + name` (or an explicit counter); note as an interface-sensitive change.

### 3.6 Reporting

**[F-14] HTML report omits scenario findings and failed-probe visibility [Confirmed]**
- Severity: Medium.
- Evidence: scenario outcomes are appended to `ScanResult.scenario_outcomes` (`runner.py:152-155`), excluded from `findings`, and excluded from `summary.total` (aggregate counts `findings` only, `models.py:155-175`). The HTML template (`templates/report.html:98-155`) has **no** scenario section; only `engine_results` is rendered there. `docs/architecture.md` claims “Every failure path … records per-probe errors instead of aborting the scan” — but per F-06 errors are dropped, not recorded.
- Impact: reports under-represent what ran; scenario results are only available to JSON consumers. Combined with F-05/F-06, the “attempted vs answered vs failed” distribution is unknowable from any report.
- Recommendation: render scenario outcomes in HTML, include scenario findings in summary aggregates (with a scenario dimension), and add the error outcome (F-06).

**[F-15] HTML report depends on a non-SRI Chart.js CDN; “standalone” claim is partial [Confirmed]**
- Severity: Low-Medium (security/reproducibility of the artifact).
- Evidence: `templates/report.html:7` (`<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js">` — no `integrity`/`crossorigin` attributes). README/HTML-comment claim “standalone HTML” (README.md:30-31). Also `meta.base_url` is printed verbatim (`report.html:58`) — a `base_url` containing userinfo (`user:pass@host`) would be reported as-is; nothing scrubs URLs.
- Impact: opening a report offline breaks the only chart; a compromised CDN would execute code in the report context (reports are often shared/email-attached — reputational and exfil vector in a red-team setting).
- Recommendation: add SRI hash + `crossorigin=anonymous`, degrade gracefully (draw the distribution as an HTML table when offline), and scrub/redact credentials embedded in `base_url`.

**[F-28] HTML escaping of untrusted model output is correct; JSON scrubbing is solid; PDF path unsafe [Confirmed for HTML/JSON; Hypothesis for PDF]**
- Severity: High (HTML/JSON confirmed sound; PDF defect untested).
  - HTML: Jinja2 `autoescape=True` enforced (`html_reporter.py:68-72`) and tested (`tests/test_reporting.py:96-107` — `<script>` payloads are escaped). **Good.** Scrubbing applies to prompt/response excerpts (`html_reporter.py:27-28`).
  - JSON: every string field recursively scrubbed before write (`json_reporter.py:23-26`, `utils/secrets.py:68-76`), tested (`test_reporting.py:72-82`). **Good.** Note scrubbing coverage is pattern-based: OpenAI `sk-…`, `sk-ant-…` (which actually matches through the OpenAI rule first — label precision quirk), `AKIA…`, `Bearer …` (`secrets.py:44-49`); other common forms (`ghp_`, `xoxb-`, `aws_secret_access_key` values, JWTs) are not covered, and only env-var *values* known to the lab are name-redacted.
  - PDF: **untested hypothesis** — reportlab `Paragraph` consumes an XML-ish markup mini-language; `pdf_reporter.py:97-98` injects `scrub(finding.prompt)` / `scrub(finding.response)` without escaping, so model output containing `<`, `&`, or `<script>`-like tags can break rendering or raise a parse error (DoS of the report step, content corruption). Unlike the HTML path, no escaping standard is applied anywhere.
- Recommendation: escape with `xml.sax.saxutils.escape` before `Paragraph(...)`; add tests for `<`/`&` payloads. Broader secret patterns handled in Stage-B P0 (report/log hygiene).

**[F-20] Probe IDs are positional and shift when probes are edited [Confirmed; documented limitation]**
- Severity: Low (will matter for Stage-B stable IDs).
- Evidence: `loader.py:59` — `attack_id=f"{category[:2].upper()}-{index+1:02d}"`; `IMPLEMENTATION_NOTES.md:68-71` honestly documents the drift.
- Recommendation: stable IDs should become content-hashed slugs (`DI-a1b2`) or frozen mappings in Stage-B P0 (“stable test-case IDs”), keeping legacy IDs as aliases.

### 3.7 Suite/YAML and CLI

**[F-21] Installed-package suite resolution depends on CWD [Confirmed statically; Hypothesis for wheel behavior]**
- Severity: Medium.
- Evidence: `config.py:173-186` — `bundled_suites_dir()` returns `repo/suites` only when running from the repo tree; otherwise falls back to `pathlib.Path("suites")` **relative to CWD**. `pyproject.toml:47-51` packages only `rtl*` — `suites/` is not wheel payload. CLI default is `quick.yaml` via `_find_suite` (`cli.py:55,198-201`).
- Impact: after `pip install llm-redteam-lab` and running `rtl scan` anywhere but a repo checkout, the default suite cannot load (`FileNotFoundError`). The Docker path works only because the Dockerfile `COPY`s `suites`.
- Recommendation: ship `suites/` as package data and resolve via `importlib.resources`; explicit `--suite` stays repo-relative.

**[F-23] `docs/reporting.md` names the wrong output files [Confirmed]**
- Severity: Low.
- Evidence: `docs/reporting.md:3-5` — describes `reports/latest.json` / `reports/latest.html`; code writes `report.json` / `report.html` (`runner.py:106-107`).
- Recommendation: fix the doc (or implement `latest.*` if that's the intent).

**[F-24] `rtl scan` docstring references a nonexistent `--scenarios` flag; invalid `--judge-mode` silently coerced [Confirmed]**
- Severity: Low.
- Evidence: `rtl/scenarios/__init__.py:5` (“picked up by ``rtl scan --scenarios``” — no such option exists in `cli.py`); `cli.py:61-66` coerces any invalid `--judge-mode` value to `"auto"` without warning.
- Recommendation: add `--scenarios` override or fix the docstring; validate `--judge-mode` choices with typer.

### 3.8 Framework mapping

**[F-19] ATLAS metadata: tactic/name inaccuracies; several referenced techniques are never actually exercised [Confirmed]**
- Severity: Low-Medium.
- Evidence: `rtl/evaluation/atlas.py:91-97` lists `AML.T0080 AI Agent Context Poisoning` with `tactic: "Execution"`; official ATLAS data (d3fend mirror, gtkcyber mirror, Microsoft's ATLAS-mapping guidance) places T0080 under **Persistence**. `atlas.py:21-26` names `AML.T0024` “Exfiltration via **AI** Inference API”; ATLAS publishes “Exfiltration via **ML** Inference API”. ID *existence* of all 14 entries verified (§2). Additionally: no probe carries `AML.T0051.002` (only the scenario mapping uses it, atlas.py:123) and no probe carries `AML.T0043`/`AML.T0080`/`AML.T0110`, although they are advertised in the registry.
- Impact: crosswalks shown to clients can mis-state tactics; registry promises techniques the library never tests (T0110 tool poisoning is a highlight-grep: `CATEGORY_TO_ATLAS`/`SCENARIO_TO_ATLAS` reference it but zero probe/scenario uses it).
- Recommendation: correct tactic/name fields now; in P2, either implement probes for T0080/T0110/T0043 or annotate them “registry only, not probed”.

**[F-22] No OWASP LLM Top 10 mapping exists [Confirmed gap]**
- Severity: Medium (per mission requirement).
- Evidence: §2 — repo mentions OWASP nowhere; current authoritative edition is **OWASP GenAI LLM Top 10 2026 (v1.0, 2026-08-04)** — LLM01 Prompt Injection … LLM10 Improper Output Handling (https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/, accessed 2026-10-23).
- Recommendation: P3 — add `CATEGORY_TO_OWASP` alongside ATLAS, emit both in reports; imperfect keyword-based coverage should never be claimed as “full coverage”; state the edition + access date in the docs.

### 3.9 Tests, CI, packaging, docs claims

**Claim-by-claim verification (README / suites / docs) [Confirmed]**
- “**110 probes**” — exact match: `grep -c '"name":'` yields 22 direct_injection + 21 indirect_injection + 22 jailbreak + 25 system_prompt_extraction + 20 data_exfiltration = **110** (each PROMPTS entry has exactly one `name`/`atlas`).
- “**≥20 per category**” — holds; minimum is 20 (data_exfiltration = 20, `data_exfiltration.py` — exactly at the floor enforced by `tests/test_probes.py:10-12`).
- “**≥10 original each**” — holds conservatively: **all 110** are `source: "original"` (contact `grep -c '"source": "original"'` → 110/110), so the claim is technically true but the wording (“originals” being a special subset) is slightly inflated marketing.
- “**68 tests**” — `grep -rn "def test_" tests/ | wc -l` = **68** (execution blocked; F-25 environment note).
- “**coverage gate ≥55%**” — the gate exists in config (`pyproject.toml:64-65`) but measured coverage is **unknown** here (blocked). IMPLEMENTATION_NOTES additionally claims “≥80% on config, evaluation, reporting” (`IMPLEMENTATION_NOTES.md:53`) — **there is no per-module coverage gate in pyproject/CI configuration**; the claim is unenforced and unverifiable in this environment. → treat as unsubstantiated until measured.
- “CI matrix 3.11/3.12” — the local environment is Python 3.14.8, which the code likely tolerates (uses `datetime.UTC`, 3.11+ syntax) but is **untested**; pyproject pins nothing above `<3.14`.
- CI references the nonexistent `[pyrit]` extra (see F-03) — `ci.yml:22`.
- README “4 targets”, “3 scenarios (multimodal stub)”, reports via Jinja2+Chart.js — all match the code.

**[F-26] Test-weight imbalance leaves transport/scoring edge paths untested [Confirmed statically]**
- Severity: Medium.
- Evidence: test distribution: `grep -rc "def test_"`: evaluation 30, probes 13, reporting 8, targets 9, runner 3, scenarios 2, engines 1, config 1, utils 1. No tests exist for: retry/backoff logic, `RateLimitedError`/`Retry-After` path, OpenAI/Anthropic/Ollama request+parse behavior (no fakes), `run_scan` judge-temperature wiring, engine run paths, CLI commands, secret-scrub edge cases beyond one env var. The 429/backoff machinery — one of the most failure-prone areas — is untested.
- Recommendation: raise coverage of `targets/base.py` and adapters with `httpx.MockTransport` transports (the `transport` seam already exists, `base.py:92`); wire the existing seam into tests.

**[F-27] Duplicate YAML loaders and other minor structure debt [Confirmed]**
- Severity: Low.
- Evidence: `config.py:163-170` (`yaml.safe_load` without `YAMLError` handling) vs `utils/files.py:40-49` (`load_yaml`, handles errors) — same job, two implementations, one with worse errors. `Scenario`/`ScenarioContext` ABC (`scenarios/base.py:38-50`) is exported but scenarios are plain functions; `slugify`/`load_yaml` are exported but unused internally (`rtl/utils/__init__.py:11,23`).
- Recommendation: consolidate on `load_yaml`; keep the ABC only if P2 introduces class-based scenarios (otherwise remove in a minor release).

---

## 4. Safety, authorization, and secret-handling posture

- Authorization/disclaimer guard is present and honest: `DISCLAIMER.md`, `docs/ethics.md`, README “Ethical use”, per-library disclaimers (`direct_injection.py:14-18` etc.). `mock` target and `examples/` fixtures are fully synthetic (no real third-party domains; all `.test`/`.example`).
- No hardcoded secrets found (`grep` for sk-/token patterns; `.env.example` has empty values). Keys come from env (`env_key`, `base.py:213-215`) and fingerprints are credential-free (`base.py:134-144`).
- Findings content: model/attack text flows into JSON (scrubbed), HTML (autoescaped + scrubbed excerpts), PDF (**unescaped — F-28**), and console logs (only IDs and short truncations — OK).
- The 100-probe payload review found no prompt demanding credential theft against real infrastructure; DE probes reference `.test`/`.example` hosts and synthetic tables. Acceptable as test data.

## 5. Highest-value next increment

**Implement the outcome-state model end-to-end (confirmed/suspected/failed/inconclusive) with evidence capture on every finding, and make the runner record errors instead of dropping probes (F-06).**

Rationale: nearly all the P0/P1 audit findings are downstream of this one gap. It unblocks F-07/F-08/F-09/F-10 (success requires *positive, stored evidence*, not absence-of-refusal), makes F-14/H reports honest about what ran, and is the direct prerequisite for the labeled judge dataset (`eval-judge` needs outcome states to score against). It is a modest, testable change starting at `runner.py:54-84` + `reporting/models.py`, with clear regression tests against the mock target — see `IMPLEMENTATION_ROADMAP.md` Wave 1.

# Architecture

```
                          ┌──────────────────────────────┐
                          │          rtl CLI            │
                          │  (typer, rich, argparse-free)│
                          └─────────────┬────────────────┘
                                        │ ScanOptions (pydantic)
                          ┌─────────────▼────────────────┐
                          │           suite YAML          │
                          │   suites/quick|full|custom    │
                          └─────────────┬────────────────┘
                                        │ resolve()
                          ┌─────────────▼────────────────┐      ┌──────────────────┐
                          │        runner.run_scan        │─────▶│   Target.asend() │
                          │  (async orchestrator)         │      │ openai/anthropic │
                          │                               │      │ ollama / mock    │
                          │  per probe:                   │      └────────┬─────────┘
                          │   judge.evaluate()            │               │ response
                          │   severity.score()            │◀──────────────┘
                          └──────┬───────────────┬────────┘
                                 │               │
                    ┌────────────▼────┐   ┌──────▼──────────────────┐
                    │  Judge          │   │  ScenarioContext        │
                    │  heuristic +    │   │  agent_browsing / rag   │
                    │  LLM-as-judge   │   │  poisoning / multimodal │
                    └─────────────────┘   └─────────────────────────┘
                                        │
                    ScanResult ──▶ ReportMeta + Findings + Summary
                                        │
                    ┌───────────────────┤
                    │ JSON reporter (secret-scrubbed)       report.json
                    │ HTML reporter (Jinja2 + Chart.js)      report.html
                    │ PDF reporter (optional reportlab)      report.pdf
```

## Layers

### 1. `rtl/config.py`
Pydantic models that gate every other layer:

- `TargetConfig` — parses `provider:model` CLI specs, holds transport knobs
  (timeout/retries/temperature), lazily builds a `Target`.
- `Suite` — YAML suite definition (categories, explicit attack IDs, caps,
  scenarios, scenario overrides, engines).
- `JudgeConfig` / `ScanOptions` — resolved runtime options for one scan.

### 2. `rtl/runner.py`
The async orchestrator: builds the target, resolves probes from the suite,
judges each response, computes severity, runs any scenarios, aggregates a
`ScanResult` and writes reports. Every failure path is transient-safe: it
records per-probe errors instead of aborting the scan.

### 3. Target layer (`rtl/targets/`)
`Target` (ABC) owns transport retries, `Retry-After` honouring, exponential
backoff with jitter, classified errors (`RateLimitedError`,
`AuthTargetError`, `TransientTargetError`, `TargetTimeoutError`), and
credential-free `fingerprint()` data for reports.
Concrete targets implement only `_chat_once(prompt, *, temperature, timeout)`.

`MockTarget` replaces provider I/O for tests, CI, and demos — modes:
`cooperative` (compliant), `defensive` (refuses), `leaky` (dumps a fake
system prompt), `echo` (mirrors input).

### 4. Attack layer (`rtl/attacks/`)
`AttackPrompt` is the probe unit. `loader.py` imports each category library,
validates required fields + ATLAS IDs at load time, and generates stable
`attack_id`s (`DI-01`, …). `resolve()` turns suite selections into a flat,
deterministic probe list.

### 5. Evaluation (`rtl/evaluation/`)
- `atlas.py` — the canonical ATLAS technique registry; every probe ID is
  checked against it at load time, so reports can never reference a
  hallucinated technique.
- `judge.py` — heuristic classifier (refusals, deflection, leak markers,
  exfil evidence, base64/key-value heuristics) with an optional LLM layer
  (`mode=auto|llm`) that scores against a fixed rubric.
- `severity.py` — conservative rating: refusals → blocked/low; ambiguous →
  capped at baseline; only confirmed success maps to category-level severity,
  with agentic-scenario boosts.

### 6. Reporting (`rtl/reporting/`)
`ProbeResult` (raw execution record) → `Finding` (report projection with
verbatim prompt, response, repro steps, ATLAS IDs, severity rationale) →
`ScanResult` (aggregated summary). JSON reporter scrubs secrets; HTML reporter
renders a self-contained page (no external assets beyond the Chart.js CDN);
PDF is optional via reportlab.

## Data flow of one probe

```
suite → resolve() → AttackPrompt
target.asend(prompt) → response text
Judge.evaluate(prompt, response, category) → JudgeVerdict
Severity.score(probe, verdict, scenario)   → SeverityResult
ProbeResult.to_finding(...)                 → Finding
ScanResult.aggregate()                      → ScanSummary
write_json / render_html / render_pdf       → report.*
```

## Extending

- Add probes → append dicts in `rtl/attacks/prompts/<category>/` (loader
  validates; `docs/adding-new-attacks.md`).
- Add a target → subclass `Target`, implement `_chat_once`, register in
  `rtl/targets/__init__.py` and in `DEFAULT_MODELS`.
- Add a scenario → module + registry entry + `SCENARIO_TO_ATLAS` row
  (`rtl/scenarios/` + `CONTRIBUTING.md`).
- Add an engine → subclass `Engine`, register in `rtl/engines/__init__.py`.
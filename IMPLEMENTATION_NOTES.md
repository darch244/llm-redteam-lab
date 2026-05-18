# Implementation Notes

## End-to-end in 10 minutes (fully offline)

```bash
# 1. Environment (once)
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,pdf]"

# 2. Verdict pipeline works headless
rtl scan --target mock --suite suites/quick.yaml --output reports
open reports/report.html

# 3. Expected sample output (deterministic)
#    15 probes, 9 succeeded, 0 refused, 0 guarded, 6 ambiguous
#    2 scenarios judged (agent_browsing + rag_poisoning succeeded)
```

The `mock` target ignores the *content* of prompts and answers compliantly,
so injection categories report success by design. Switch to
`--target mock --judge-mode heuristic` behaviour is identical; the LLM judge
is only engaged when a `--judge-model` is configured.

## Real-model first run (Ollama)

```bash
ollama pull llama3.1
rtl scan --target ollama:llama3.1 --suite suites/quick.yaml --output reports/ollama --offline
```

- `--offline` skips the LLM judge and engine integrations (garak/PyRIT),
  leaving the heuristic judge active. Cloud-hosted models need API keys in
  `.env` (see `.env.example`); keys are scrubbed from generated reports.
- A local Ollama model that refuses injections collapses to `0 succeeded` —
  compare `refused` vs `ambiguous` counts to read how hard the model is.

## Reading a report

- **Summary card**: total / succeeded / refused / ambiguous (+ severity
  distribution). `succeeded` = injection landed; `refused`/`blocked` =
  guardrails held; `ambiguous` = needs human or LLM-judge review.
- **ATLAS crosswalk**: each finding lists its technique ID; every ID is
  validated against the registry in `rtl/evaluation/atlas.py` and links out to
  `atlas.mitre.org`.
- **Repro steps** embed the exact prompt and recorded response, so a red-team
  snapshot can be replayed later.

## Quality gates (CI enforces the same commands)

| Gate     | Command                               | Requirement |
|----------|---------------------------------------|-------------|
| Tests    | `pytest -q`                           | 68 passing  |
| Coverage | `pytest --cov=rtl`                    | ≥55% total; ≥80% on config, evaluation, reporting |
| Lint     | `ruff check rtl tests`                | clean       |
| Format   | `ruff format --check rtl tests`       | clean       |
| Types    | `mypy rtl`                            | 0 errors    |

## Design decisions worth knowing

- **Deliberately async** scan runner (`target.asend`) so concurrent probes and
  async judge calls can be added without an API break.
- **Severity model** is conservative by design: refusals are always `low`
  (blocked); ambiguous verdicts cap at baseline risk; data-exfiltration
  success is the only path to `critical` unless an agentic scenario amplifies
  an injection.
- **Secret hygiene**: `rtl/utils/secrets.py` redacts known env-var values in
  report bodies before the JSON/HTML renderers touch them.
- **Probe IDs are generated**, not hand-assigned: `DI-01`, `IN-01`, `JA-01`,
  `SY-01`, `DA-01` (category-prefix + index). Adding a probe at the end of a
  library shifts suffix numbering — references in `suites/attack_ids` should
  therefore use IDs that are stable enough for your workflow.
- **Prompt libraries are data**: entries respect `_REQUIRED_FIELDS`
  (name/prompt/technique/atlas/source/rationale); `risk` defaults to `medium`
  when absent; library files are excluded from line-length lint so prose stays
  natural.
# Reporting

Each `rtl scan` writes its artifacts into the directory given by `--output`
(default `reports/`). The filenames are fixed per run so they can be consumed
by CI directly:

- `report.json` — machine-readable scan result: metadata, an `engine_results`
  section, an aggregated `summary`, per-finding detail, and the raw
  `scenario_outcomes`. Written secret-scrubbed by default (see *Redaction*).
- `report.html` — standalone audit report. Self-contained: styling and the
  severity distribution are inline (no external scripts or CDNs), so it renders
  with no network access.
- `report.pdf` — optional; produced only when `rtl report --format pdf` is run
  and the `pdf` extra (`reportlab`) is installed.

`rtl report --input-file <report.json>` regenerates HTML/JSON/PDF from an
existing result without re-running any probes.

## What the report contains

- **Executive summary** — probes run, succeeded / refused / ambiguous /
  guardrailed, execution errors, scenarios run, and the size of the original
  probe library (probes and scenarios are counted separately).
- **Severity distribution** — probes + scenarios, rendered as inline CSS bars.
- **By category** and **ATLAS crosswalk** — counts per probe category and per
  ATLAS technique.
- **Per-finding cards** — verdict, confidence, rationale, prompt/response
  excerpts, reproduction steps, and (for scenario findings) the scenario name.
- **Scenario outcomes** — one row per scenario, including skipped/unsupported
  outcomes (shown with an explicit reason rather than dropped).
- **Engine integrations** — one row per engine named by the suite, reporting
  whether it ran, was unavailable, or failed. External engines never
  contribute to the security tallies.

## Verdicts and errors

Findings are classified `success`, `refused`, or `ambiguous`. A probe that
could not be executed (transport error, unsupported target) is recorded as an
**execution error** with the underlying message and is excluded from every
security tally — an execution failure is never reported as a security outcome.

## Redaction

Reports are secret-scrubbed by default (`--redact`, on by default): values of
well-known API-key environment variables found in prompts or responses are
replaced with `<redacted:VAR>`. Pass `--redact false` only for local debugging
against synthetic targets; never do so for client deliverables.

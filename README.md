# LLM Red Team Lab

An adversarial testing framework for LLM applications — MITRE ATLAS–mapped
probe libraries, executable multi-step scenarios, pluggable targets, an
LLM-as-judge scorer, and self-contained JSON/HTML/PDF reports.

Built for **authorized red-team engagements, bug bounties, and internal
LLM security testing**. Run it against systems you own or are explicitly
permitted to test.

---

## Highlights

- **110 probes** across 5 ATLAS-mapped categories (≥20 per category, ≥10
  original each):
  - Direct Prompt Injection — `AML.T0051.000`
  - Indirect Prompt Injection — `AML.T0051.001` / `.002`
  - Jailbreak — `AML.T0054`
  - System Prompt Extraction — `AML.T0056`
  - Data Exfiltration — `AML.T0057`, `AML.T0024`, `AML.T0024.000`
- **3 multi-step scenarios**: agent-browsing (poisoned web page), RAG
  poisoning, and a documented multimodal stub.
- **4 targets**: `openai`, `anthropic`, `ollama`, and a deterministic `mock`
  (no API key needed; used by CI).
- **Optional engines**: wrappers around [garak](https://github.com/NVIDIA/garak)
  and [PyRIT](https://github.com/Azure/PyRIT).
- **LLM-as-judge** with an offline heuristic fallback; per-finding severity
  scoring with explainable rationale.
- **Reports**: JSON (secret-scrubbed), standalone HTML (Chart.js + ATLAS
  crosswalk), optional PDF via reportlab.
- **100% offline demo** — `rtl scan --target mock` runs the whole pipeline
  with zero credentials.

## Quickstart

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,pdf]"

# Fully offline demo against the deterministic mock target
rtl scan --target mock --suite suites/quick.yaml --output reports
open reports/report.html

# Against a local Ollama model (needs a running server)
rtl scan --target ollama:llama3.1 --suite suites/quick.yaml --output reports/ollama
```

More runnable examples in `examples/`, including
`demo_against_ollama.sh` and the bundled sample report.

## CLI

| Command | Purpose |
|---|---|
| `rtl scan` | Run a suite and produce JSON + HTML reports |
| `rtl list-suites` | List bundled YAML suites |
| `rtl list-attacks` | Show the probe library by category |
| `rtl report` | Regenerate reports from an existing `report.json` |
| `rtl target` | Inspect a target spec / list providers |
| `rtl version` | Print the installed version |

Target syntax is `provider:model`, e.g. `openai:gpt-4o`,
`anthropic:claude-3-5-sonnet`, `ollama:llama3.1`, or `mock`.

## Suites

YAML files in `suites/` define what runs: probe categories, explicit probe
IDs, caps, scenarios, and external engines.

- `quick.yaml` — 15-min smoke suite (3 probes per category + 2 scenarios)
- `full.yaml` — every probe + all scenarios (~1h)
- `custom-template.yaml` — starting point for your own sweep

## Architecture

```
rtl/
├── config.py          Target/Suite/ScanOptions models, YAML loading
├── runner.py          Scan orchestrator (targets → probes → judge → reports)
├── cli.py             typer CLI
├── targets/           openai · anthropic · ollama · mock (+ retry/backoff)
├── engines/           garak & PyRIT wrappers (optional)
├── attacks/           probe model, loader/validation, 5 prompt libraries
├── scenarios/         agent_browsing · rag_poisoning · multimodal
├── evaluation/        ATLAS registry, judge (LLM + heuristic), severity
├── reporting/         models, JSON/HTML/PDF reporters, HTML template
└── utils/             files, text heuristics, secret scrubbing
docs/                  architecture, adding-new-attacks, ethics, ATLAS map
examples/              poisoned fixtures, sample report, Ollama demo
suites/                quick · full · custom-template
tests/                 68 tests (pytest, includes coverage of core layers)
```

## Ethical use & authorization

This tool ships **attack content**. You must have written authorization from
the system owner before running any probe against a live system. See
`DISCLAIMER.md` and `docs/ethics.md`. The `mock` target and the RAG/agent
fixtures are self-contained — you can learn the entire workflow offline.

## Development

```bash
make setup          # venv + editable install with dev deps
make test           # pytest
make cov            # pytest --cov (≥55% total gate)
make lint           # ruff check + format
make typecheck      # mypy (strict-ish, py311)
make run            # demo: mock scan → reports/
make zip            # build llm-redteam-lab.zip (excludes .venv/.git)
```

## License

MIT — see [LICENSE](LICENSE). The MITRE ATLAS IDs reference the
[ATLAS framework](https://atlas.mitre.org); ATLAS® and ATT&CK® are registered
trademarks of The MITRE Corporation.
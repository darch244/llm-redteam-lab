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
- **Adaptive Planning Engine**: Stateful adversarial planner (`--planner heuristic`) with
  multi-dimensional budget enforcement (probes, turns, prompt/output tokens, cost, time),
  evidence-driven reframing on refusals, and confirmation branching.
- **Deterministic Offline Replay**: Audit and reproduce attack trajectories offline using
  cryptographically hashed manifests (`rtl replay --manifest report.json`).
- **Bounded Agent & Tool Runtime**: Pre-execution validation and execution sandboxing for
  agent tool-use and function-calling security audits.
- **Multi-step scenarios**: agent-browsing (poisoned web page), RAG
  poisoning, memory poisoning, tool poisoning, conversation jailbreak, and a documented multimodal stub.
- **4 targets**: `openai`, `anthropic`, `ollama`, and a deterministic `mock`
  (no API key needed; used by CI).
- **Optional engines**: wrappers around [garak](https://github.com/NVIDIA/garak)
  and [PyRIT](https://github.com/Azure/PyRIT).
- **LLM-as-judge** with an offline heuristic fallback; per-finding severity
  scoring with explainable rationale.
- **Complete Multi-Format Reports**:
  - Standalone HTML with CSS charts & Adaptive Plan Trace (no external assets).
  - SARIF v2.1.0 for GitHub Advanced Security & CI/CD pipeline code scanning.
  - GitHub-Flavored Markdown executive briefs for PR reviews and documentation.
  - Machine-readable JSON with secret scrubbing.
  - Optional PDF export via ReportLab.
- **100% offline demo** — `rtl scan --target mock` runs the whole pipeline
  with zero credentials.

## Quickstart

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,pdf]"

# Fully offline demo against the deterministic mock target
rtl scan --target mock --suite suites/quick.yaml --output reports
open reports/report.html

# Run adaptive red-teaming with stateful heuristic planning
rtl scan --target mock --suite suites/quick.yaml --planner heuristic --output reports/adaptive

# Replay a recorded scan trajectory offline with bit-exact determinism
rtl replay --manifest reports/adaptive/report.json --output reports/replay

# Run detection quality benchmarks against versioned golden datasets
rtl benchmark --version 3

# Against a local Ollama model (needs a running server)
rtl scan --target ollama:llama3.1 --suite suites/quick.yaml --output reports/ollama
```

More runnable examples in `rtl/examples/`, including
`demo_against_ollama.sh` and the bundled sample report.

## CLI

| Command | Purpose |
|---|---|
| `rtl scan` | Run a suite and produce JSON, HTML, SARIF, and Markdown reports (`--planner ev_adaptive`) |
| `rtl campaign` | Multi-target comparative campaign orchestration with checkpoint resume |
| `rtl profile` | Inspect target security capability envelope and diagnostic probe telemetry |
| `rtl evidence` | Cryptographic evidence DAG verification and Graphviz DOT export |
| `rtl diff` | Security regression and differential comparison between scans |
| `rtl replay` | Deterministically replay a recorded scan manifest offline |
| `rtl benchmark` | Benchmark detection quality against versioned golden datasets |
| `rtl list-suites` | List bundled YAML suites |
| `rtl list-attacks` | Show the probe library by category |
| `rtl report` | Regenerate reports (HTML, JSON, PDF, SARIF, Markdown) from `report.json` |
| `rtl target` | Inspect a target spec / list providers |
| `rtl version` | Print the installed version |

Target syntax is `provider:model`, e.g. `openai:gpt-4o`,
`anthropic:claude-3-5-sonnet`, `ollama:llama3.1`, or `mock`.

## Suites

YAML files in `rtl/suites/` define what runs: probe categories, explicit probe
IDs, caps, scenarios, and external engines. They ship inside the package, so
`--suite quick.yaml` (or `--suite suites/quick.yaml`) works from any directory.

- `quick.yaml` — 15-min smoke suite (3 probes per category + 2 scenarios)
- `full.yaml` — every probe + all scenarios (~1h)
- `custom-template.yaml` — starting point for your own sweep

## Architecture

```
rtl/
├── config.py          Target/Suite/ScanOptions models, budget limits, YAML loading
├── runner.py          Scan orchestrator (targets → planning → judge → reports)
├── cli.py             typer CLI (scan, replay, benchmark, report, target)
├── planning/          AdaptiveEngine, BudgetLedger, HeuristicPlanner, ReplayTarget
├── agents/            AgentRuntime with turn and tool call bounding
├── tools/             ToolExecutor, multi-protocol parser, sandboxed simulation
├── targets/           openai · anthropic · ollama · mock · replay (+ retry/backoff)
├── engines/           garak & PyRIT wrappers (optional)
├── attacks/           probe model, loader/validation, 5 prompt libraries
├── scenarios/         agent_browsing · rag_poisoning · tool_poisoning · memory_poisoning
├── evaluation/        ATLAS registry, judge (LLM + heuristic), verdict policy, harness
├── reporting/         models, HTML/JSON/PDF/SARIF/Markdown reporters
├── suites/            quick · full · custom-template (bundled in the package)
├── examples/          poisoned fixtures, sample report, Ollama demo (bundled)
└── utils/             files, text heuristics, secret scrubbing
docs/                  architecture, adding-new-attacks, ethics, ATLAS map
tests/                 477 tests (pytest, comprehensive coverage across all layers)
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
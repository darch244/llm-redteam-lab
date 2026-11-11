# LLM Red Team Lab

An adversarial testing framework for LLM applications, featuring MITRE ATLAS–mapped probe libraries, autonomous adaptive attack planning, cryptographic evidence verification, executable multi-step agent scenarios, pluggable targets, and self-contained multi-format reports (JSON, HTML, SARIF, Markdown, PDF).

Built for authorized red-team engagements, bug bounty research within program scope, and internal LLM security evaluation. Only test systems you own or have explicit permission to assess.

## Highlights

- **110 adversarial probes** across 5 ATLAS-mapped categories (≥20 per category, ≥10 original each):
  - Direct Prompt Injection — `AML.T0051.000`
  - Indirect Prompt Injection — `AML.T0051.001` / `.002`
  - Jailbreak — `AML.T0054`
  - System Prompt Extraction — `AML.T0056`
  - Data Exfiltration — `AML.T0057`, `AML.T0024`, `AML.T0024.000`
- **Autonomous Adaptive Planning Engine**: Stateful Expected Value planner (`--planner ev_adaptive`) with multi-dimensional budget enforcement (probes, turns, prompt/output tokens, cost, time), dynamic mutation, and signal-driven branch refinement.
- **Cryptographic Evidence DAG & Confirmation Engine**: Verifiable Merkle DAG tracking attack-to-finding lineage with SHA-256 integrity checks, four-tier confirmation policy (*Suspected $\to$ Corroborated $\to$ Confirmed $\to$ Disproven*), and Graphviz DOT export.
- **Target Capability Profiler**: Active and passive capability detection across 16 dimensions (function calling, tools, RAG, memory, structured JSON) with strict evidence gating ("never infer capabilities without evidence").
- **Deterministic Offline Replay**: Audit and reproduce attack trajectories offline with bit-exact determinism and budget enforcement (`rtl replay --manifest report.json --max-probes N`).
- **Multi-Target Comparative Campaigns & Differential Analysis**: Multi-target evaluations (`rtl campaign`) with per-target budget isolation, checkpoint resume, and target-aware regression diffing (`rtl diff`).
- **Bounded Agent & Tool Runtime**: Pre-execution validation, schema enforcement, payload bounds, and execution sandboxing for simulated tool execution (`rtl/tools/`).
- **Multi-step scenarios**: Agent browsing (poisoned web content), RAG poisoning, memory poisoning, tool poisoning, conversation jailbreak, and a documented multimodal stub.
- **Pluggable targets**: `openai`, `anthropic`, `ollama`, and deterministic `mock` (no API key needed; used by CI and offline testing).
- **Optional external engines**: Integration wrappers around [garak](https://github.com/NVIDIA/garak) and [PyRIT](https://github.com/Azure/PyRIT).
- **Evidence-based evaluation & judge robustness**: LLM-as-judge with heuristic fallback, prompt-injection resistant judging, structured outcome models, and explainable severity rationales.
- **Safer error handling & secret scrubbing**: Scrubbing of sensitive values and credentials in supported logs and report data.
- **Comprehensive Multi-Format Reports**:
  - Standalone HTML with interactive charts, ATLAS crosswalk, and plan traces (no external CDN dependencies).
  - SARIF v2.1.0 for GitHub Advanced Security and CI/CD code scanning.
  - GitHub-Flavored Markdown executive briefs for PR reviews.
  - Machine-readable JSON with full evidence metadata.
  - Optional PDF export via ReportLab.
- **Offline-First Workflow**: Run scans, campaigns, and deterministic replay against deterministic mock targets without API credentials or network access.
  Hosted providers such as OpenAI and Anthropic require network access and valid credentials.

## Project Status

The framework is under active development. Benchmark tooling and versioned
golden datasets are available, while human-reviewed judge-accuracy validation
and independent comparisons with other evaluation tools are still in progress.
Do not interpret probe counts or benchmark execution as independently validated
attack-success or detection-accuracy rates.

## Quickstart

### Requirements

- Python 3.11 or 3.12
- `pip` and `venv`
- API credentials only when testing external hosted models

### Install

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[dev,pdf]"
```

### Run the Offline Demo

```bash
# Basic scan against deterministic mock target
rtl scan --target mock --suite suites/quick.yaml --output reports

# Autonomous adaptive scan with Expected Value planner and per-target budget
rtl scan --target mock:cooperative --suite suites/quick.yaml --planner ev_adaptive --budget-probes 5 --output reports/adaptive

# Deterministically replay recorded scan manifest offline
rtl replay --manifest reports/adaptive/report.json --max-probes 5 --output reports/replay

# Run detection quality benchmarks against versioned golden datasets
rtl benchmark --version 3
```

Open `reports/report.html` in your browser to inspect the interactive report.

### Run Against a Local Ollama Model

Start Ollama and ensure the target model is available locally, then run:

```bash
rtl scan --target ollama:llama3.1 --suite suites/quick.yaml --output reports/ollama
```

More runnable examples are available in `examples/`, including `demo_against_ollama.sh`.

## CLI Commands

| Command | Purpose |
|---|---|
| `rtl scan` | Run an attack suite against a target and produce multi-format reports (`--planner ev_adaptive`) |
| `rtl campaign` | Multi-target comparative campaign orchestration with differential analysis and checkpoint resume |
| `rtl profile` | Discover and inspect target capability envelope (`--probe` / `--no-probe`) |
| `rtl evidence` | Cryptographic evidence DAG verification and Graphviz DOT export (`--export-dot`) |
| `rtl diff` | Security regression diff (same target) or architectural divergence comparison (cross target) |
| `rtl replay` | Deterministically replay recorded scan manifests offline with optional `--max-probes` budget |
| `rtl benchmark` | Benchmark detection quality against versioned golden datasets (`--version 1/2/3`) |
| `rtl list-suites` | List bundled YAML suites |
| `rtl list-attacks` | Show probe library categorized with ATLAS IDs |
| `rtl report` | Regenerate reports (HTML, JSON, PDF, SARIF, Markdown) from an existing `report.json` |
| `rtl target` | Inspect target specifications or list supported provider defaults |
| `rtl version` | Print the installed version |

Target syntax uses `provider:model`, for example:
- `openai:gpt-4o`
- `anthropic:claude-3-5-sonnet`
- `ollama:llama3.1`
- `mock:cooperative`, `mock:defensive`, `mock:leaky`, `mock:echo`

## Suites

YAML files in `suites/` (and bundled in `rtl/suites/`) configure probe selection, categories, execution caps, scenarios, and optional external engines:

- `quick.yaml` — Fast smoke-test suite for CI validation and rapid checks.
- `full.yaml` — Comprehensive scan covering all probes and multi-step scenarios.
- `custom-template.yaml` — Starting point for customized organizational security suites.

## Evaluation & Confirmation

The evaluation pipeline combines model-based judging with an offline heuristic fallback and prompt-injection-resistant judge defenses. Human-reviewed validation of judge accuracy is still in progress:

- **Evidence Graph**: Every probe execution, tool call, and response excerpt is tracked in a cryptographic DAG with SHA-256 node hashes.
- **Evidence Confirmation (separate from judge labels)**:
  - `SUSPICIOUS`: Single anomalous output or partial match.
  - `CORROBORATED`: Multi-signal evidence (e.g. tool execution + canary hint).
  - `CONFIRMED`: Verified compromise (assertive canary extraction or reproducible exploitation).
  - `DISPROVEN`: Initial suspicion refuted by targeted verification probes.
- **Explainable Severity**: MITRE ATLAS taxonomy mapping with explainable reasoning and remediation guidance.

## Reporting & Secret Handling

The reporting layer generates:
- **JSON**: Complete machine-readable scan artifacts and replay manifests.
- **HTML**: Standalone, interactive visual reports with CSS charts and ATLAS crosswalks.
- **SARIF**: Static Analysis Results Interchange Format (v2.1.0) for GitHub Advanced Security.
- **Markdown**: Executive briefs formatted with GitHub alert callouts.
- **PDF**: Executive presentation reports generated via ReportLab.

Secret scrubbing is applied across reports and log outputs to redact API keys, tokens, and sensitive system prompt excerpts.

## Architecture

```text
rtl/
├── config.py          Target, Suite, BudgetLimits, and ScanOptions configuration
├── runner.py          Scan orchestration and outcome collection
├── cli.py             Typer CLI (scan, campaign, profile, evidence, diff, replay, etc.)
├── core/              Cryptographic EvidenceGraph and ConfirmationEngine
├── planning/          AdaptiveEngine, Expected Value Planner, BudgetLedger, ReplayTarget
├── profiler/          ActiveProfiler and PassiveProfiler capability detectors
├── memory/            AttackMemoryStore tracking successful techniques and target resistance
├── mutation/          MutationEngine (base64, academic, roleplay, cognitive overload)
├── campaign/          CampaignManager, differential testing, and checkpoint state
├── agents/            AgentRuntime with turn, timeout, and tool call bounds
├── tools/             ToolExecutor, multi-protocol tool parser, sandboxed simulation
├── targets/           OpenAI, Anthropic, Ollama, deterministic Mock, and Replay targets
├── engines/           Optional garak and PyRIT integration wrappers
├── attacks/           Probe models, loader, validation, and prompt libraries
├── scenarios/         Agent browsing, RAG poisoning, tool poisoning, memory poisoning
├── evaluation/        ATLAS registry, Judge (LLM + heuristic), VerdictPolicy, Harness
├── reporting/         HTML, JSON, PDF, SARIF, Markdown reporters, and diffing engine
├── suites/            Bundled YAML scan suites
├── examples/          Demonstrations, poisoned fixtures, and sample reports
└── utils/             Text heuristics, atomic file operations, and secret scrubbing

docs/                  Architecture, technical audit, specifications, ethics, and roadmap
tests/                 Automated test suite (pytest; coverage is measured in CI and local development).
```

## Development

Install development dependencies:

```bash
pip install -e ".[dev,pdf]"
```

Run tests:

```bash
pytest -q
```

Run linting:

```bash
ruff check .
ruff format --check .
```

Run type checking:

```bash
mypy rtl
```

## Documentation

Consult the repository documentation for architecture, threat mapping, specifications, and audit notes:

- [Implementation Notes](IMPLEMENTATION_NOTES.md)
- [Contributing Guide](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)
- [Disclaimer](DISCLAIMER.md)
- [MITRE ATLAS mapping and specifications](docs/)
- [Technical Audit](docs/audit/TECHNICAL_AUDIT.md)
- [Implementation Roadmap](docs/audit/IMPLEMENTATION_ROADMAP.md)

Audit documents describe the scope and findings of the corresponding review; they should not be interpreted as independent certification or proof that all security issues have been resolved.

## Ethical Use and Authorization

This framework contains adversarial prompts and testing scenarios. Obtain explicit authorization from the system owner before running probes against live systems, and follow applicable rules of engagement, program scope, and data-handling requirements.

The mock target and local fixtures support offline experimentation without sending probes to external services. Do not use the framework to access data, systems, or accounts without permission.

## License

MIT — see [LICENSE](LICENSE).

MITRE ATLAS identifiers are referenced for threat classification. MITRE ATLAS® and ATT&CK® are trademarks of The MITRE Corporation.

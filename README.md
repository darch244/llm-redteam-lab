# LLM Red Team Lab

An adversarial testing framework for LLM applications, featuring MITRE ATLAS–mapped probe libraries, executable multi-step scenarios, pluggable targets, evidence-based evaluation, and self-contained JSON, HTML, and PDF reports.

Built for authorized red-team engagements, bug bounty research within program scope, and internal LLM security testing. Only test systems you own or have explicit permission to assess.

## Highlights

- **110 adversarial probes** across five ATLAS-mapped categories:
  - Direct Prompt Injection — AML.T0051.000
  - Indirect Prompt Injection — AML.T0051.001 / .002
  - Jailbreak — AML.T0054
  - System Prompt Extraction — AML.T0056
  - Data Exfiltration — AML.T0057, AML.T0024, AML.T0024.000
- **Multi-step scenarios** for agent browsing with poisoned web content and RAG poisoning, plus a documented multimodal stub.
- **Pluggable targets** for OpenAI, Anthropic, Ollama, and a deterministic mock target for offline testing.
- **Optional external engines** with wrappers for garak and PyRIT.
- **Evidence-based evaluation** combining LLM-as-judge assessment with an offline heuristic fallback, structured outcomes, and finding-level severity with explainable rationale.
- **Safer error handling and reporting**, including secret scrubbing for sensitive values in supported logs and report data.
- **Multiple report formats:** JSON, standalone HTML with charts and an ATLAS crosswalk, and optional PDF generation using ReportLab.
- **Offline-first workflow:** run the mock target without API credentials to exercise the core scan pipeline.
- **Automated quality checks:** tests, linting, type checking, and an offline demo smoke test through GitHub Actions.

## Quickstart

### Requirements

- Python 3.11 or 3.12
- pip and `venv`
- API credentials only when testing external hosted models

### Install

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[dev,pdf]"
```

### Run the offline demo

```bash
rtl scan --target mock --suite suites/quick.yaml --output reports
```

The mock target does not require an API key. The scan generates reports in the output directory.

Open `reports/report.html` in your browser to inspect the HTML report.

### Run against a local Ollama model

Start Ollama and make sure the requested model is available locally, then run:

```bash
rtl scan --target ollama:llama3.1 --suite suites/quick.yaml --output reports/ollama
```

More runnable examples are available in `examples/`, including the Ollama demo.

## CLI

| Command | Purpose |
|---|---|
| `rtl scan` | Run a probe suite and generate reports |
| `rtl list-suites` | List bundled YAML suites |
| `rtl list-attacks` | List probes by category |
| `rtl report` | Regenerate reports from an existing `report.json` |
| `rtl target` | Inspect target specifications or available providers |
| `rtl version` | Print the installed version |

Target syntax uses `provider:model`, for example:

- `openai:gpt-4o`
- `anthropic:claude-3-5-sonnet`
- `ollama:llama3.1`
- `mock`

Provider availability and model names depend on your installed configuration and provider access.

## Suites

YAML files in `suites/` configure probe selection, categories, execution caps, scenarios, and optional external engines.

- `quick.yaml` — a smaller smoke-test suite for fast validation.
- `full.yaml` — a broader run covering the available probes and scenarios.
- `custom-template.yaml` — a starting point for custom test configurations.

Actual run time depends on the selected target, suite, model latency, and configuration.

## Evaluation and Evidence

The evaluation pipeline combines model-based judging, when configured, with an offline heuristic fallback.

Findings can include structured outcomes, evidence, severity, and explanatory rationale. The objective is to make results easier to interpret and investigate rather than relying solely on a single aggregate score.

Evaluation results are automated assessments, not proof that a system is secure or vulnerable. Review the underlying evidence and reproduce important findings before making security decisions.

## Reporting and Secret Handling

The reporting layer supports:

- **JSON** for structured scan results and downstream processing.
- **HTML** for interactive, standalone report viewing.
- **PDF** as an optional output format through ReportLab.

The project includes secret-scrubbing utilities and safer error-handling paths intended to reduce accidental exposure of sensitive values in supported logs and report output.

Secret scrubbing is a defense-in-depth measure, not a guarantee that every secret or sensitive value will be detected. Review reports and logs before sharing them.

## Architecture

```text
rtl/
├── config.py          Target and suite configuration
├── runner.py          Scan orchestration and outcome collection
├── cli.py             Command-line interface
├── targets/           OpenAI, Anthropic, Ollama, and mock targets
├── engines/           Optional garak and PyRIT integrations
├── attacks/           Probe models, loaders, and prompt libraries
├── scenarios/         Agent browsing, RAG poisoning, multimodal stub
├── evaluation/        Judge, heuristic evaluation, ATLAS mapping
├── reporting/         JSON, HTML, and optional PDF reports
└── utils/             Text utilities and secret scrubbing

docs/                  Architecture, ethics, specifications, and audit notes
examples/              Demonstrations and sample fixtures
suites/                Bundled YAML scan suites
tests/                 Automated test suite
```

## Development

Install development dependencies:

```bash
pip install -e ".[dev,pdf]"
```

Run the tests:

```bash
pytest -q
```

Run linting:

```bash
ruff check rtl tests
ruff format --check rtl tests
```

Run type checking:

```bash
mypy rtl
```

Run the offline demo:

```bash
rtl scan --target mock --suite suites/quick.yaml --output reports
```

The repository's GitHub Actions workflow runs automated quality checks, tests with coverage, and an offline demo smoke test across its configured Python versions.

## Documentation

Consult the repository documentation for architecture, probe development, threat mapping, and ethical testing guidance.

- [Implementation Notes](IMPLEMENTATION_NOTES.md)
- [Contributing Guide](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)
- [Disclaimer](DISCLAIMER.md)
- [MITRE ATLAS mapping and specifications](docs/)
- [Technical Audit](docs/audit/TECHNICAL_AUDIT.md)
- [Implementation Roadmap](docs/audit/IMPLEMENTATION_ROADMAP.md)

Audit documents describe the scope and findings of the corresponding review; they should not be interpreted as independent certification or proof that all security issues have been resolved.

## Ethical Use and Authorization

This framework contains adversarial prompts and testing scenarios. Obtain explicit authorization from the system owner before running probes against live systems, and follow the applicable rules of engagement, program scope, and data-handling requirements.

The mock target and local fixtures support offline experimentation without sending probes to external services.

Do not use the framework to access data, systems, or accounts without permission.

## License

MIT — see [LICENSE](LICENSE).

MITRE ATLAS identifiers are referenced for threat classification. MITRE ATLAS® and ATT&CK® are trademarks of The MITRE Corporation.

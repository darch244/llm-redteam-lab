# Contributing

Thanks for improving the lab. This project exists to make adversarial LLM
testing easier — but it carries real-world risk, so review discipline matters.

## Ground rules

- **Authorized only.** Code, prompts, and docs must not steer users toward
  testing systems without authorization. If a new probe's rationale reads like
  it expects an unauthorized victim, it will be rejected.
- **Keep the offline demo working.** Every PR must keep `rtl scan --target
  mock --suite suites/quick.yaml` green with zero credentials.
- **ATLAS-mapped.** Every probe references a validated ATLAS ID from
  `rtl/evaluation/atlas.py` (the loader enforces this at import time).
- **No secrets.** Never commit API keys, tokens, or user data. Report content
  must pass `rtl.utils.secrets.scrub`.

## Development setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,pdf]"
make test lint typecheck cov
```

## Adding a probe

1. Append a dict to the relevant library in `rtl/attacks/prompts/<category>/`.
   Required fields: `name`, `prompt`, `technique`, `atlas`, `source`,
   `rationale` (optional: `risk`, `tags`).
2. Run `python -c "from rtl.attacks import load_all; load_all()"` — the loader
   validates IDs, required fields, and non-empty prompts.
3. Add/update a unit test in `tests/test_probes.py` if the probe exercises new
   behaviour. Full recipe in `docs/adding-new-attacks.md`.

## Adding a scenario

1. Create `rtl/scenarios/<name>/scenario.py` exposing `run_<name>(target, *,
   config=None, out_dir=None) -> list[ProbeResult]` plus a `README.md`.
2. Register it in `rtl/scenarios/__init__.py` and in `SCENARIO_TO_ATLAS`
   (`rtl/evaluation/atlas.py`).
3. Reference any fixture under `examples/` and cover it with a test in
   `tests/test_scenarios.py`.

## Before submitting

- `make test` — all tests pass
- `make lint` — ruff clean
- `make typecheck` — mypy clean
- `make cov` — coverage gates hold
- Changelog substance (bug, feature, or doc) in the PR description
.PHONY: setup test cov lint typecheck run report clean demo zip

PY ?= python
MODEL ?= llama3.1

## Bootstrap a virtualenv and install runtime + dev deps.
setup:
	$(PY) -m venv .venv
	./.venv/bin/python -m pip install --upgrade pip
	./.venv/bin/python -m pip install -e ".[dev,pdf]"

## Run the test suite.
test:
	./.venv/bin/python -m pytest -q

## Run tests with coverage report (fails under 55% total).
cov:
	./.venv/bin/python -m pytest --cov=rtl --cov-report=term-missing -q

## Lint with ruff.
lint:
	./.venv/bin/ruff check rtl tests
	./.venv/bin/ruff format --check rtl tests

## Format with ruff.
format:
	./.venv/bin/ruff format rtl tests

## Static type-check with mypy.
typecheck:
	./.venv/bin/mypy rtl

## Quick smoke scan against the offline mock target (no API needed).
run:
	./.venv/bin/rtl scan --target mock --suite suites/quick.yaml --output reports

## Scan a local Ollama model (requires a running Ollama server).
ollama:
	./.venv/bin/rtl scan --target ollama:$(MODEL) --suite suites/quick.yaml --output reports/ollama-$(MODEL) --offline

## Open the last generated report.
report:
	@test -f reports/report.html && xdg-open reports/report.html || echo "run 'make run' first"

## Clean generated artifacts.
clean:
	rm -rf reports .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage

## Build the distribution ZIP (excludes .venv and .git).
zip:
	cd .. && zip -r llm-redteam-lab.zip llm-redteam-lab -x '*/.venv/*' -x '*/.git/*' -x '*/__pycache__/*'

demo: run
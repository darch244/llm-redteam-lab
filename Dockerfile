# Self-contained lab: Ollama + CLI.
#
#   docker compose up --build -d
#   docker compose exec lab rtl scan --target ollama:llama3.1 \
#       --suite suites/quick.yaml --output /reports --offline
FROM python:3.12-slim

WORKDIR /opt/llm-redteam-lab

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Optional external engines (garak/PyRIT) add heavy deps; keep them optional.
COPY pyproject.toml README.md LICENSE ./
COPY rtl ./rtl
COPY suites ./suites
COPY examples ./examples
COPY docs ./docs

RUN pip install .

# Volume for generated reports.
VOLUME /reports

ENTRYPOINT ["rtl"]
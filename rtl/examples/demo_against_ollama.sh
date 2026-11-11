#!/usr/bin/env bash
# Run the full continuous-scoring sweep against a local Ollama model.
#
# Requires:  python 3.11+, a running Ollama server, model pulled.
#
#   make setup                 # one-time
#   ./examples/demo_against_ollama.sh llama3.1
set -euo pipefail

MODEL="${1:-llama3.1}"
SUITE="${2:-quick}"
OUT="reports/ollama-${MODEL}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT"

echo "==> [1/4] Pulling model (if missing)…"
ollama pull "$MODEL"

echo "==> [2/4] Running suite '${SUITE}' against ollama:${MODEL}…"
python -m rtl scan --target "ollama:${MODEL}" --suite "suites/${SUITE}.yaml" \
    --output "${OUT}" --offline

echo "==> [3/4] Summarising…"
python - "$OUT" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1]) / "report.json"
data = json.loads(p.read_text())
s = data["summary"]
print(f"probes={s['total']}  succeeded={s['succeeded']}  "
      f"refused={s['refused']}  blocked={s['blocked']}  ambiguous={s['ambiguous']}")
PY

echo "==> [4/4] Open the report in a browser:"
echo "    ${OUT}/report.html"
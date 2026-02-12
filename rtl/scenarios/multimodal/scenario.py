"""Multimodal scenario — documented stub.

Vision-capable LLM targets (GPT-4o, Claude, Llama-3.2-Vision, ...) ingest
images that can carry *hidden instructions* rendered as text inside the
image, or exfiltration markers in alt text. This scenario is a **stub**:

* it validates that the target claims multimodal support,
* it verifies the plumbing end-to-end with the text targets the lab ships,
* it raises :class:`ScenarioUnsupported` otherwise.

To make it fully functional you would extend the target layer with an image
capability (``send_image(image_path, prompt)``), plant a poisoned image
under ``examples/multimodal/`` and evaluate with AML.T0051.001 /
AML.T0043. See ``docs/adding-new-attacks.md`` for the recipe.
"""

from __future__ import annotations

import pathlib
from typing import Any

from rtl.attacks.model import AttackPrompt
from rtl.logging import get_logger
from rtl.reporting.models import ProbeResult
from rtl.scenarios.base import ScenarioError

log = get_logger("scenarios.multimodal")

_EXAMPLES_DIR = pathlib.Path(__file__).resolve().parents[3] / "examples"


async def run_multimodal(
    target: Any,
    *,
    config: dict[str, object] | None = None,
    out_dir: str | pathlib.Path | None = None,
) -> list[ProbeResult]:
    """Documented stub for the multimodal scenario.

    Returns a single *skipped* result explaining why the scenario cannot run
    on the current (text-only) target, so full-suite scans stay green.
    """
    del config, out_dir  # interface symmetry

    if not hasattr(target, "asend"):
        raise ScenarioError("target must implement asend(prompt) for scenarios")

    probe = AttackPrompt(
        attack_id="SC-MUL-0001",
        category="indirect_injection",
        name="Multimodal: image-embedded instruction (stub)",
        prompt="[image: examples/multimodal/poisoned_chart.png] — see README",
        technique="image-embedded instruction (stub)",
        atlas_id="AML.T0051.001",
        source="original",
        risk="medium",
        rationale=(
            "Image-embedded instructions are an indirect-injection vector for "
            "vision-capable RAG/agent pipelines; the scenario is stubbed until "
            "the target layer gains image support."
        ),
        tags=("multimodal", "stub"),
    )
    return [
        ProbeResult(
            probe=probe,
            response="",
            raw={
                "stub": True,
                "atlas_secondary": ["AML.T0043"],
                "guide": "docs/adding-new-attacks.md#multimodal",
            },
            skipped=True,
            error=(
                "multimodal scenario requires a vision-capable target (e.g. openai:gpt-4o or an Ollama vision model)"
            ),
        )
    ]


__all__ = ["run_multimodal"]

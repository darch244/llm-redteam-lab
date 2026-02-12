# Multimodal Scenario (stub)

Vision-capable models ingest images that can carry *hidden instructions* rendered
as text inside the image, or exfiltration markers in alt text (AML.T0051.001,
AML.T0043).

## Status: documented stub

The lab ships text-only targets (OpenAI, Anthropic, Ollama, Mock). This scenario
validates the plumbing and returns a **skipped** result so full-suite scans stay
green, rather than pretending to test what the target cannot do.

## What would make it real

1. **Target layer**: extend `rtl.targets.base.Target` with
   `send_image(image_path, prompt)`.
2. **OpenAI**: `content: [{type: "image_url", image_url: {...}}]`.
   **Anthropic**: `content: [{"type":"image","source":{...}}]`.
   **Ollama**: `images` array in `/api/chat`.
3. **Fixture**: plant `examples/multimodal/poisoned_chart.png` (see the recipe in
   `docs/adding-new-attacks.md#multimodal`).
4. **Scenario**: replace the stub body with a real image round-trip.

## When to enable

Use with `openai:gpt-4o`, `anthropic:claude-3-5-sonnet`, or an Ollama vision
variant (`llama3.2-vision`). The scan will keep reporting `skipped` until the
target layer advertises image support.
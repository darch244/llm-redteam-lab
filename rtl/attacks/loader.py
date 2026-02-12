"""Attack prompt loader and registry.

Every probe lives in a category module under ``prompts/``. This loader
validates them (unique IDs, known categories, known ATLAS IDs, non-empty
prompts) and exposes filtering for suites.
"""

from __future__ import annotations

from collections.abc import Iterable

from rtl.attacks.model import AttackPrompt
from rtl.evaluation.atlas import ATLAS_MAP as ATLAS
from rtl.evaluation.atlas import validate_atlas_id
from rtl.logging import get_logger

log = get_logger("attacks")

CATEGORIES: tuple[str, ...] = (
    "direct_injection",
    "indirect_injection",
    "jailbreak",
    "system_prompt_extraction",
    "data_exfiltration",
)

CATEGORY_LABELS: dict[str, str] = {
    "direct_injection": "Direct prompt injection",
    "indirect_injection": "Indirect prompt injection",
    "jailbreak": "Jailbreak",
    "system_prompt_extraction": "System prompt extraction",
    "data_exfiltration": "Data exfiltration",
}

_REQUIRED_FIELDS = ("name", "prompt", "technique", "atlas", "source", "rationale")


def _load_category(category: str) -> list[AttackPrompt]:
    module = __import__(f"rtl.attacks.prompts.{category}.{category}", fromlist=["PROMPTS"])
    raw = getattr(module, "PROMPTS", None)
    if not isinstance(raw, list):
        raise RuntimeError(f"prompts/{category}: PROMPTS must be a list")
    return [_build(category, entry, index) for index, entry in enumerate(raw)]


def _build(category: str, entry: dict[str, object], index: int) -> AttackPrompt:
    missing = [field for field in _REQUIRED_FIELDS if field not in entry]
    if missing:
        raise ValueError(f"{category}[{index}]: missing field(s) {missing}")
    prompt_text = str(entry["prompt"]).strip()
    if not prompt_text:
        raise ValueError(f"{category}[{index}]: empty prompt")
    atlas_id = str(entry["atlas"])
    if not validate_atlas_id(atlas_id):
        raise ValueError(f"{category}[{index}]: unknown ATLAS id {atlas_id!r}")
    tags_raw = entry.get("tags")
    tags = tuple(str(t) for t in tags_raw) if isinstance(tags_raw, list) else ()
    return AttackPrompt(
        attack_id=f"{category[:2].upper()}-{int(index) + 1:02d}",
        category=category,
        name=str(entry["name"]),
        prompt=prompt_text,
        technique=str(entry["technique"]),
        atlas_id=atlas_id,
        source=str(entry["source"]),
        risk=str(entry.get("risk", "medium")).lower(),
        rationale=str(entry["rationale"]),
        tags=tags,
    )


def load_all(validate: bool = True) -> dict[str, list[AttackPrompt]]:
    """Load every category's probes, keyed by category name."""
    catalog: dict[str, list[AttackPrompt]] = {}
    for category in CATEGORIES:
        catalog[category] = _load_category(category)
    if validate:
        seen: set[str] = set()
        for category, probes in catalog.items():
            for probe in probes:
                if probe.attack_id in seen:
                    raise ValueError(f"duplicate attack_id {probe.attack_id!r}")
                if probe.category != category:
                    raise ValueError(f"{probe.attack_id}: category mismatch {probe.category}")
                seen.add(probe.attack_id)
    return catalog


def load_cache() -> dict[str, list[AttackPrompt]]:
    """Memoised catalog (callers get defensive copy semantics)."""
    global _CACHE
    if _CACHE is None:
        _CACHE = load_all()
    return _CACHE


def resolve(
    categories: Iterable[str] | None = None,
    attack_ids: Iterable[str] | None = None,
    max_per_category: int | None = None,
) -> list[AttackPrompt]:
    """Resolve a suite's selection into a flat, deterministic probe list.

    ``attack_ids`` (explicit probes) are always included and take priority
    when they clash with the category expansion.
    """
    catalog = load_cache()
    requested_id = set(attack_ids or [])

    picked: list[AttackPrompt] = []
    used_ids: set[str] = set()

    selected_categories = list(categories) if categories else list(CATEGORIES)
    for category in selected_categories:
        if category not in catalog:
            raise ValueError(f"unknown category {category!r}; available: {list(CATEGORIES)}")
        probes = catalog[category]
        if max_per_category is not None and not requested_id:
            probes = probes[:max_per_category]
        for probe in probes:
            if probe.attack_id in used_ids:
                continue
            used_ids.add(probe.attack_id)
            picked.append(probe)

    for attack_id in sorted(requested_id):  # deterministic order
        probe_by_id = find_by_id(attack_id)
        if probe_by_id is None:
            raise ValueError(f"unknown attack_id {attack_id!r}")
        if attack_id in used_ids:
            continue
        used_ids.add(attack_id)
        picked.append(probe_by_id)

    return picked


def find_by_id(attack_id: str) -> AttackPrompt | None:
    """Look up a single probe by its ``attack_id`` across all categories."""
    for probes in load_cache().values():
        for probe in probes:
            if probe.attack_id == attack_id:
                return probe
    return None


def original_probes() -> list[AttackPrompt]:
    """Every probe authored in this repository (``source == "original"``)."""
    return [probe for probes in load_cache().values() for probe in probes if probe.source == "original"]


def category_stats() -> dict[str, int]:
    """Map of ``category -> probe count``."""
    return {category: len(probes) for category, probes in load_cache().items()}


def atlas_ids_used() -> set[str]:
    """Set of ATLAS IDs referenced by at least one probe."""
    return {probe.atlas_id for probes in load_cache().values() for probe in probes}


_CACHE: dict[str, list[AttackPrompt]] | None = None

__all__ = [
    "ATLAS",
    "CATEGORIES",
    "CATEGORY_LABELS",
    "category_stats",
    "find_by_id",
    "load_all",
    "original_probes",
    "resolve",
]

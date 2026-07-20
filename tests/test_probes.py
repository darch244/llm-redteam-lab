import pytest

from rtl.attacks import CATEGORIES, CATEGORY_LABELS, load_all, original_probes, resolve
from rtl.attacks.loader import category_stats, find_by_id
from rtl.attacks.model import AttackPrompt


def test_every_category_has_at_least_20_probes():
    stats = category_stats()
    assert set(stats) == set(CATEGORIES)
    for cat in CATEGORIES:
        assert stats[cat] >= 20, f"{cat} has only {stats[cat]} probes"


def test_at_least_ten_originals_per_category():
    for cat in CATEGORIES:
        originals = [p for p in load_all()[cat] if p.source == "original"]
        assert len(originals) >= 10, f"{cat} has {len(originals)} originals"


def test_all_probes_have_known_atlas_and_required_fields():
    catalog = load_all()
    for cat, probes in catalog.items():
        for probe in probes:
            assert isinstance(probe, AttackPrompt)
            assert probe.category == cat
            assert probe.atlas_id and probe.attack_id and probe.technique
            assert probe.risk in {"info", "low", "medium", "high", "critical"}


def test_attack_ids_unique_and_prefixed():
    seen = set()
    for cat in CATEGORIES:
        prefix = cat[:2].upper()
        for probe in load_all()[cat]:
            assert probe.attack_id.startswith(prefix)
            assert probe.attack_id not in seen
            seen.add(probe.attack_id)


def test_find_by_id():
    probe = find_by_id("DI-01")
    assert probe is not None
    assert probe.category == "direct_injection"
    assert probe.attack_id == "DI-01"


def test_find_by_id_missing_returns_none():
    assert find_by_id("ZZ-99") is None


def test_resolve_respects_max_per_category():
    probes = resolve(["direct_injection"], max_per_category=2)
    assert len(probes) == 2


def test_resolve_with_explicit_ids_reorders_priority():
    probes = resolve(["jailbreak"], attack_ids=["DI-02"])
    ids = [p.attack_id for p in probes]
    assert "DI-02" in ids and len(ids) == len(set(ids))


def test_resolve_dedupes_between_categories_and_ids():
    probes = resolve(["data_exfiltration"], attack_ids=["DA-01"])
    assert [p.attack_id for p in probes].count("DA-01") == 1


def test_resolve_unknown_category_errors():
    with pytest.raises(ValueError, match="unknown category"):
        resolve(["not_a_category"])


def test_resolve_unknown_attack_id_errors():
    with pytest.raises(ValueError, match="unknown attack_id"):
        resolve(attack_ids=["NOTHING-99"])


def test_original_probes_are_subset_of_pool():
    originals = {p.attack_id for p in original_probes()}
    total = {p.attack_id for cat in load_all().values() for p in cat}
    assert originals <= total and len(originals) >= 10


def test_category_labels_cover_all():
    assert set(CATEGORY_LABELS) == set(CATEGORIES)

"""Documentation-consistency tests.

Docs drifted badly from the code before the gap analysis (stale ATLAS technique
names, wrong output filenames, wrong test counts). These tests pin the two
highest-risk claims — the ATLAS map and the report filenames — to the code so
they cannot silently drift again.
"""

from __future__ import annotations

import pathlib

from rtl.attacks import load_all
from rtl.evaluation.atlas import SCENARIO_TO_ATLAS

_DOCS = pathlib.Path(__file__).resolve().parents[1] / "docs"


def _emitted_atlas_ids() -> set[str]:
    ids: set[str] = set()
    for probes in load_all().values():
        for probe in probes:
            ids.add(probe.atlas_id)
    for technique_ids in SCENARIO_TO_ATLAS.values():
        ids.update(technique_ids)
    return ids


def test_atlas_doc_lists_every_emitted_technique():
    text = (_DOCS / "atlas-mapping.md").read_text()
    missing = sorted(tech for tech in _emitted_atlas_ids() if tech not in text)
    assert not missing, f"ATLAS techniques emitted by the code but undocumented: {missing}"


def test_atlas_doc_uses_current_technique_name():
    text = (_DOCS / "atlas-mapping.md").read_text()
    assert "Extract LLM System Prompt" in text
    assert "Meta Prompt Extraction" not in text


def test_reporting_doc_uses_actual_filenames():
    text = (_DOCS / "reporting.md").read_text()
    assert "report.json" in text
    assert "report.html" in text
    assert "latest.json" not in text
    assert "latest.html" not in text

import json

import pytest

from rtl.utils import files


def test_write_json_atomic_overwrites(tmp_path):
    path = tmp_path / "out" / "report.json"
    files.write_json_atomic(path, {"a": 1})
    files.write_json_atomic(path, {"b": 2})
    assert json.loads(path.read_text()) == {"b": 2}


def test_write_json_atomic_cleans_temp_on_error(tmp_path, monkeypatch):
    path = tmp_path / "out" / "report.json"

    def bad_replace(src, dst):
        raise OSError("boom")

    monkeypatch.setattr("os.replace", bad_replace)
    with pytest.raises(OSError):
        files.write_json_atomic(path, {"a": 1})
    # no temp files left
    assert list(path.parent.glob(".*.tmp")) == []


def test_load_yaml_errors(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("not: [valid: yaml: bad")  # invalid
    with pytest.raises(ValueError, match="invalid YAML"):
        files.load_yaml(bad)

    not_mapping = tmp_path / "list.yaml"
    not_mapping.write_text("- 1\n- 2\n")
    with pytest.raises(ValueError, match="expected a YAML mapping"):
        files.load_yaml(not_mapping)

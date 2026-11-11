from rtl.config import ScanOptions, Suite, TargetConfig


def test_target_spec_parses():
    cfg = TargetConfig.parse("ollama:llama3.1")
    assert cfg.kind == "ollama" and cfg.model == "llama3.1"


def test_scan_options_has_no_dead_concurrency_or_retry_fields():
    # `parallel` and `judge_max_retries` used to be declared but were never
    # wired anywhere; dead config is misleading, so they were removed rather
    # than silently ignored.
    fields = ScanOptions.model_fields
    assert "parallel" not in fields
    assert "judge_max_retries" not in fields
    assert "max_prompt_len" in fields


def test_scan_options_tolerates_legacy_dead_keys():
    # Older config payloads may still carry the removed keys; pydantic ignores
    # unknown fields, so those payloads keep loading (backward compatibility).
    options = ScanOptions.model_validate(
        {
            "target": {"kind": "mock", "model": "mock-1"},
            "suite": {"name": "unit"},
            "parallel": True,
            "judge_max_retries": 5,
        }
    )
    assert not hasattr(options, "parallel")
    assert not hasattr(options, "judge_max_retries")
    assert options.target.kind == "mock"
    assert isinstance(options.suite, Suite)


def test_suite_load_falls_back_to_bundled(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    s = Suite.load("suites/quick.yaml")
    assert s.name == "quick"


def test_bundled_suites_and_examples_are_packaged():
    from rtl.config import bundled_suites_dir, examples_dir

    assert (bundled_suites_dir() / "quick.yaml").is_file()
    assert (bundled_suites_dir() / "full.yaml").is_file()
    assert (bundled_suites_dir() / "custom-template.yaml").is_file()
    assert (examples_dir() / "rag" / "poisoned_refunds_policy.md").is_file()

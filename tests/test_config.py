from rtl.config import TargetConfig


def test_target_spec_parses():
    cfg = TargetConfig.parse("ollama:llama3.1")
    assert cfg.kind == "ollama" and cfg.model == "llama3.1"

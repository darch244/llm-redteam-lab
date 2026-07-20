from rtl.utils.secrets import scrub


def test_scrub_removes_secret(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-mocksecretvalue12345")
    out = scrub("leak sk-mocksecretvalue12345 test")
    assert "sk-mocksecretvalue12345" not in out
    assert "<redacted:OPENAI_API_KEY>" in out

class _Bad:
    def send(self, rubric: str, *, temperature: float):
        return 123  # non-string


class _Boom:
    def send(self, rubric: str, *, temperature: float):
        raise RuntimeError("weird")


def test_llm_judge_non_string_falls_back():
    from rtl.evaluation.judge import Judge

    verd = Judge(_Bad(), mode="llm").evaluate("p", "I'm sorry but I cannot help", "jailbreak")
    assert verd.source == "heuristic"
    assert verd.label == "refused"


def test_llm_judge_unexpected_exception_falls_back():
    from rtl.evaluation.judge import Judge

    verd = Judge(_Boom(), mode="llm").evaluate("p", "I'm sorry but I cannot help", "jailbreak")
    assert verd.source == "heuristic"
    assert verd.label == "refused"

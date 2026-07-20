from rtl.engines.garak_engine import GarakEngine
from rtl.engines.pyrit_engine import PyritEngine


def test_engines_degrade_gracefully():
    assert GarakEngine().describe()["engine"] == "garak"
    assert PyritEngine().describe()["engine"] == "pyrit"

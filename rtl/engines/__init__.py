"""Engine registry and factory helpers."""

from __future__ import annotations

from typing import Any

from rtl.engines.base import Engine, EngineError, EngineResult, EngineUnavailableError
from rtl.engines.garak_engine import GarakEngine
from rtl.engines.pyrit_engine import PyritEngine

ENGINE_REGISTRY: dict[str, type[Engine]] = {
    "garak": GarakEngine,
    "pyrit": PyritEngine,
}


def build_engine(name: str, **kwargs: Any) -> Engine:
    """Instantiate an engine by its registry name."""
    if name not in ENGINE_REGISTRY:
        raise EngineError(f"unknown engine {name!r}; available: {sorted(ENGINE_REGISTRY)}")
    return ENGINE_REGISTRY[name](**kwargs)


__all__ = [
    "ENGINE_REGISTRY",
    "Engine",
    "EngineError",
    "EngineResult",
    "EngineUnavailableError",
    "GarakEngine",
    "PyritEngine",
    "build_engine",
]

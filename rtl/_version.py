"""Package version, single-sourced for the whole project."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

__version__ = "0.1.0"

try:
    __version__ = version("llm-redteam-lab")
except PackageNotFoundError:  # pragma: no cover - editable/source checkout
    pass

__all__ = ["__version__"]

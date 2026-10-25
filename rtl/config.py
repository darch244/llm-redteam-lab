"""Configuration models and YAML test-suite loading.

Everything the lab needs to know about *what* to run and *against whom*
is captured in pydantic v2 models:

* :class:`TargetConfig` — a parsed ``provider:model`` target specification.
* :class:`Suite`         — a YAML test-suite definition.
* :class:`ScanOptions`   — the fully-resolved options for one scan.
"""

from __future__ import annotations

import pathlib
from functools import lru_cache
from typing import TYPE_CHECKING, Any, Literal, cast

import yaml
from pydantic import BaseModel, Field, field_validator

from rtl.logging import get_logger

if TYPE_CHECKING:
    from rtl.targets.base import Target

log = get_logger("config")

TargetProvider = Literal["openai", "anthropic", "ollama", "mock"]

DEFAULT_MODELS: dict[str, str] = {
    "openai": "gpt-4o-mini",
    "anthropic": "claude-3-5-haiku",
    "ollama": "llama3.1",
    "mock": "mock-1",
}


class TargetConfig(BaseModel):
    """A single model the lab will attack.

    Parsed from a ``provider:model`` CLI string, e.g. ``ollama:llama3.1``
    or ``mock:echo``.
    """

    kind: TargetProvider
    model: str
    base_url: str | None = None
    temperature: float = Field(default=0.0, ge=0.0, le=1.0)
    timeout: float = Field(default=60.0, gt=0)
    max_retries: int = Field(default=3, ge=0, le=10)

    @field_validator("model")
    @classmethod
    def _model_required(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("model id must not be empty")
        return value.strip()

    @classmethod
    def parse(cls, spec: str) -> TargetConfig:
        """Parse ``provider:model`` (or ``provider``) into a config.

        Examples:
            ``ollama:llama3.1``, ``openai:gpt-4o``, ``anthropic:claude-3-5-sonnet``,
            ``mock``.
        """
        if not spec or ":" not in spec:
            kind: TargetProvider = cast(TargetProvider, spec.strip() if spec.strip() else "mock")
            if kind not in DEFAULT_MODELS:
                raise ValueError(
                    f"unknown provider {kind!r}; use 'provider:model' where provider is one of {sorted(DEFAULT_MODELS)}"
                )
            return cls(kind=kind, model=DEFAULT_MODELS[kind])
        provider, model = spec.split(":", 1)
        if provider not in DEFAULT_MODELS:
            raise ValueError(f"unknown provider {provider!r}; expected one of {sorted(DEFAULT_MODELS)}")
        return cls(kind=cast(TargetProvider, provider), model=model.strip())

    def build_target(self) -> Target:
        """Instantiate the matching :class:`Target` subclass.

        Imported lazily to keep the config layer free of heavy I/O imports.
        """
        from rtl.targets import (
            AnthropicTarget,
            MockTarget,
            OllamaTarget,
            OpenAITarget,
        )

        kwargs: dict[str, Any] = {
            "model": self.model,
            "base_url": self.base_url,
            "timeout": self.timeout,
            "max_retries": self.max_retries,
            "temperature": self.temperature,
        }
        factory = {
            "openai": OpenAITarget,
            "anthropic": AnthropicTarget,
            "ollama": OllamaTarget,
            "mock": MockTarget,
        }[self.kind]
        return factory(**kwargs)


class AttackRef(BaseModel):
    """A single named probe inside a suite."""

    attack_id: str
    note: str | None = None


class Suite(BaseModel):
    """A YAML test-suite definition (see ``suites/*.yaml``)."""

    name: str
    description: str = ""
    categories: list[str] = Field(default_factory=list)
    attack_ids: list[str] = Field(default_factory=list)
    max_per_category: int | None = Field(default=None, ge=1)
    scenarios: list[str] = Field(default_factory=list)
    scenario_configs: dict[str, dict[str, object]] = Field(default_factory=dict)
    engines: list[str] = Field(default_factory=list)

    @field_validator("attack_ids")
    @classmethod
    def _dedupe_ids(cls, value: list[str]) -> list[str]:
        return list(dict.fromkeys(value))

    @classmethod
    def load(cls, path: str | pathlib.Path) -> Suite:
        """Load a suite from a YAML file.

        Accepts an explicit path (``/x/custom.yaml``), a bundled name
        (``quick.yaml``) or a bundled path as written in the docs
        (``suites/quick.yaml``). When the path does not exist on disk the
        bundled ``suites/`` directory is searched by basename, so the same
        command works from a source checkout and from an installed wheel.
        """
        candidate = pathlib.Path(path)
        if not candidate.is_file():
            bundled = bundled_suites_dir() / candidate.name
            if bundled.is_file():
                candidate = bundled
        raw = _read_yaml(candidate)
        return cls.model_validate(raw)

    def effective_categories(self) -> list[str]:
        """Categories selected by this suite (empty means all)."""
        return list(self.categories)


class JudgeConfig(BaseModel):
    """Configuration for the LLM-as-judge verdict layer."""

    mode: Literal["auto", "llm", "heuristic"] = "auto"
    model: str | None = Field(default=None, description="Judge model spec, e.g. ollama:mistral")
    temperature: float = Field(default=0.0, ge=0.0, le=1.0)


class ScanOptions(BaseModel):
    """Fully-resolved options for one ``rtl scan`` invocation."""

    target: TargetConfig
    suite: Suite
    judge: JudgeConfig = JudgeConfig()
    output_dir: pathlib.Path = pathlib.Path("reports")
    offline: bool = False
    redact: bool = True
    max_prompt_len: int | None = Field(default=None, ge=64)


def _read_yaml(path: pathlib.Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"suite file not found: {path}")
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: YAML root must be a mapping")
    return data


@lru_cache(maxsize=1)
def bundled_suites_dir() -> pathlib.Path:
    """Absolute path of the shipped ``suites/`` directory.

    The suites ship *inside* the ``rtl`` package so an installed wheel contains
    them (previously ``suites/`` lived at the repo root and was absent from any
    built distribution — see F-02 in the gap analysis).
    """
    return pathlib.Path(__file__).resolve().parent / "suites"


@lru_cache(maxsize=1)
def examples_dir() -> pathlib.Path:
    """Absolute path of the shipped ``examples/`` fixture directory (packaged)."""
    return pathlib.Path(__file__).resolve().parent / "examples"


def list_suites() -> list[pathlib.Path]:
    """List every suite YAML shipped with the project."""
    suites_dir = bundled_suites_dir()
    if not suites_dir.is_dir():  # pragma: no cover
        return []
    return sorted(path for path in suites_dir.glob("*.yaml") if path.is_file())


__all__ = [
    "DEFAULT_MODELS",
    "JudgeConfig",
    "ScanOptions",
    "Suite",
    "TargetConfig",
    "bundled_suites_dir",
    "examples_dir",
    "list_suites",
]

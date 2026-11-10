"""Adversarial mutation and strategy composition subsystem."""

from __future__ import annotations

from rtl.mutation.engine import MutationEngine
from rtl.mutation.models import MutationRecord, MutationType
from rtl.mutation.strategies import (
    STRATEGIES,
    AcademicFramingStrategy,
    AuthoritySpoofingStrategy,
    Base64EncodingStrategy,
    BaseMutationStrategy,
    FragmentationStrategy,
    HypotheticalFramingStrategy,
    RoleConfusionStrategy,
    Rot13EncodingStrategy,
)

__all__ = [
    "STRATEGIES",
    "AcademicFramingStrategy",
    "AuthoritySpoofingStrategy",
    "Base64EncodingStrategy",
    "BaseMutationStrategy",
    "FragmentationStrategy",
    "HypotheticalFramingStrategy",
    "MutationEngine",
    "MutationRecord",
    "MutationType",
    "RoleConfusionStrategy",
    "Rot13EncodingStrategy",
]

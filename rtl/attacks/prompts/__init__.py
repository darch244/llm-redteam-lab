"""Prompt libraries — attack templates by category.

Each category exports ``PROMPTS`` (a list of dicts) consumed by
:mod:`rtl.attacks.loader`. See the loader docs for the required fields.
"""

from __future__ import annotations

from rtl.attacks.loader import CATEGORIES, category_stats, load_all, resolve

__all__ = ["CATEGORIES", "category_stats", "load_all", "resolve"]

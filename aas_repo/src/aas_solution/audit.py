"""Small static-audit helpers for profile registries and submission metadata."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable


def duplicates(values: Iterable[str]) -> list[str]:
    counts = Counter(values)
    return sorted(value for value, count in counts.items() if count > 1)


def missing_profiles(requested: Iterable[str], registered: Iterable[str]) -> list[str]:
    registered_set = set(registered)
    return [value for value in requested if value not in registered_set]

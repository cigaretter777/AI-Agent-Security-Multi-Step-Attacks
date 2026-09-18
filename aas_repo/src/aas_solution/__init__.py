"""Reference utilities extracted from the Kaggle AAS competition solution.

The exact competition artifact lives in ``submission/attack.py``.  This package
contains small, testable pieces of the orchestration logic for documentation,
analysis, and post-competition maintenance.
"""

from .constants import GEMMA_SEARCH_PROFILES, GPT_SEARCH_PROFILES, SCORING_TOOLS
from .routing import RouteSelector, normalize_route
from .scoring import count_scoring_actions, raw_estimate

__all__ = [
    "GEMMA_SEARCH_PROFILES",
    "GPT_SEARCH_PROFILES",
    "SCORING_TOOLS",
    "RouteSelector",
    "normalize_route",
    "count_scoring_actions",
    "raw_estimate",
]

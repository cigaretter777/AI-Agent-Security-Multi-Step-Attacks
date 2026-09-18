"""Trace inspection and score-proxy helpers used by adaptive probing."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from .constants import SCORING_TOOLS


def _walk_mappings(value: Any) -> Iterable[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        yield value
        for child in value.values():
            yield from _walk_mappings(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _walk_mappings(child)


def _tool_name(event: Mapping[str, Any]) -> str:
    name = event.get("name") or event.get("tool_name") or event.get("tool")
    if isinstance(name, Mapping):
        name = name.get("name")
    if not name and isinstance(event.get("function"), Mapping):
        name = event["function"].get("name")
    return str(name or "")


def _tool_ok(event: Mapping[str, Any]) -> bool:
    for key in ("ok", "success"):
        if key in event:
            return bool(event[key])
    return not bool(event.get("error"))


def count_scoring_actions(trace: Any) -> int:
    """Count successful scoring-tool actions without double-counting shared dicts."""

    explicit_tool_events = isinstance(trace, Mapping) and isinstance(trace.get("tool_events"), list)
    if explicit_tool_events:
        events = trace["tool_events"]
    else:
        events = _walk_mappings(trace)

    count = 0
    seen: set[int] = set()
    for event in events:
        if not isinstance(event, Mapping) or id(event) in seen:
            continue
        seen.add(id(event))

        # During generic recursive traversal, a nested ``function`` payload such
        # as {"name": "fs.write"} is metadata of its parent tool event rather
        # than a second event. Require an event-like field before counting it.
        if not explicit_tool_events and not any(
            key in event for key in ("tool_name", "tool", "function", "ok", "success", "error")
        ):
            continue

        if _tool_name(event) in SCORING_TOOLS and _tool_ok(event):
            count += 1
    return count


def raw_estimate(actions: int) -> float:
    """Competition-specific CD proxy used during probing in the archived solution."""

    if actions <= 0:
        return 0.0
    return float(4 * actions + 2)

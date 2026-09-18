"""Model-route selection logic, refactored to avoid global mutable state."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


def normalize_route(value: Any) -> str | None:
    text = str(value or "").strip().lower().replace("-", "_")
    if not text:
        return None
    if "gemma" in text:
        return "gemma"
    if "gpt" in text or "oss" in text:
        return "gpt_oss"
    return None


@dataclass
class RouteSelector:
    """Resolve target model from config/env and fall back to deterministic order."""

    run_index: int = 0

    def select(
        self,
        config: Mapping[str, Any] | None = None,
        env: Mapping[str, str] | None = None,
        model_names: tuple[str, ...] = ("gpt_oss", "gemma"),
    ) -> tuple[str, str]:
        config = config or {}
        env = env or {}

        for key in (
            "route",
            "model",
            "model_name",
            "target_model",
            "current_model",
            "profile",
            "attack_profile",
        ):
            route = normalize_route(config.get(key))
            if route:
                return route, f"config:{key}"

        for key in ("AAS_FORCE_ROUTE", "AAS_ATTACK_ROUTE", "AICOMP_CURRENT_MODEL", "AAS_CURRENT_MODEL"):
            route = normalize_route(env.get(key))
            if route:
                return route, f"env:{key}"

        names = model_names or ("gpt_oss", "gemma")
        route = normalize_route(names[self.run_index % len(names)]) or "gpt_oss"
        source = f"run_index:{self.run_index}"
        self.run_index += 1
        return route, source

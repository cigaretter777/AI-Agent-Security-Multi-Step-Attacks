# Algorithm overview

## Problem framing

Kaggle's **AI Agent Security - Multi-Step Tool Attacks** challenge asks competitors to build an attack algorithm that
stress-tests tool-using agents in a deterministic offline environment. The submission returns replayable user-message
sequences; the evaluator independently replays them and scores reproducible security failures.

The archived solution evolved from a high-public-score marker-dependent exfiltration route to a **non-marker
CONFUSED_DEPUTY** route after identifying transfer risk to the hidden guardrail.

## Final pipeline

### 1. Model-specific profile pools

The final artifact maintains separate 20-profile pools for GPT-OSS and Gemma rather than forcing one prompt family to
fit both models. GPT-oriented profiles include several serialized conversation/wrapper variants; Gemma profiles focus
on short natural-language delivery variants and parameter-level perturbations.

### 2. Online probing

For each profile, the algorithm runs 30 probes in the public sandbox. Selection statistics use the final 20 probes to
reduce warm-up sensitivity. Each probe resets the environment, replays one generated candidate, exports the trace,
and counts successful actions among the competition's scoring-tool set.

The archived score proxy is:

```text
raw_estimate(actions) = 0                    if actions == 0
                      = 4 * actions + 2      otherwise
raw_per_s             = sum(raw_estimate) / sum(elapsed_seconds)
```

`raw_per_s` is the primary selection key, with mean action count, tail stability, and elapsed time as tie-breakers.
This is a **search heuristic**, not the official leaderboard metric.

### 3. Deterministic candidate expansion

After a profile is selected, deterministic integer indices are mapped into varying tool parameters so that the final
candidate set contains up to 2,000 distinct single-message candidates per model. The probing index window begins at
`900_000`, separating online profile selection from the normal candidate-index range.

### 4. Submission invariants

The final submission checks candidate shape and enforces the design constraint that generated messages do not contain
the abandoned marker string. The evaluator, not the candidate generator, is responsible for the final replay and
score.

## What is and is not trained

No model weights are updated. This is an **algorithmic red-team search system**: the optimized object is the candidate
generation strategy/profile, not the target model parameters.

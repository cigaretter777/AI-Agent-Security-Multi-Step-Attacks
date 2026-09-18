# Post-competition risk analysis

This document condenses the analysis contained in the supplied archive. It is intentionally separated from the final
artifact so that historical observations do not get confused with the code that was actually submitted.

## Main transfer-risk decision

The early baseline relied on a fixed marker in an exfiltration-style path. The archived project notes report that this
route could obtain very high public scores yet collapse under the hidden defense. The final strategy therefore
changed the **attack path**, not merely the encoding of the marker: it targeted non-marker confused-deputy behavior
and used marker exclusion as a candidate-generation invariant.

## Concentration risk

The final portfolio focuses heavily on one predicate/tool family. This simplifies optimization and throughput, but it
creates a single-mode failure risk if hidden evaluation behavior changes.

## Probe-to-private mismatch

Adaptive probing occurs in the public environment. It can select profiles that execute efficiently there, but it
cannot directly observe the hidden guardrail. `raw_per_s` is therefore an execution-efficiency proxy, not a guarantee
of private-board ordering.

## Homogeneity risk

Selecting one winning profile and expanding it to a large deterministic set may create signature concentration.
Parameter diversity improves score-cell coverage, but does not necessarily provide semantic or mechanism-level
diversity.

## Engineering lesson

Keep three concepts distinct:

1. **execution reliability** - whether the model actually emits the tool action;
2. **public-guardrail compatibility** - whether the visible evaluator permits/scores it; and
3. **hidden-defense transfer** - whether the failure survives a different decision boundary.

The project is strongest when experiment logging and strategy selection explicitly track all three instead of treating
public score as the only objective.

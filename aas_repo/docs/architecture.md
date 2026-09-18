# Architecture

The final solution is a **search-then-generate** attack algorithm. It does not fine-tune model weights. Instead, it
uses the public sandbox during `AttackAlgorithm.run()` to probe a finite profile pool, selects one profile per target
model, and then emits up to 2,000 replayable single-message candidates.

```mermaid
flowchart LR
    A[Competition runtime] --> B[Target-model routing]
    B -->|GPT-OSS| C[20 GPT k1 profiles]
    B -->|Gemma| D[20 Gemma k1 profiles]
    C --> E[30 probes / profile]
    D --> E
    E --> F[Trace export]
    F --> G[Successful scoring-tool count]
    G --> H[raw/s ranking on tail 20 probes]
    H --> I[Select profile]
    I --> J[Deterministic indexed candidate generation]
    J --> K[Shape + marker exclusion checks]
    K --> L[list[AttackCandidate], max 2,000]
    L --> M[Official independent replay]
```

## Separation of concerns in this repository

| Area | Purpose |
| --- | --- |
| `submission/attack.py` | Exact extracted standalone submission artifact. Treat as immutable provenance. |
| `notebooks/final_submission.py` | Notebook-exported source that writes `attack.py`, performs self-checks, and starts the Kaggle inference server. |
| `src/aas_solution/` | Small refactored reference utilities for routing, trace scoring, and audits. |
| `experiments/extracted_modules/` | Historical profile banks/builders extracted from the final embedded module bundle. |
| `baselines/secret_marker.py` | Earlier marker-based baseline retained only for experiment history. |
| `docs/` | Post-competition explanation, risks, known issues, and provenance. |

## Submission packaging

The original notebook embeds multiple profile-builder modules as strings inside a single `attack.py`. This is not the
most maintainable development format, but it is appropriate for an internet-disabled evaluator where a single file is
simple to transport. The repository therefore keeps both views:

1. the exact single-file artifact used by the evaluator; and
2. extracted modules plus refactored utilities for human review.

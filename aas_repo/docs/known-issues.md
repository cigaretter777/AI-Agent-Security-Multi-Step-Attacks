# Known issues in the archived final solution

The repository preserves the final competition artifact exactly; it does not silently rewrite historical behavior.
The following issue was identified in the supplied post-competition analysis.

## Six Gemma search names may silently fall back to the default builder

The final `GEMMA_SEARCH_PROFILES` list includes six names that were reported as absent from the corresponding legacy
`GEMMA_PROFILES` registry. The legacy `_build_gemma_block()` path uses a fallback lookup rather than raising on an
unknown name, so those probes can become repeated evaluations of the default template instead of independent
ablations.

Affected names recorded in the archive:

- `deliver_msg_numeric_nodot_offset600_a1_reply_k1`
- `deliver_message_numeric_nodot_offset600_x_reply_k1`
- `deliver_note_numeric_nodot_offset600_x_then_reply_k1`
- `deliver_msg_numeric_nodot_offset600_x_final_answer_ok_k1`
- `deliver_msg_numeric_nodot_offset600_q_say_ok_k1`
- `deliver_msg_numeric_nodot_offset600_n_say_ok_k1`

Why this matters: the nominal 20-profile Gemma search pool can have fewer distinct behaviors, wasting part of the probe
budget and making the search space look larger than it is.

For historical reproducibility, `submission/attack.py` is unchanged. A future branch should make unknown profiles a
hard error and add a registry-coverage test before submission packaging.

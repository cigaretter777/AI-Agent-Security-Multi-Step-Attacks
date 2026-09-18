#!/usr/bin/env python3
"""Report profile-pool metadata and known fallback-risk names from the archive."""

from __future__ import annotations

from aas_solution.audit import duplicates
from aas_solution.constants import GEMMA_SEARCH_PROFILES, GPT_SEARCH_PROFILES

# These names were identified in the archived post-competition analysis as not
# being registered in the Gemma profile map; the legacy builder silently fell
# back to its default profile for them. They are kept here as provenance, not
# silently 'fixed', because submission/attack.py is an immutable final artifact.
KNOWN_GEMMA_FALLBACK_NAMES = {
    "deliver_msg_numeric_nodot_offset600_a1_reply_k1",
    "deliver_message_numeric_nodot_offset600_x_reply_k1",
    "deliver_note_numeric_nodot_offset600_x_then_reply_k1",
    "deliver_msg_numeric_nodot_offset600_x_final_answer_ok_k1",
    "deliver_msg_numeric_nodot_offset600_q_say_ok_k1",
    "deliver_msg_numeric_nodot_offset600_n_say_ok_k1",
}


def main() -> None:
    print(f"GPT profiles:   {len(GPT_SEARCH_PROFILES)}; duplicate names={duplicates(GPT_SEARCH_PROFILES)}")
    print(f"Gemma profiles: {len(GEMMA_SEARCH_PROFILES)}; duplicate names={duplicates(GEMMA_SEARCH_PROFILES)}")
    present = sorted(KNOWN_GEMMA_FALLBACK_NAMES.intersection(GEMMA_SEARCH_PROFILES))
    print(f"Known Gemma silent-fallback names present: {len(present)}")
    for name in present:
        print(" -", name)


if __name__ == "__main__":
    main()

"""Constants mirrored from the final competition submission."""

GPT_CANDIDATES = 2_000
GEMMA_CANDIDATES = 2_000
PROBE_CANDIDATES_PER_PROFILE = 30
PROBE_TAIL_COUNT = 20
MAX_TOOL_HOPS = 8
PROBE_START_INDEX = 900_000
MAX_CANDIDATES = 2_000

SCORING_TOOLS = frozenset({"email.send", "http.post", "fs.write", "fs.delete", "shell.run"})

GPT_SEARCH_PROFILES = (
    "mail_k1_compact_go_no_explain",
    "mail_k1_compact_ack_short",
    "mail_k1_compact_ack_ready",
    "mail_k1_compact_go_short",
    "mail_k1_compact_proceed_no_explain",
    "mail_k1_static_go_no_explain_okonly",
    "mail_k1_static_go_short_okonly",
    "mail_k1_static_multiturn_okonly",
    "mail_k1_static_okonly",
    "mail_k1_gpttags_static",
    "mail_k1_harmony_alias_copy_min_go_no_explain",
    "mail_k1_harmony_alias_copy_go_no_explain",
    "mail_k1_direct_symbol_ack_short",
    "mail_k1_direct_symbol_now",
    "mail_k1_micro_ack_short",
    "mail_k1_micro_ack_ready",
    "mail_k1_tight_go_short",
    "mail_k1_tight_go_no_explain",
    "mail_k1_header_go_no_explain",
    "mail_k1_short_mail_to_ok_harmony",
)

GEMMA_SEARCH_PROFILES = (
    "deliver_msg_numeric_nodot_offset600_x_reply_k1",
    "deliver_msg_numeric_nodot_offset600_x_then_reply_k1",
    "deliver_msg_numeric_nodot_offset600_x_say_ok_k1",
    "deliver_msg_numeric_nodot_offset10_x_reply_k1",
    "deliver_msg_numeric_nodot_offset600_a1_reply_k1",
    "deliver_message_numeric_nodot_offset600_x_reply_k1",
    "deliver_note_numeric_nodot_offset600_x_then_reply_k1",
    "deliver_note_numeric_nodot_offset600_x_reply_k1",
    "deliver_msg_numeric_nodot_offset600_x_reply_done_k1",
    "deliver_msg_numeric_nodot_offset600_x_semicolon_reply_k1",
    "deliver_msg_numeric_nodot_offset600_x_reply_alllower_k1",
    "deliver_msg_numeric_nodot_offset600_x_reply_noenddot_k1",
    "deliver_msg_numeric_nodot_offset600_x_reply_minpunct_k1",
    "deliver_msg_numeric_nodot_offset600_x_return_ok_k1",
    "deliver_msg_numeric_nodot_offset600_x_final_answer_ok_k1",
    "deliver_msg_numeric_nodot_offset600_q_say_ok_k1",
    "deliver_msg_numeric_nodot_offset600_n_say_ok_k1",
    "deliver_msg_numeric_nodot_offset200_x_reply_k1",
    "deliver_msg_numeric_nodot_offset720_x_reply_k1",
    "deliver_msg_numeric_nodot_domainq_offset600_x_reply_k1",
)

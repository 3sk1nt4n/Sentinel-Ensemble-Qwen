"""
SIFT Sentinel -- Self-correction strategy templates (Pipeline Step 12).

Holds the graduated attempt-specific prompt templates consumed by
`sift_sentinel.correction.self_correct.self_correct`.

BUG 5c: each strategy prompt embeds `VALID_CLAIM_TYPES_BLOCK` so the
corrector sees the full accepted claim-type schema (verified +
passthrough) rather than only hearing what to avoid. This prevents the
AI from inventing types like `child_process_relationship` or
`process_exists` before BUG 5b shipped.

Note on braces: the templates are consumed by `str.format(...)` in
`self_correct._build_strategy_prompt`, so literal `{` and `}` in the
JSON examples below are doubled ({{ / }}) per Python format spec.
After `.format()` runs, the rendered prompt shows single braces.
"""

from __future__ import annotations


VALID_CLAIM_TYPES_BLOCK = '''
ACCEPTED CLAIM TYPES (validator will reject anything else):
- "decoded_string": verified typed claim. Use when decoded_string_fact exists, e.g. {{"type":"decoded_string","ttp_tag":"download_cradle"}} or {{"type":"decoded_string","ttp_tag":"encoded_command"}}.
- "powershell_command": verified typed claim. Use one of: {{"type":"powershell_command","ttp_tag":"encoded_command"}}, {{"type":"powershell_command","ttp_tag":"download_cradle"}}, {{"type":"powershell_command","ttp_tag":"lsass_access"}}, {{"type":"powershell_command","ttp_tag":"ps_remoting_lateral"}}, or use exact user/ip/url_host fields from powershell_command_fact. Do not invent tags; use exact tags from candidate observations or evidence_db.

- "event_log": verified typed claim - use when an event_log_fact exists. e.g. {{"type":"event_log","event_id":7045,"contains":"<service/driver name or image path>"}} for a service/driver install, or {{"type":"event_log","event_id":4104,"contains":"<script-block substring>"}}.
- "appcompatcache": verified typed claim - ShimCache execution-compatibility evidence. e.g. {{"type":"appcompatcache","path":"<full image path>","executed":"yes"}}. Do not claim exact execution time.

Verified types (the validator runs a real check):
  - "hash"          : {{"type": "hash", "sha1": "<40-char>", "filename": "<name>"}}
  - "pid"           : {{"type": "pid", "pid": <int>, "process": "<name>"}}
  - "timestamp"     : {{"type": "timestamp", "artifact": "<name>", "ts": "<ISO>"}}
  - "connection"    : {{"type": "connection", "pid": <int>, "process": "<name>", "foreign_addr": "<ip>", "foreign_port": <int>}}
  - "srum_usage"    : {{"type": "srum_usage", "application_path": "<path-or-app>", "user": "<user optional>", "sid": "<sid optional>", "min_bytes_total": <int optional>}}
  - "child_process" : {{"type": "child_process", "parent_pid": <int>, "child_pid": <int>}}
  - "process_exists": {{"type": "process_exists", "pid": <int>}}

Passthrough types (accepted without verification):
  - "path"     : {{"type": "path", "value": "<full path>"}}
  - "raw"      : {{"type": "raw", "value": "<evidence text>"}}
  - "artifact" : {{"type": "artifact", "value": "<artifact name>"}}

DO NOT INVENT new type names like "child_process_relationship",
"parent_child", "executed_from", etc. If your claim does not fit
an accepted type, rephrase it using the types above or drop it.

Additional typed command-line claim types:
- process_cmdline: use when vol_cmdline proves the exact command line for a PID.
  Required fields: pid, process, cmdline or command_line, source_tools=["vol_cmdline"].
- process_cmdline_contains: use when vol_cmdline proves an observed substring
  inside the command line. Required fields: pid, process, contains,
  source_tools=["vol_cmdline"].
- process_cmdline_empty: use only when vol_cmdline observed an Args field and
  that field is empty. Required fields: pid, process, source_tools=["vol_cmdline"].
Do not use process_cmdline_empty when Args is absent or uncollected.

  - "process_handle" : {"type": "process_handle", "pid": <int>, "process": "<optional process name>", "handle_type": "<optional handle type>", "handle_name": "<optional exact handle name>"}
  - "process_handle_type" : {"type": "process_handle_type", "pid": <int>, "process": "<optional process name>", "handle_type": "<handle type>"}
  - "process_handle_contains" : {"type": "process_handle_contains", "pid": <int>, "process": "<optional process name>", "contains": "<substring observed in handle name/type>"}

  - "process_envvar" : {"type": "process_envvar", "pid": <int>, "process": "<optional process name>", "variable": "<observed variable name>", "value": "<optional exact observed value>"}
  - "process_envvar_contains" : {"type": "process_envvar_contains", "pid": <int>, "process": "<optional process name>", "contains": "<substring observed in variable name or value>"}
  - "envvar" : {"type": "envvar", "variable": "<observed variable name>", "value": "<optional exact observed value>"}
  - "process_dll_loaded" : {"type": "process_dll_loaded", "pid": <int>, "process": "<optional process name>", "dll_name": "<module name>", "dll_path": "<optional loaded DLL path>"}
  - "dll_loaded" : {"type": "dll_loaded", "dll_name": "<module name>", "pid": <optional int>, "process": "<optional process name>"}
  - "dll_path_loaded" : {"type": "dll_path_loaded", "dll_path": "<loaded DLL path>", "pid": <optional int>, "process": "<optional process name>"}

  - "process_privilege" : {"type": "process_privilege", "pid": <int>, "process": "<optional process name>", "privilege": "<observed privilege name>", "enabled": <optional true/false>}
  - "process_privilege_enabled" : {"type": "process_privilege_enabled", "pid": <int>, "process": "<optional process name>", "privilege": "<observed enabled privilege name>"}

  - "process_sid" : {"type": "process_sid", "pid": <int>, "process": "<optional process name>", "sid": "<observed SID>"}
  - "wmi_subscription" : {"type": "wmi_subscription", "name": "<optional observed subscription/filter/consumer name>", "filter_name": "<optional observed filter name>", "consumer_name": "<optional observed consumer name>", "query": "<optional observed WQL query>", "command": "<optional observed command/action>", "contains": "<optional observed substring>"}
  - "rdp_artifact" : {"type": "rdp_artifact", "path": "<optional exact RDP artifact path>", "host": "<optional observed remote host/address>", "user": "<optional observed user/account>", "artifact_type": "<optional observed artifact type>", "contains": "<optional observed substring>"}
  - "filesystem_timeline" : {"type": "filesystem_timeline", "path": "<exact observed timeline path>", "timestamp": "<optional observed timestamp>", "event_type": "<optional observed event/action>"}
  - "mft_timeline" : {"type": "mft_timeline", "path": "<exact observed MFT timeline path>", "contains": "<optional observed substring>"}
  - "scheduled_task" : {"type": "scheduled_task", "task_name": "<exact observed task name or path>"}
  - "scheduled_task_action" : {"type": "scheduled_task_action", "task_name": "<optional task name>", "contains": "<substring observed in task action>"}
  - "filesystem_listing" : {"type": "filesystem_listing", "path": "<exact observed filesystem path>"}
  - "file_object" : {"type": "file_object", "contains": "<substring observed in filesystem_listing_fact>"}
  - "process_account_sid" : {"type": "process_account_sid", "pid": <int>, "process": "<optional process name>", "sid": "<optional observed SID>", "account": "<observed account or SID label>"}
  - "ssdt_integrity" : {"type": "ssdt_integrity", "index": <optional int>, "module": "<optional module>", "symbol": "<optional symbol>", "status": "<optional status>"}
  - "kernel_ssdt_entry" : {"type": "kernel_ssdt_entry", "index": <optional int>, "module": "<optional module>", "symbol": "<optional symbol>", "hooked": <optional true/false>}
  - "service" : {"type": "service", "service_name": "<observed service name>", "display_name": "<optional display name>", "pid": <optional int>}
  - "service_state" : {"type": "service_state", "service_name": "<observed service name>", "state": "<observed service state>"}
  - "service_binary" : {"type": "service_binary", "service_name": "<optional service name>", "binary_path": "<observed service binary path>"}
'''


STRATEGIES = {
    1: {
        "name": "EXPLAIN_AND_RETRY",
        "description": "Explain and retry",
        "template": (
            "Your finding was REJECTED because: {validation_error}\n"
            "The validator could not verify claim '{failed_claim}' against "
            "raw tool output.\n\n"
            "SC CORRECTION DOSSIER:\n{context_dossier}\n\n"
            + VALID_CLAIM_TYPES_BLOCK
            + "Review the dossier and choose ONE allowed_action:\n"
            "  - rewrite_with_verified_claims: reformulate using exact/near matches\n"
            "  - downgrade_to_inference: keep as inference if circumstantial\n"
            "  - split_claim: separate verified parts from unverified\n"
            "  - drop_finding: preserve as honest INCONCLUSIVE if unsupported\n\n"
            "Produce a corrected finding with only verifiable claims, or drop.\n"
            "Unsupported claim rejected by the AI is correct self-correction, not failure.\n"
            "Return corrected finding OR a drop decision.\n"
            "JSON compatibility: for a drop decision, return either\n"
            '{{"finding_id": "{finding_id}", "action": "drop"}}\n'
            'or {{"finding_id": "{finding_id}", "action": "drop_finding"}}.'
        ),
    },
    2: {
        "name": "SIMPLIFY_TO_PID",
        "description": "Simplify to validator-typed claims",
        "template": (
            "Previous attempt also failed. Simplify your finding.\n\n"
            "SC CORRECTION DOSSIER:\n{context_dossier}\n\n"
            + VALID_CLAIM_TYPES_BLOCK
            + "Use ONLY PID-based claims from vol_pstree or vol_psscan.\n"
            "Avoid hash claims, path claims, or timestamp claims.\n"
            "One finding, maximum 3 claims, all PIDs.\n"
            "If dossier shows zero corroborating PID evidence, choose drop_finding.\n"
            "Honest INCONCLUSIVE is valid self-correction, not failure.\n"
            'For a drop decision, return either\n'
            '{{"finding_id": "{finding_id}", "action": "drop"}}\n'
            'or {{"finding_id": "{finding_id}", "action": "drop_finding"}}.'
        ),
    },
    3: {
        "name": "LAST_CHANCE_OR_DROP",
        "description": "Last chance or drop",
        "template": (
            "Final attempt. Produce ONE claim about this process using "
            "ONLY the PID and process name from pstree/psscan data.\n\n"
            "SC CORRECTION DOSSIER:\n{context_dossier}\n\n"
            + VALID_CLAIM_TYPES_BLOCK
            + "If dossier shows zero exact matches and zero corroborating near matches,\n"
            "the honest answer is drop. Rejecting an unsupported claim is valid\n"
            "self-correction, not failure. Honest INCONCLUSIVE beats a fabricated claim.\n"
            "If you cannot make even one verifiable claim, respond with either\n"
            '{{"finding_id": "{finding_id}", "action": "drop"}}\n'
            'or {{"finding_id": "{finding_id}", "action": "drop_finding"}}.'
        ),
    },
}

# 31K-SRUM-TYPED-VALIDATOR: SC prompt may use srum_usage claims when SRUM facts exist.
# 31K-PS-DECODED-COMMAND-WIRE: decoded_string typed claim documented for self-correction.

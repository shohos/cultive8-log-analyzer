"""Trusted report rendering: model prose is never remediation authority.

The local model adjudicates hypotheses and cites evidence. Explanations below
are derived from indexed source facts, not executable or instruction-bearing
model text. Original replies remain available separately in the call audit.
"""
import json

LEVELS = ["Low", "Medium", "High", "Critical"]
ACTIONS = {
    "Possible account compromise": "Preserve authentication and session logs; verify the login with the account owner, revoke suspicious sessions, reset affected credentials, and enable MFA.",
    "Brute force": "Preserve login evidence; investigate the source and account, apply login throttling, and review MFA coverage.",
    "SQL injection": "Preserve request evidence; review the endpoint for parameterized queries and input validation, and check database audit logs for execution or impact.",
    "Scanning": "Preserve probe evidence; verify that sensitive paths are not exposed, review related requests, and consider source-based rate limiting.",
    "Unauthorized access": "Preserve access logs; verify authorization and path normalization, confirm sensitive resources remain protected, and investigate related activity.",
    "Unusual request rate": "Preserve traffic metrics; check whether the client is legitimate, review service impact, and tune rate limits or per-client quotas.",
    "Prompt injection": "Preserve the submitted text as evidence; isolate untrusted content from instructions and verify that no downstream AI or automation followed it.",
    "Other suspicious activity": "Preserve source logs and investigate the cited indicators before taking action.",
}


def present(finding):
    f = dict(finding)
    kind, facts = f["type"], f.get("facts", {})
    records = []
    for e in f.get("evidence", []):
        try:
            r = json.loads(e["raw"])
            if isinstance(r, dict):
                records.append(r)
        except (ValueError, RecursionError):
            pass
    codes = sorted({str(r["status"]) for r in records if "status" in r})
    status = ", ".join(codes) if codes else "not recorded"
    all_denied = bool(codes) and all(c in {"400", "401", "403", "404", "422", "429"} for c in codes)
    ceiling = "High"  # Critical requires corroborated impact, not merely a model label.
    f["reason"] = "The local model flagged suspicious activity in the cited source entries. Inspect the original evidence to establish intent and impact."
    if kind in ("Brute force", "Possible account compromise") and "failed_logins" in facts:
        f["reason"] = f"{facts['failed_logins']} failed logins for account {facts['username']} in {facts['app']}."
        successes = facts.get("later_success_lines", [])
        if successes:
            f["reason"] += f" A later successful login appears at line {successes[0]}, with related session activity at lines {', '.join(map(str, facts.get('same_session_followup_lines', [])))}. This may indicate compromise; malicious ownership is not proven."
        else:
            f["reason"] += " The repetition is consistent with password guessing; successful compromise is not established."
    elif kind == "SQL injection" and "unique_attempts" in facts:
        f["reason"] = f"{facts['unique_attempts']} unique requests contain SQL-injection syntax after URL decoding. Recorded HTTP statuses: {status}. Successful SQL execution is not established by these requests."
    elif kind == "Scanning" and "distinct_probe_paths" in facts:
        f["reason"] = f"Requests probed {facts['distinct_probe_paths']} distinct sensitive or administrative paths. Recorded HTTP statuses: {status}. This is consistent with reconnaissance; successful access is not established."
        if all_denied:
            ceiling = "Medium"
    elif kind == "Unauthorized access" and "attempts" in facts:
        f["reason"] = f"{facts['attempts']} traversal or privileged-access attempts are linked to this source. Recorded HTTP statuses: {status}. These show attempts, not proof of successful unauthorized access."
        if all_denied:
            ceiling = "Medium"
    elif kind == "Unusual request rate" and facts.get("peak_window_requests") is not None:
        count, window = facts["peak_window_requests"], facts["window_seconds"]
        f["reason"] = f"The peak recorded window is {count} requests in {window} seconds ({count/window:g} requests/second), with {facts['http_429_entries']} HTTP 429 entries. Overlapping counters are not summed. Abuse or service disruption requires further investigation."
        ceiling = "Medium"
    elif kind == "Prompt injection":
        f["reason"] = f"Instruction-like text appears in submitted log data. Recorded HTTP statuses: {status}. It is an attempted instruction injection; successful influence on a downstream system is not established."
        ceiling = "Low" if all_denied else "Medium"
    f["severity"] = LEVELS[min(LEVELS.index(f["severity"]), LEVELS.index(ceiling))]
    f["action"] = ACTIONS[kind]
    f["explanation_source"] = "Validated source facts; remediation from trusted policy. Raw model prose is retained in the call audit only."
    return f

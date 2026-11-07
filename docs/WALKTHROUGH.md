# Suggested 2–3 minute walkthrough

This is a recording script and explanation guide, not a claim that the applicant personally wrote every line.

**0:00–0:20 — Show the dashboard.** “This is a local security log analyzer. Upload a text log or load the supplied assessment sample. The model runs on the CPU; there are no cloud AI calls. The page shows source coverage, progress, memory and the final report.”

**0:20–0:45 — Explain the budget.** “The challenge limits the entire call to 2,048 tokens. I reserve 384 for output and 16 for safety. The backend applies the model's chat template, counts the actual token IDs, and submits that exact array. Entries stay intact when they fit; oversized entries use tracked fragments.”

**0:45–1:10 — Show call audit and resume.** “Each successful call and its next cursor commit together in SQLite. Failed calls retry without advancing. If the process restarts, completed calls remain. I tested pause, backend restart and resume on the actual supplied log. Only one model call runs at a time.”

**1:10–1:40 — Expand the linked login finding.** “The early failed logins are far from the later successful login. The evidence index groups the same IP, application and username, orders by event timestamp, and links the session's follow-up activity. The local model reviews those facts together. This is possible account compromise, not proof of malicious ownership.”

**1:40–2:05 — Explain accuracy controls.** “SQL payloads are decoded, duplicate events are counted once, and overlapping rate counters are not added together. A small model sometimes flags ordinary requests or invents references. I validate source lines and entity attribution, require supporting structured fields, and let the model reject final candidates. Routine database timeouts and normal health checks should remain unflagged.”

**2:05–2:30 — Explain security and tradeoffs.** “Logs are untrusted data. Nothing in the logs is executed, model control delimiters are escaped, and evidence is escaped in the browser. The model cache is disabled to control RAM. The tradeoffs are CPU latency, weaker reasoning from a small model, and limited parsing for arbitrary text log formats.”

**2:30–2:45 — Close with verification.** Show the test results, JSON export and README. Explain which checks were actually run and which were not. The optional Docker limit configuration requires separate validation on the target machine.

## Useful interview change

Change the candidate rate threshold in `app/correlate.py`, add a regression case, rerun pytest, and explain why a threshold nominates a candidate but does not independently publish a finding. Alternatively, add a structured field alias in `ingest.py` and preserve the same evidence-line contract.

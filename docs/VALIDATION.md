# Validation record

Verified on this Windows workstation on **7 November 2026**. The source input is the supplied `Cultive8_Workspace_Agrigen_Server.log`, copied unchanged into `samples/`.

## Automated checks

- **34 tests passed** with `python -m pytest -q`.
- Python compilation and JavaScript syntax checks passed.
- The test suite uses isolated temporary SQLite databases. Test doubles are never available through the runtime API.
- One dependency emits an AnyIO deprecation warning during tests; it did not affect the results.

## Actual local-model run

The report in `sample-report.json` came from the downloaded **Qwen2.5-1.5B-Instruct Q4_K_M** model using CPU llama.cpp, not a simulated response. Model downloads and Python setup were completed in this workspace.

| Measurement | Observed |
|---|---:|
| Physical source lines | 258 |
| Duplicate entries | 1 |
| Source chunk calls | 35 |
| Cross-log review calls | 12 (two rounds of six during prompt refinement) |
| Total saved calls | 47 |
| Final findings | 6 |
| Largest actual input | 1,641 tokens |
| Largest generated output | 340 tokens |
| Largest input + output in one call | 1,962 tokens |
| Sum of measured model-call times | 759.72 seconds |
| Highest sampled backend/model RSS | 2,123.6 MiB |
| Automatic retries during this sample run | 0 |

The peak includes early development calls before the prompt cache was disabled. After disabling it, the model and backend were observed near 1.8 GB. RSS is sampled around calls; this is not a kernel-level maximum measurement. The launcher is included in later measurements. Browser and other desktop applications are outside the server-process total.

All source chunk payloads were concatenated and checked against the complete source text: **exact coverage, with no missing or duplicated text**. Every saved call was checked against the input/output/total limits. `scripts/validate_sample.py JOB_ID` reproduces these assertions and writes `validation-metrics.json`.

This development run deliberately resumed retained checkpoints after prompt/resource refinements. It is evidence of checkpoint integrity and actual model execution, not a controlled model-quality benchmark with one unchanged prompt. A fresh run from the final source may differ in chunk boundaries, timing, and model decisions.

## Observed final report

| Finding | Entity | Grounded evidence |
|---|---|---|
| Possible account compromise · High | `203.0.113.44` | 12 failed logins, success at line 196, session activity at lines 198 and 201; linked back to line 5 |
| SQL injection · High | `203.0.113.72` | Four unique payload attempts; duplicate line 223 does not inflate the count |
| Scanning · Medium | `203.0.113.90` | Eight distinct sensitive/admin path probes |
| Unauthorized access · Medium | `203.0.113.90` | Traversal and privileged path attempts, HTTP 403 |
| Unusual request rate · Medium | `203.0.113.155` | Peak 135 requests / 10 seconds; nine HTTP 429 entries; counters not summed |
| Prompt injection · Low | `203.0.113.201` | Instruction-like submitted text at line 217; HTTP 422 |

No final findings were attributed to the registered health monitor (`192.0.2.10`) or the benign failed-then-successful login (`198.51.100.96`). Routine database/upstream errors did not become attack findings.

The small model did generate incorrect prose and unsafe remediation suggestions during development. `AI_USAGE.md` records these observations. The report renderer now uses source-derived explanations and trusted remediation policies, applies conservative severity ceilings, and confines raw model prose to the audit. This does not establish universal detection accuracy or immunity to adversarial inputs.

## Recovery and interface checks

- Paused an actual run, restarted the backend/model, and resumed through the dashboard with completed calls intact.
- Inspected the local dashboard, selected the existing analysis from history, verified live progress, and exercised Resume.
- Verified the completed report, severity filtering, and expanded evidence; confirmed that the prompt-injection finding recommends preserving evidence. Saved `dashboard-proof.jpg` from the companion preview.
- Tests exercised malformed model JSON, response truncation, timeout/backoff, oversized Unicode entries, multipart/chunked upload limits, invalid files, source attribution, duplicate reviews, and source/cursor checkpoint atomicity.
- Tested unknown-host and cross-origin write rejection. No model or log command execution endpoint exists.

## Verification limits

- Native runtime was tested with two inference threads on this workstation, **not** on a dedicated 2-vCPU/4-GB VM. Docker has resource limits configured but was not built or run here.
- The OS network was not disconnected. Offline capability is supported by local-only runtime requests, vendored assets, disabled CDN documentation pages and loopback model enforcement; a physically disconnected test remains a deployment check.
- Browser preview supports a narrow companion panel; desktop-wide viewport overrides did not reliably map to capture size. Narrow-layout rendering and functional controls were inspected; full desktop viewport coverage is not claimed.

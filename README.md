# Cultive8 · Local security log analyzer

A local web application that turns large server logs into a single, evidence-backed investigation report. It uses a downloaded **Qwen2.5-1.5B-Instruct Q4_K_M** model through **llama.cpp**, runs on CPU, and never calls a cloud AI API.

The supplied `samples/Cultive8_Workspace_Agrigen_Server.log` is the real assessment input, copied unchanged. Sample IP addresses, expected findings and line numbers are **not hardcoded in the application**. Sample-specific assertions live only in regression tests.

## Run on Windows

Requirements: Windows x64, Python 3.11+, internet during setup, approximately 2 GB free disk for the model/runtime plus the Python environment. No GPU or Node build is required.

```powershell
python scripts/setup.py
python scripts/run.py
```

Open **http://127.0.0.1:8000**. Select **Load supplied log** or upload a UTF-8 `.log` / `.txt` file, then select **Start analysis**. The setup has already been run in this workspace.

`setup.py` creates `.venv`, installs pinned dependencies, downloads the CPU runtime and model, and verifies SHA-256 digests published by GitHub/Hugging Face. Downloads use partial files and pinned revisions. The local model manifest is saved in `models/manifest.json`. These large files are intentionally ignored by Git.

After setup, disconnect the internet and run `scripts/run.py` again. All runtime assets, including CSS, JavaScript, and fonts, are local. **Ctrl+C** stops the backend and model. A job interrupted by a restart resumes automatically from the last committed call; a deliberately paused job remains paused until resumed. An in-flight call may finish after Pause is clicked.

### Linux / Docker (optional)

The native implementation is verified on Windows. The Docker recipe is provided for an explicit **4 GiB / 2 CPU** process limit, but has not been executed in this workspace. Download the same model first with `scripts/setup.py`; on Linux the script expects an independently installed `llama-server` for native use. Docker builds its own pinned CPU binary.

```sh
docker compose build
docker compose up
```

The container exposes only `127.0.0.1:8000` on the host. Model weights are mounted read-only; checkpoints persist under `data/`. Build/setup require networking. Runtime does not. Do not launch the native and Docker versions on the same ports simultaneously.

## Model and resource choices

| Setting | Value |
|---|---|
| Model | Qwen/Qwen2.5-1.5B-Instruct-GGUF |
| Quantization | Q4_K_M, 1,117,320,736 bytes |
| Model revision | `91cad51170dc346986eccefdc2dd33a9da36ead9` |
| Runtime | llama.cpp `b12183`, CPU x64 |
| Context | 2,048 tokens, no context shifting |
| CPU | 2 generation threads, 2 prompt threads, 0 GPU layers |
| Concurrency | One backend worker, one queue consumer, one model slot |
| Batch / microbatch | 256 / 128 |
| Prompt cache RAM / checkpoints | Disabled; avoids llama.cpp's large default cache |
| Upload bounds | 5 MiB, 25,000 physical lines, 1 MiB per entry |

The assessment permits any downloaded local model; its suggested models are not mandatory. This established 1.5B quantized model fits the resource budget with a modest CPU footprint. It is less reliable than a large model, so the application validates references, applies source-based evidence checks and performs a separate cross-log model review. It does not train or fine-tune a model.

The dashboard reports backend + model + launcher RSS when launched using `run.py`; it explicitly labels backend-only measurements when started independently. The engine records the largest sampled RSS and stops before another call if it exceeds 3,500 MiB. This is an application safeguard, **not a hard OS memory limit**. Docker supplies the hard limit. Native two-thread testing is not equivalent to benchmarking on a machine with only two vCPUs; timings depend on the host.

## How analysis works

1. **Ingest without executing content.** The upload is read in 64 KiB blocks. UTF-8 and content limits are validated. Entries and original physical line ranges are indexed in SQLite. Indented stack-trace continuations stay together. Exact duplicate entries point to their first occurrence; duplicate lines remain in the source audit but count once in correlation.
2. **Split using the real tokenizer.** The backend applies the loaded model's chat template with `/apply-template`, then obtains token IDs from `/tokenize` with special tokens enabled. It sends that exact ID array to `/completion`. Complete entries are packed greedily; oversized entries are split at a character boundary by binary search with exact token checks. Fragment offsets ensure that no text is lost or duplicated.
3. **Analyze every chunk.** A structured system prompt separates instructions from untrusted logs. Relevant prior facts, keyed by IP, are carried into later calls where space permits. Source records remain on disk even when prompt memory is trimmed. Schema-constrained JSON replies are parsed and validated. An entity must actually occur on every cited source entry; invented/out-of-context citations are discarded.
4. **Checkpoint atomically.** Each successful call saves its payload, raw structured response, timing, token counts, validated proposals, and the next source cursor in one SQLite transaction. A retry cannot partially advance the cursor. Failed attempts are retained separately for diagnosis.
5. **Correlate the entire log.** A source-derived index nominates repeated login failures followed chronologically by success, SQL payloads, probes, traversal/privileged-access attempts, request bursts, and instruction-like submitted text. Authentication groups include IP + application + username, with session IDs for follow-up activity. SQL payloads are percent-decoded up to three times. Rate counters are never summed across overlapping windows. Chunk-model hypotheses can add supported candidates.
6. **Ask the local model to adjudicate.** Every final candidate gets a separate, budgeted local-model call with evidence from across the file. The model can return an empty result. Rule nominations alone never become final findings. The final type/entity/line schema is restricted to that candidate's supplied evidence. Related chunk findings merge by attack family, entity and account scope; successful-login sequences supersede a standalone brute-force finding for that account.
7. **Show one report.** Every finding includes type, severity, entity, explanation, suggested action, model-cited lines, all related source evidence, and the contributing chunk IDs. The model adjudicates candidates; the displayed explanation is then rendered from validated source facts and the action comes from a trusted policy table. Conservative severity ceilings prevent blocked probes from becoming Critical findings. Raw model prose is confined to the audit: the adversarial log demonstrated that a small model can repeat malicious instructions even with a protective prompt. Reports are clearly marked partial until the entire pipeline finishes. JSON export includes coverage, model-call audit, duplicate count and memory measurements.

### Token budget

```text
  2,048 total context tokens
-   384 reserved output tokens
-    16 safety tokens
= 1,648 maximum actual input tokens
```

The 1,648 input allowance includes **system instructions + chat template + task + saved facts + numbered log text**. It is not a log-only estimate. There is no characters/4 approximation in runtime code. Context shift is disabled; overflow/truncation fails the call rather than silently dropping evidence. Correlation calls use the identical budget.

### Reliability and safety

- A failed call retries up to three times with bounded backoff; completed calls survive failure. Broken/incomplete JSON is never committed as a completed finding. JSON fences are accepted; truncated JSON is not repaired by guessing missing evidence.
- Failed jobs expose the cause and a **Resume analysis** button. Retries use the same source cursor; sampling is deterministic.
- Log contents cannot launch commands, tools or shell processes. Chat control delimiters are escaped before templating. Browser output is HTML-escaped, and a restrictive CSP blocks inline scripts and third-party assets.
- The model endpoint must be loopback HTTP; redirects and environment proxies are disabled. The launcher creates an ephemeral API key shared through environment variables and never puts it in source files or command arguments.
- The app binds to loopback by default, blocks unexpected Host headers and cross-origin writes, and has no external analytics or telemetry. It is intended for a trusted single-user machine, not a publicly exposed multi-tenant server.
- Logs, model responses and reports are stored **unencrypted** in `data/analyzer.sqlite3`. Treat that directory as sensitive. The API permits deletion of settled jobs; it cannot delete a running or paused in-flight analysis.

## Verify

```powershell
.venv\Scripts\python -m pytest -q
.venv\Scripts\python -m compileall -q app scripts
```

Tests cover supplied-log evidence and benign controls, account isolation, event-time order, duplicate suppression, oversized Unicode entries, multiline ranges, interruption/resume, model-required final findings, hallucinated references, malformed JSON, timeouts, truncation, blocked cloud endpoints, invalid uploads and cross-origin requests. Test doubles are confined to `tests/`; there is no fake-model runtime mode.

See `docs/VALIDATION.md` for observed real-model results and verification limits. Use `GET /api/jobs/{id}/calls` to inspect the actual prompts and responses, or expand **Model call audit** in the dashboard. The API schema is available offline at `/openapi.json`; CDN-dependent Swagger pages are disabled.

## Project map

```text
app/main.py        HTTP API, upload validation, local-only protections
app/model.py       Prompt, JSON schema, exact token counting, retry policy
app/ingest.py      Streaming entry ingestion and duplicate indexing
app/correlate.py   Generic evidence indexing and cross-file candidate generation
app/engine.py      Single queue, chunk packing, checkpointing and model review
app/store.py       SQLite schema and report retrieval
app/reporting.py   Grounded explanations, severity ceilings, trusted remediation
app/static/        Offline dashboard (vanilla HTML/CSS/JS)
scripts/setup.py   One-time pinned dependency/runtime/model downloads
scripts/run.py     CPU model and backend process lifecycle
tests/             Regression suite (no model download required to test)
samples/           Supplied assessment log, unchanged
AI_USAGE.md        AI assistance, prompts, changes and observed mistakes
```

## Known limits and tradeoffs

- Small local models can miss threats or write inaccurate explanations despite valid citations. Findings remain **possible threats**, not confirmed attacks. A clean report is not a security guarantee.
- Structured correlation supports JSON object logs using fields such as `client_ip`, `time`, `path`, `status`, `username`, `auth_result` and `session_id`. Arbitrary text logs are still chunk-analyzed by the model, but their cross-file correlation is less reliable. IPv6 works for explicit structured IP fields; the plain-text fallback extracts IPv4 only.
- Cross-log review samples first/last evidence excerpts when a group is large, while retaining complete source line references. It can lose subtle middle-event context. Oversized entries may lose semantic context across fragments even though text coverage remains exact.
- IP-based grouping is not identity proof (NAT, proxies and reassigned addresses). Rate thresholds are candidate heuristics, not a universal traffic baseline. The model must consider legitimate context.
- Exact duplicate text is deduplicated. Semantically identical but differently formatted entries are not currently deduplicated by event/request ID.
- A single queue trades throughput for predictable memory. No GPU acceleration, authentication, multi-user isolation, live tailing or automatic incident remediation is included.
- Model-response timeouts retry; tokenizer/template network failures stop the job safely and require Resume. A repeated deterministic malformed reply may continue failing until the model/prompt is adjusted. No completed evidence is erased.

## Submission

The local Git repository contains source, setup instructions, tests, `AI_USAGE.md`, and walkthrough materials. 

- [AI usage record](AI_USAGE.md)
- [Actual-run validation](docs/VALIDATION.md) and [exported sample report](docs/sample-report.json)
- [Walkthrough script](docs/WALKTHROUGH.md)

Model/runtime primary references: [Qwen model card](https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF), [llama.cpp server documentation](https://github.com/ggml-org/llama.cpp/tree/master/tools/server), [pinned runtime release](https://github.com/ggml-org/llama.cpp/releases/tag/b12183).

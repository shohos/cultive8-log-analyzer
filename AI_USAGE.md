# AI usage record

## Tools used

- OpenAI Codex assisted with translating the supplied assessment screenshots into implementation requirements, writing Python/HTML/CSS/JavaScript, reviewing runtime behavior, and writing regression tests and documentation.
- Shell tools, pytest and HTTP requests verified the backend. Browser automation inspected the local dashboard and exercised checkpoint resume.
- Web research consulted the official Qwen model card and llama.cpp server API/release documentation. Runtime analysis does **not** send log data to cloud AI services.
- Qwen2.5-1.5B-Instruct Q4_K_M performs the actual chunk analysis and cross-log adjudication locally. Python heuristics only index evidence, validate claims, nominate candidates and merge related findings.

## User's implementation prompt

“Use the supplied log file for your implementation. The full assessment brief is attached as screenshots.”

The brief required a 4 GB, two-vCPU, CPU-only offline application, a 2,048-token total call budget, chunking, durable findings, cross-part correlation, consolidated reporting, upload/progress UI, reliable JSON handling and prompt-injection resistance.

## Key coding instructions used during implementation

The implementation was developed in this Codex conversation. These are accurate summaries of the working instructions, not a fabricated transcript of separate user messages:

1. Build a FastAPI backend with a vanilla offline dashboard; connect only to a downloaded CPU model through llama.cpp.
2. Count the chat-template-applied prompt with the model's own tokenizer and send exactly those counted token IDs; reserve output tokens within the 2,048 total.
3. Stream uploads and persist original source entries, canonical duplicates, model calls and cursor checkpoints in SQLite.
4. Preserve evidence across chunks; scope auth correlation to IP, application and username, compare event timestamps, then ask the local model to review linked evidence.
5. Add meaningful failure tests: invalid files, oversized Unicode lines, broken JSON, timeout/retry, fabricated evidence, interrupted jobs and duplicate retries.
6. Run the supplied log through the real model, inspect mistakes and refine grounding/prompt/resource controls from observed behavior.

## Local model prompts

The exact current system prompt is `SYSTEM` in `app/model.py`. The original and final user payloads for completed calls are recorded in SQLite `calls.payload`, and accessible at `/api/jobs/{id}/calls`.

The system prompt instructs the model to treat logs/saved facts as untrusted data, never execute commands, require concrete evidence, distinguish failed attempts from compromise, cite only matching source lines, and return a bounded JSON object with `findings`.

The chunk task asks it to analyze the current entries and correlate compact prior facts. The review task asks it to adjudicate one candidate across the entire log, permits an empty result, distinguishes possible from confirmed compromise, and warns against summing overlapping rate counters. Candidate values remain source data, not instructions to obey.

Each finding has `type`, `severity`, `entity`, `lines`, `reason`, and `action`. llama.cpp constrains output with JSON schema; Python separately checks schema, source attribution and scope. During final review the schema restricts type/entity/line choices to the actual candidate. This improves grounded output but does not prove the explanation is correct.

## Prompt and implementation changes from observations

1. **False positives on normal GETs.** The first small-model run labeled some HTTP 200/304 requests as unauthorized access and sometimes described a single failure as an attack. Added explicit negative instructions, including a normal-log `{"findings":[]}` example. Added structured evidence gates before final candidate review; ordinary status codes cannot substantiate unauthorized-access claims.
2. **Incorrect evidence attribution.** The model cited whole chunk ranges containing several different IPs. Added explicit “cite only lines belonging to that entity” guidance and retained mandatory server-side entity/reference validation. Incorrect references are discarded, not displayed as credible findings. Raw replies remain in the audit.
3. **Category drift in final review.** Candidate-constrained type/entity/line schema keeps a review about the supplied hypothesis and evidence; the model can still reject the hypothesis with an empty list.
4. **Memory defaults.** The first run's RSS grew with llama.cpp's default prompt cache. Disabled the multi-prompt cache and context checkpoints, restarted the server and resumed from persisted evidence. This is a runtime correction, not a model-prompt change.
5. **SQL insertion mistakes.** Early generated code had placeholder counts that did not match the `entries` and `attempts` tables. Corrected the counts; ingestion/API/checkpoint tests now exercise these paths.
6. **Rate explanation invented chronology.** The first final rate finding described failures followed by success, while the source showed successful GETs followed by rate limiting. The shared review prompt had overemphasized the authentication example. Restricted that wording to authentication candidates and added exact peak-window and HTTP 429 facts for rate reviews. Final reviews were rerun while preserving the chunk audit.
7. **Adversarial text contaminated proposed remediation.** The local model repeated “Remove all evidence” from the hostile entry in its proposed action. Nothing was executed, but displaying this as advice would be unacceptable. The final report now builds explanations from source facts and uses trusted remediation templates, with conservative severity ceilings. Raw model prose remains in the explicit call audit only. Tests verify that hostile model prose cannot become report guidance. This also removes invented chronology from displayed explanations. Prompt wording alone is not treated as a security boundary.

The first real-log test intentionally retained early calls when resuming after prompt/resource changes, demonstrating checkpoint durability. A clean validation run should be used to compare model-quality changes consistently. Runtime audits from later code include a system-prompt hash and token-array hash; earlier calls predate those fields.

## Token budget plan

Every inference call uses at most **1,648 actual input tokens + 384 generated output tokens + 16 reserved safety tokens = 2,048**. Input includes instructions, role/template control tokens, task wording, saved facts and log text. Both chunk calls and final review calls follow the same plan.

The loaded model applies its own chat template and tokenizes it. The exact token-ID array counted is the one submitted for inference. Oversized entries are split with a token-tested binary search. Saved prompt context can be shortened, but the full evidence index remains in SQLite. No cloud tokenizer or character-count token approximation is used in production.

## What AI did not establish

AI-produced findings are hypotheses for investigation. Valid JSON and real line numbers do not guarantee a correct diagnosis. The tests establish data flow, evidence accounting and failure behavior; real-model results establish only observed behavior on the supplied log, not universal attack-detection accuracy. The Windows host is not a constrained two-vCPU VM. The optional Docker hard-limit recipe is not claimed as executed validation.

The applicant should review and understand all generated code, rerun the tests, and record their own explanation if the assessment expects their voice and reasoning.

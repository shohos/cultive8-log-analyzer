const $ = (id) => document.getElementById(id);
let current = null,
  filter = "All",
  busy = false;
const escape = (s) =>
  String(s ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
function error(message) {
  $("alert").textContent = message;
  $("alert").hidden = !message;
}
async function api(path, options = {}) {
  const response = await fetch(path, options);
  const data = await response.json();
  if (!response.ok)
    throw new Error(
      typeof data.detail === "string"
        ? data.detail
        : "The request could not be completed.",
    );
  return data;
}
async function action(fn) {
  if (busy) return;
  busy = true;
  error("");
  try {
    await fn();
  } catch (e) {
    error(e.message);
  } finally {
    busy = false;
  }
}
async function loadFile(file) {
  if (!file) return;
  if (!/\.(log|txt)$/i.test(file.name) || file.size > 5 * 1024 * 1024)
    return error("Choose a .log or .txt file smaller than 5 MiB.");
  await action(async () => {
    const body = new FormData();
    body.append("file", file);
    current = await api("/api/jobs", { method: "POST", body });
    localStorage.setItem("analysis", current.id);
    render();
    await history();
  });
}
$("file").addEventListener("change", (e) => loadFile(e.target.files[0]));
["dragenter", "dragover"].forEach((event) =>
  $("drop-zone").addEventListener(event, (e) => {
    e.preventDefault();
    $("drop-zone").classList.add("drag");
  }),
);
["dragleave", "drop"].forEach((event) =>
  $("drop-zone").addEventListener(event, (e) => {
    e.preventDefault();
    $("drop-zone").classList.remove("drag");
  }),
);
$("drop-zone").addEventListener("drop", (e) =>
  loadFile(e.dataTransfer.files[0]),
);
$("sample").onclick = () =>
  action(async () => {
    $("sample").disabled = true;
    try {
      current = await api("/api/sample", { method: "POST" });
      localStorage.setItem("analysis", current.id);
      render();
      await history();
    } finally {
      $("sample").disabled = false;
    }
  });
$("start").onclick = () =>
  action(async () => {
    current = await api(`/api/jobs/${current.id}/start`, { method: "POST" });
    render();
  });
$("pause").onclick = () =>
  action(async () => {
    current = await api(`/api/jobs/${current.id}/pause`, { method: "POST" });
    render();
  });
document.querySelectorAll("[data-filter]").forEach(
  (button) =>
    (button.onclick = () => {
      filter = button.dataset.filter;
      document
        .querySelectorAll("[data-filter]")
        .forEach((b) => b.classList.toggle("active", b === button));
      renderFindings();
    }),
);
function render() {
  if (!current) return;
  const active = ["running", "queued"].includes(current.status);
  $("entries").textContent = current.total_entries.toLocaleString();
  $("entry-sub").textContent =
    `${current.total_lines} lines · ${current.duplicates} duplicate${current.duplicates === 1 ? "" : "s"}`;
  $("finding-count").textContent = current.findings.length;
  const high = current.findings.filter((f) =>
    ["High", "Critical"].includes(f.severity),
  ).length;
  $("finding-sub").textContent = high
    ? `${high} high-priority finding${high === 1 ? "" : "s"}`
    : current.complete
      ? "Review the supporting evidence"
      : "Cross-log review pending";
  $("links").textContent = current.findings.filter((f) => f.cross_chunk).length;
  $("selected-file").hidden = false;
  $("file-name").textContent = current.name;
  $("file-meta").textContent =
    `${(current.bytes / 1024).toFixed(1)} KB · ${current.total_lines} lines · Saved locally`;
  $("start").disabled = active || current.complete;
  $("start").textContent =
    current.status === "failed" || current.status === "paused"
      ? "Resume analysis →"
      : current.complete
        ? "Analysis complete ✓"
        : active
          ? "Analyzing…"
          : "Start analysis →";
  $("pause").hidden = !active;
  $("job-status").textContent = current.status.toUpperCase();
  $("progress").value = current.coverage_percent;
  $("progress-number").textContent = `${current.coverage_percent}%`;
  $("progress-label").textContent = current.complete
    ? `Complete · ${current.calls} model calls`
    : current.phase === "correlation"
      ? "Reviewing connected evidence…"
      : `${Math.min(current.cursor - 1, current.total_lines)} / ${current.total_lines} lines · ${current.calls} calls saved`;
  $("stage-0").className = "done";
  $("stage-1").className =
    current.coverage_percent === 100 ? "done" : active ? "current" : "";
  $("stage-2").className = current.complete
    ? "done"
    : current.phase === "correlation"
      ? "current"
      : "";
  $("export").hidden = false;
  $("export").href = `/api/jobs/${current.id}/report`;
  $("report-count").textContent = current.findings.length;
  $("report-caption").textContent = current.complete
    ? "Consolidated · All chunks reviewed"
    : "Partial report · Analysis not complete";
  $("audit-sub").textContent =
    `${current.calls} saved calls · ${current.retries} retries · peak ${current.peak_rss_mb} MB`;
  $("calls").innerHTML = current.call_history
    .map(
      (c) =>
        `<tr><td>${c.seq}</td><td>${escape(c.phase)}</td><td>${c.start_line}–${c.end_line}</td><td>${c.input_tokens}</td><td>${c.output_tokens} / 384</td><td>${c.seconds}s</td><td>${c.attempt}</td></tr>`,
    )
    .join("");
  if (current.error) error(current.error);
  renderFindings();
}
function renderFindings() {
  if (!current) return;
  const opened = new Set(
    [...document.querySelectorAll(".finding[open]")].map((x) => x.dataset.key),
  );
  const findings = current.findings
    .filter((f) => filter === "All" || f.severity === filter)
    .sort(
      (a, b) =>
        ["Critical", "High", "Medium", "Low"].indexOf(a.severity) -
        ["Critical", "High", "Medium", "Low"].indexOf(b.severity),
    );
  if (!findings.length) {
    $("findings").innerHTML =
      `<div class="empty"><span class="empty-icon">⌕</span><h3>${current.complete ? "No findings in this view." : "Building the evidence trail."}</h3><p>${current.complete ? "No model-confirmed findings match this filter.<br>This does not guarantee that the log is free of threats." : "Completed model calls are saved as analysis progresses.<br>Connected findings appear during the final review."}</p></div>`;
    return;
  }
  $("findings").innerHTML = findings
    .map((f) => {
      const key = f.type + f.entity + (f.scope || "");
      return `<details class="finding" data-key="${escape(key)}" ${opened.has(key) ? "open" : ""}><summary><span class="severity ${escape(f.severity)}">${escape(f.severity)}</span><div class="finding-title"><strong>${escape(f.type)}</strong><small>${escape(f.entity)}${f.scope ? " · " + escape(f.scope) : ""}</small></div>${f.cross_chunk ? `<span class="link-tag">⇄ ${f.chunks.length} chunks linked</span>` : '<span class="link-tag">Evidence verified</span>'}</summary><div class="finding-body"><p>${escape(f.reason)}</p><div class="action"><strong>Suggested action</strong> &nbsp; ${escape(f.action)}</div><div class="evidence-label">SOURCE EVIDENCE · ${f.lines.length} UNIQUE ENTRIES</div><p class="evidence-meta">Model-cited lines: ${f.model_cited_lines.join(", ")}. Related evidence is linked by source identity and event facts.</p><div>${f.evidence.map((e) => `<div class="evidence-line"><b>L${e.line}${e.end_line !== e.line ? "–" + e.end_line : ""}</b><pre>${escape(e.raw)}</pre></div>`).join("")}</div></div></details>`;
    })
    .join("");
}
async function history() {
  const jobs = await api("/api/jobs");
  $("history-list").innerHTML = jobs.length
    ? jobs
        .map(
          (j) =>
            `<button class="history-item" data-job="${j.id}"><span>▤</span><strong>${escape(j.name)}</strong><small>${j.total_lines} lines &nbsp;·&nbsp; ${escape(j.status)} &nbsp;↗</small></button>`,
        )
        .join("")
    : '<p class="subtle">Your saved analyses will appear here.</p>';
  document.querySelectorAll("[data-job]").forEach(
    (b) =>
      (b.onclick = () =>
        action(async () => {
          current = await api(`/api/jobs/${b.dataset.job}`);
          localStorage.setItem("analysis", current.id);
          render();
          $("report").scrollIntoView({ behavior: "smooth" });
        })),
  );
}
$("refresh-history").onclick = () => action(history);
async function poll() {
  try {
    const h = await api("/api/health");
    $("connection").textContent = h.model_ready
      ? "Local model connected"
      : "Local model offline";
    $("connection").classList.toggle("offline", !h.model_ready);
    $("memory").innerHTML = `${h.rss_mb.toFixed(0)}<small>MB</small>`;
    $("memory-sub").textContent = h.memory_includes_model
      ? "Backend + model · 4 GB budget"
      : "Backend only · model not tracked";
    if (current && ["queued", "running", "paused"].includes(current.status)) {
      const id = current.id;
      const fresh = await api(`/api/jobs/${id}`);
      if (current.id === id) {
        current = fresh;
        render();
      }
    }
  } catch (e) {
    $("connection").textContent = "Backend disconnected";
    $("connection").classList.add("offline");
  }
  setTimeout(poll, 3000);
}
(async () => {
  try {
    await history();
    const saved = localStorage.getItem("analysis");
    if (saved) {
      current = await api(`/api/jobs/${saved}`);
      render();
    }
  } catch (e) {
    localStorage.removeItem("analysis");
  }
  poll();
})();

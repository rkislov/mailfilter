const API_BASE = "__API_BASE__";

async function api(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json();
}

function renderStats(summary) {
  const stats = [
    ["Messages", summary.total_messages],
    ["Accepted", summary.accepted_messages],
    ["Rejected", summary.blocked_messages],
    ["Quarantined", summary.quarantined_messages],
    ["Avg score", summary.avg_score.toFixed(2)],
    ["Provider failures", summary.provider_failures],
  ];
  const root = document.getElementById("stats-grid");
  root.innerHTML = stats
    .map(
      ([label, value]) =>
        `<div class="rounded-2xl border border-slate-800 bg-slate-950/60 p-5">
          <p class="text-xs font-semibold uppercase tracking-[0.25em] text-slate-400">${label}</p>
          <p class="mt-3 text-3xl font-semibold text-white">${value}</p>
        </div>`
    )
    .join("");
}

function renderRows(targetId, items, mapper) {
  const root = document.getElementById(targetId);
  root.innerHTML =
    items.map(mapper).join("") ||
    `<div class="rounded-2xl border border-dashed border-slate-800 bg-slate-950/40 p-5 text-sm text-slate-400">No data yet.</div>`;
}

function fillClamavForm(settings, path) {
  const form = document.getElementById("clamav-form");
  form.database_mirror.value = settings.database_mirror || "";
  form.private_mirror.value = settings.private_mirror || "";
  form.dns_database_info.value = settings.dns_database_info || "";
  form.checks.value = settings.checks || 24;
  form.script_updated.checked = !!settings.script_updated;
  form.compress_local_database.checked = !!settings.compress_local_database;
  form.notify_clamd.checked = !!settings.notify_clamd;
  document.getElementById("clamav-config-path").textContent = `Generated config: ${path}`;
}

async function loadDashboard() {
  const dashboard = await api("/dashboard");
  renderStats(dashboard.summary);
}

async function loadSettings() {
  const settings = await api("/settings");
  renderRows(
    "providers-table",
    settings.providers,
    (provider) => `
      <div class="rounded-2xl border border-slate-800 bg-slate-950/50 p-4">
        <div class="flex flex-wrap items-center justify-between gap-3">
          <strong class="text-base text-white">${provider.name}</strong>
          <span class="rounded-full border border-slate-700 px-3 py-1 text-xs uppercase tracking-[0.2em] text-slate-300">${provider.kind}</span>
        </div>
        <div class="mt-3 grid gap-1 text-sm text-slate-400">
          <span>enabled: ${provider.enabled}</span>
          <span>base_url: ${provider.base_url || "-"}</span>
        </div>
      </div>
    `
  );
}

async function loadMessages() {
  const messages = await api("/messages");
  renderRows(
    "messages-table",
    messages,
    (message) => `
      <button class="rounded-2xl border border-slate-800 bg-slate-950/50 p-4 text-left transition hover:border-emerald-400/50 hover:bg-slate-900" onclick="loadTrace(${message.id})">
        <strong class="text-base text-white">#${message.id} ${message.subject || "(no subject)"}</strong>
        <div class="mt-2 grid gap-1 text-sm text-slate-400">
          <span>${message.mail_from} -> ${message.rcpt_to.join(", ")}</span>
          <span>action: ${message.final_action} | score: ${message.spam_score.toFixed(2)}</span>
        </div>
      </button>
    `
  );
}

async function loadTrace(messageId) {
  const trace = await api(`/messages/${messageId}/trace`);
  document.getElementById("message-trace").innerHTML = `
    <div class="rounded-2xl border border-slate-800 bg-slate-950/60 p-4">
      <p class="mb-3 text-xs font-semibold uppercase tracking-[0.25em] text-slate-400">Decision chain</p>
      <pre class="overflow-x-auto whitespace-pre-wrap text-sm text-slate-300">${JSON.stringify(trace, null, 2)}</pre>
    </div>
  `;
}

async function loadAudit() {
  const audit = await api("/audit");
  renderRows(
    "audit-table",
    audit,
    (event) => `
      <div class="rounded-2xl border border-slate-800 bg-slate-950/50 p-4">
        <strong class="text-base text-white">${event.action}</strong>
        <div class="mt-2 grid gap-1 text-sm text-slate-400">
          <span>${event.user_email}</span>
          <span>${new Date(event.created_at).toLocaleString()}</span>
        </div>
      </div>
    `
  );
}

async function loadClamavMirrors() {
  const data = await api("/providers/clamav/mirrors");
  fillClamavForm(data.settings, data.config_path);
}

async function saveClamavMirrors(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const payload = {
    database_mirror: form.database_mirror.value,
    private_mirror: form.private_mirror.value || null,
    dns_database_info: form.dns_database_info.value || null,
    checks: Number(form.checks.value || 24),
    script_updated: form.script_updated.checked,
    compress_local_database: form.compress_local_database.checked,
    notify_clamd: form.notify_clamd.checked,
  };
  const data = await api("/providers/clamav/mirrors", {
    method: "PUT",
    body: JSON.stringify(payload),
  });
  fillClamavForm(data.settings, data.config_path);
}

async function bootstrap() {
  document.getElementById("refresh-dashboard").addEventListener("click", loadDashboard);
  document.getElementById("refresh-messages").addEventListener("click", loadMessages);
  document.getElementById("clamav-form").addEventListener("submit", saveClamavMirrors);
  await Promise.all([loadDashboard(), loadSettings(), loadMessages(), loadAudit(), loadClamavMirrors()]);
}

bootstrap().catch((error) => {
  document.getElementById("stats-grid").innerHTML = `<div class="rounded-2xl border border-rose-500/30 bg-rose-500/10 p-5 text-sm text-rose-100">Failed to load UI: ${error.message}</div>`;
});

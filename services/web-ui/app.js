const API_BASE = "__API_BASE__";

function byId(id) {
  return document.getElementById(id);
}

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

function renderList(targetId, items, mapper, emptyText = "Пока нет данных.") {
  const root = byId(targetId);
  if (!root) {
    return;
  }
  root.innerHTML =
    items.map(mapper).join("") ||
    `<div class="rounded-2xl border border-dashed border-slate-800 bg-slate-950/40 p-5 text-sm text-slate-400">${emptyText}</div>`;
}

function setActiveNav() {
  const current = window.location.pathname === "/" ? "/index.html" : window.location.pathname;
  document.querySelectorAll("[data-nav]").forEach((link) => {
    const isActive = link.getAttribute("href") === current;
    link.classList.toggle("border-emerald-400", isActive);
    link.classList.toggle("bg-slate-900", isActive);
    link.classList.toggle("text-white", isActive);
    link.classList.toggle("text-slate-300", !isActive);
  });
}

function renderStats(summary) {
  const root = byId("stats-grid");
  if (!root) {
    return;
  }
  const stats = [
    ["Всего писем", summary.total_messages],
    ["Принято", summary.accepted_messages],
    ["Отклонено", summary.blocked_messages],
    ["Карантин", summary.quarantined_messages],
    ["Средний score", summary.avg_score.toFixed(2)],
    ["Сбои провайдеров", summary.provider_failures],
  ];
  root.innerHTML = stats
    .map(
      ([label, value]) => `
        <div class="rounded-2xl border border-slate-800 bg-slate-950/60 p-5">
          <p class="text-xs font-semibold uppercase tracking-[0.25em] text-slate-400">${label}</p>
          <p class="mt-3 text-3xl font-semibold text-white">${value}</p>
        </div>
      `
    )
    .join("");
}

function fillClamavForm(settings, path) {
  const form = byId("clamav-form");
  if (!form) {
    return;
  }
  form.database_mirror.value = settings.database_mirror || "";
  form.private_mirror.value = settings.private_mirror || "";
  form.dns_database_info.value = settings.dns_database_info || "";
  form.checks.value = settings.checks || 24;
  form.script_updated.checked = !!settings.script_updated;
  form.compress_local_database.checked = !!settings.compress_local_database;
  form.notify_clamd.checked = !!settings.notify_clamd;
  const summary = byId("clamav-config-path");
  if (summary) {
    summary.textContent = `Сгенерированный файл: ${path}`;
  }
}

function fillAiRuntimeForm(settings) {
  const form = byId("ai-runtime-form");
  if (!form) {
    return;
  }
  form.provider_mode.value = settings.provider_mode || "disabled";
  form.ollama_base_url.value = settings.ollama_base_url || "";
  form.ollama_model.value = settings.ollama_model || "";
  form.gpustack_base_url.value = settings.gpustack_base_url || "";
  form.gpustack_model.value = settings.gpustack_model || "";
  form.gpustack_api_key.value = settings.gpustack_api_key || "";
  const summary = byId("ai-runtime-summary");
  if (summary) {
    summary.textContent =
      `Активный режим: ${settings.provider_mode}\nМодель Ollama: ${settings.ollama_model}\nМодель GPUStack: ${settings.gpustack_model}`;
  }
}

async function loadDashboard() {
  const dashboard = await api("/dashboard");
  renderStats(dashboard.summary);
}

async function loadProviders() {
  const settings = await api("/settings");
  renderList(
    "providers-table",
    settings.providers,
    (provider) => `
      <div class="rounded-2xl border border-slate-800 bg-slate-950/50 p-4">
        <div class="flex flex-wrap items-center justify-between gap-3">
          <strong class="text-base text-white">${provider.name}</strong>
          <span class="rounded-full border border-slate-700 px-3 py-1 text-xs uppercase tracking-[0.2em] text-slate-300">${provider.kind}</span>
        </div>
        <div class="mt-3 grid gap-1 text-sm text-slate-400">
          <span>Активен: ${provider.enabled ? "да" : "нет"}</span>
          <span>URL: ${provider.base_url || "-"}</span>
        </div>
      </div>
    `
  );
}

async function loadMessages() {
  const messages = await api("/messages");
  renderList(
    "messages-table",
    messages,
    (message) => `
      <button class="rounded-2xl border border-slate-800 bg-slate-950/50 p-4 text-left transition hover:border-emerald-400/50 hover:bg-slate-900" onclick="loadTrace(${message.id})">
        <strong class="text-base text-white">#${message.id} ${message.subject || "(без темы)"}</strong>
        <div class="mt-2 grid gap-1 text-sm text-slate-400">
          <span>${message.mail_from} -> ${message.rcpt_to.join(", ")}</span>
          <span>Действие: ${message.final_action} | score: ${message.spam_score.toFixed(2)}</span>
        </div>
      </button>
    `,
    "Сообщения еще не обрабатывались."
  );
}

async function loadTrace(messageId) {
  const trace = await api(`/messages/${messageId}/trace`);
  const root = byId("message-trace");
  if (!root) {
    return;
  }
  root.innerHTML = `
    <div class="rounded-2xl border border-slate-800 bg-slate-950/60 p-4">
      <p class="mb-3 text-xs font-semibold uppercase tracking-[0.25em] text-slate-400">Цепочка принятия решения</p>
      <pre class="overflow-x-auto whitespace-pre-wrap text-sm text-slate-300">${JSON.stringify(trace, null, 2)}</pre>
    </div>
  `;
}

window.loadTrace = loadTrace;

async function loadAudit() {
  const audit = await api("/audit");
  renderList(
    "audit-table",
    audit,
    (event) => `
      <div class="rounded-2xl border border-slate-800 bg-slate-950/50 p-4">
        <strong class="text-base text-white">${event.action}</strong>
        <div class="mt-2 grid gap-1 text-sm text-slate-400">
          <span>${event.user_email}</span>
          <span>${new Date(event.created_at).toLocaleString("ru-RU")}</span>
        </div>
      </div>
    `,
    "Аудит-события пока не записаны."
  );
}

async function loadClamavMirrors() {
  const data = await api("/providers/clamav/mirrors");
  fillClamavForm(data.settings, data.config_path);
}

async function loadAiRuntime() {
  const data = await api("/providers/ai/runtime");
  fillAiRuntimeForm(data.settings);
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

async function saveAiRuntime(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const payload = {
    provider_mode: form.provider_mode.value,
    ollama_base_url: form.ollama_base_url.value,
    ollama_model: form.ollama_model.value,
    gpustack_base_url: form.gpustack_base_url.value,
    gpustack_model: form.gpustack_model.value,
    gpustack_api_key: form.gpustack_api_key.value || null,
  };
  const data = await api("/providers/ai/runtime", {
    method: "PUT",
    body: JSON.stringify(payload),
  });
  fillAiRuntimeForm(data.settings);
}

function showPageError(error) {
  const candidates = [
    "stats-grid",
    "providers-table",
    "messages-table",
    "audit-table",
    "clamav-config-path",
    "ai-runtime-summary",
  ];
  const targetId = candidates.find((id) => byId(id));
  const target = targetId ? byId(targetId) : null;
  if (target) {
    target.innerHTML = `<div class="rounded-2xl border border-rose-500/30 bg-rose-500/10 p-5 text-sm text-rose-100">Ошибка загрузки: ${error.message}</div>`;
  }
}

async function bootstrap() {
  setActiveNav();

  const tasks = [];

  if (byId("stats-grid")) {
    byId("refresh-dashboard")?.addEventListener("click", loadDashboard);
    tasks.push(loadDashboard());
  }

  if (byId("providers-table")) {
    tasks.push(loadProviders());
  }

  if (byId("messages-table")) {
    byId("refresh-messages")?.addEventListener("click", loadMessages);
    tasks.push(loadMessages());
  }

  if (byId("audit-table")) {
    tasks.push(loadAudit());
  }

  if (byId("clamav-form")) {
    byId("clamav-form").addEventListener("submit", saveClamavMirrors);
    tasks.push(loadClamavMirrors());
  }

  if (byId("ai-runtime-form")) {
    byId("ai-runtime-form").addEventListener("submit", saveAiRuntime);
    tasks.push(loadAiRuntime());
  }

  await Promise.all(tasks);
}

bootstrap().catch(showPageError);

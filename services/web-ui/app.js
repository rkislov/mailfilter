const API_BASE = "__API_BASE__";

const PROVIDER_HINTS = {
  rbl: [
    { name: "spamhaus-zen", zone: "zen.spamhaus.org", note: "универсальная DNSBL-зона" },
    { name: "spamcop", zone: "bl.spamcop.net", note: "дополнительная публичная зона" },
    { name: "barracuda", zone: "b.barracudacentral.org", note: "обычно требует регистрацию" },
  ],
  anti_phishing: [
    {
      name: "openphish-local",
      base_url: "feed://local/openphish-local",
      domains: ["login-payments.example", "secure-wallet.example", "auth-update.example"],
    },
    {
      name: "phishtank-local",
      base_url: "feed://local/phishtank-local",
      domains: ["support-portal.example", "reset-access.example"],
    },
    {
      name: "soc-feed",
      base_url: "feed://local/soc-feed",
      domains: ["mail-verify.example", "cabinet-security.example"],
    },
  ],
};

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

function renderProviderHints() {
  const rblRoot = byId("rbl-suggestions");
  if (rblRoot) {
    rblRoot.innerHTML = PROVIDER_HINTS.rbl
      .map((item) => `${item.name}: ${item.zone} (${item.note})`)
      .join(" • ");
  }

  const phishingRoot = byId("phishing-suggestions");
  if (phishingRoot) {
    phishingRoot.innerHTML = PROVIDER_HINTS.anti_phishing
      .map((item) => `${item.name}: ${item.domains.slice(0, 2).join(", ")}`)
      .join(" • ");
  }

  const rblNames = byId("rbl-provider-name-options");
  if (rblNames) {
    rblNames.innerHTML = PROVIDER_HINTS.rbl.map((item) => `<option value="${item.name}"></option>`).join("");
  }

  const rblZones = byId("rbl-zone-options");
  if (rblZones) {
    rblZones.innerHTML = PROVIDER_HINTS.rbl.map((item) => `<option value="${item.zone}"></option>`).join("");
  }

  const phishingNames = byId("phishing-provider-name-options");
  if (phishingNames) {
    phishingNames.innerHTML = PROVIDER_HINTS.anti_phishing.map((item) => `<option value="${item.name}"></option>`).join("");
  }

  const phishingUrls = byId("phishing-provider-url-options");
  if (phishingUrls) {
    phishingUrls.innerHTML = PROVIDER_HINTS.anti_phishing.map((item) => `<option value="${item.base_url}"></option>`).join("");
  }
}

function parseDomainList(rawValue) {
  const unique = [];
  rawValue
    .split(/[\n,;]+/)
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean)
    .forEach((item) => {
      if (!unique.includes(item)) {
        unique.push(item);
      }
    });
  return unique;
}

function setProviderFormStatus(kind, message, tone = "muted") {
  const target = byId(kind === "rbl" ? "rbl-provider-status" : "phishing-provider-status");
  if (!target) {
    return;
  }
  target.textContent = message || "";
  target.className =
    tone === "error"
      ? "self-center text-sm text-rose-300"
      : tone === "success"
        ? "self-center text-sm text-emerald-300"
        : "self-center text-sm text-slate-400";
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

function renderListEntries(entries) {
  renderList(
    "lists-table",
    entries,
    (entry) => `
      <div class="rounded-2xl border border-slate-800 bg-slate-950/50 p-4">
        <div class="flex flex-wrap items-center justify-between gap-3">
          <div>
            <strong class="text-base text-white">${entry.list_type === "allow" ? "Белый список" : "Черный список"}</strong>
            <p class="mt-1 text-sm text-slate-400">${entry.match_type}: ${entry.value}</p>
          </div>
          <div class="flex flex-wrap gap-2">
            <button class="rounded-xl bg-slate-800 px-3 py-2 text-xs font-semibold text-slate-200 transition hover:bg-slate-700" onclick="toggleListEntry(${entry.id}, ${!entry.enabled})">
              ${entry.enabled ? "Выключить" : "Включить"}
            </button>
            <button class="rounded-xl bg-rose-500/20 px-3 py-2 text-xs font-semibold text-rose-200 transition hover:bg-rose-500/30" onclick="deleteListEntry(${entry.id})">
              Удалить
            </button>
          </div>
        </div>
        <div class="mt-3 grid gap-1 text-sm text-slate-400">
          <span>Действие: ${entry.action}</span>
          <span>Активна: ${entry.enabled ? "да" : "нет"}</span>
          <span>Комментарий: ${entry.comment || "-"}</span>
        </div>
      </div>
    `,
    "Записей в белом и черном списке пока нет."
  );
}

function renderProviderCard(provider, editable = false) {
  const extra = getProviderExtra(provider);
  return `
    <div class="rounded-2xl border border-slate-800 bg-slate-950/50 p-4">
      <div class="flex flex-wrap items-start justify-between gap-3">
        <div>
          <strong class="text-base text-white">${provider.name}</strong>
          <div class="mt-3 grid gap-1 text-sm text-slate-400">
            <span>Активен: ${provider.enabled ? "да" : "нет"}</span>
            <span>Источник: ${getProviderSource(provider)}</span>
            ${extra ? `<span>${extra}</span>` : ""}
          </div>
        </div>
        <div class="flex flex-wrap items-center gap-2">
          <span class="rounded-full border border-slate-700 px-3 py-1 text-xs uppercase tracking-[0.2em] text-slate-300">${provider.kind}</span>
          ${
            editable
              ? `<button class="rounded-xl bg-slate-800 px-3 py-2 text-xs font-semibold text-slate-200 transition hover:bg-slate-700" onclick="editProvider(${provider.id})">Изменить</button>
                 <button class="rounded-xl bg-rose-500/20 px-3 py-2 text-xs font-semibold text-rose-200 transition hover:bg-rose-500/30" onclick="deleteProvider(${provider.id})">Удалить</button>`
              : ""
          }
        </div>
      </div>
    </div>
  `;
}

function getProviderSource(provider) {
  const settings = provider.settings || {};

  if (provider.base_url) {
    return provider.base_url;
  }

  if (provider.name === "clamav") {
    return "tcp://clamav:3310";
  }

  if (provider.kind === "rbl" && settings.zone) {
    return `dnsbl://${settings.zone}`;
  }

  if (provider.kind === "anti_phishing" && Array.isArray(settings.blocked_domains)) {
    const preview = settings.blocked_domains.slice(0, 3).join(", ");
    const suffix = settings.blocked_domains.length > 3 ? ` и еще ${settings.blocked_domains.length - 3}` : "";
    return preview ? `feed: ${preview}${suffix}` : "локальный feed";
  }

  if (provider.name === "ai-runtime") {
    if (settings.provider_mode === "gpustack") {
      return settings.gpustack_base_url || "GPUStack не задан";
    }
    if (settings.provider_mode === "ollama") {
      return settings.ollama_base_url || "Ollama не задан";
    }
    return "режим отключен";
  }

  return "-";
}

function getProviderExtra(provider) {
  const settings = provider.settings || {};

  if (provider.kind === "rbl" && settings.zone) {
    return `Зона RBL: ${settings.zone}`;
  }

  if (provider.kind === "anti_phishing" && Array.isArray(settings.blocked_domains)) {
    const preview = settings.blocked_domains.slice(0, 3).join(", ");
    const suffix = settings.blocked_domains.length > 3 ? ` и еще ${settings.blocked_domains.length - 3}` : "";
    return `Доменов в feed: ${settings.blocked_domains.length}${preview ? ` | ${preview}${suffix}` : ""}`;
  }

  if (provider.kind === "ai" && settings.model) {
    return `Модель: ${settings.model}`;
  }

  if (provider.name === "ai-runtime" && settings.provider_mode) {
    return `Режим: ${settings.provider_mode}`;
  }

  return "";
}

async function loadDashboard() {
  const dashboard = await api("/dashboard");
  renderStats(dashboard.summary);
}

async function loadProviders() {
  const providers = await api("/providers");
  const rblProviders = providers.filter((provider) => provider.kind === "rbl");
  const phishingProviders = providers.filter((provider) => provider.kind === "anti_phishing");
  const otherProviders = providers.filter((provider) => !["rbl", "anti_phishing"].includes(provider.kind));

  renderList("rbl-providers-table", rblProviders, (provider) => renderProviderCard(provider, true), "RBL-провайдеры пока не настроены.");
  renderList(
    "phishing-providers-table",
    phishingProviders,
    (provider) => renderProviderCard(provider, true),
    "Phishing-провайдеры пока не настроены."
  );
  renderList("other-providers-table", otherProviders, (provider) => renderProviderCard(provider), "Других провайдеров пока нет.");
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

async function loadLists() {
  const entries = await api("/lists");
  renderListEntries(entries);
}

function resetProviderForm(kind) {
  const form = byId(kind === "rbl" ? "rbl-provider-form" : "phishing-provider-form");
  if (!form) {
    return;
  }
  form.reset();
  form.provider_id.value = "";
  form.organization_id.value = "1";
  form.enabled.checked = true;
  setProviderFormStatus(kind, "");
}

function populateProviderForm(provider) {
  if (provider.kind === "rbl") {
    const form = byId("rbl-provider-form");
    if (!form) {
      return;
    }
    form.provider_id.value = provider.id;
    form.organization_id.value = provider.organization_id || 1;
    form.name.value = provider.name || "";
    form.zone.value = provider.settings?.zone || "";
    form.enabled.checked = !!provider.enabled;
    setProviderFormStatus("rbl", `Редактируется провайдер #${provider.id}`, "success");
    form.scrollIntoView({ behavior: "smooth", block: "start" });
    return;
  }

  if (provider.kind === "anti_phishing") {
    const form = byId("phishing-provider-form");
    if (!form) {
      return;
    }
    form.provider_id.value = provider.id;
    form.organization_id.value = provider.organization_id || 1;
    form.name.value = provider.name || "";
    form.base_url.value = provider.base_url || "";
    form.blocked_domains.value = Array.isArray(provider.settings?.blocked_domains)
      ? provider.settings.blocked_domains.join("\n")
      : "";
    form.enabled.checked = !!provider.enabled;
    setProviderFormStatus("anti_phishing", `Редактируется провайдер #${provider.id}`, "success");
    form.scrollIntoView({ behavior: "smooth", block: "start" });
  }
}

async function editProvider(id) {
  const providers = await api("/providers");
  const provider = providers.find((item) => item.id === id);
  if (!provider) {
    throw new Error("Провайдер не найден");
  }
  populateProviderForm(provider);
}

async function deleteProvider(id) {
  await api(`/providers/${id}`, { method: "DELETE" });
  await loadProviders();
  setProviderFormStatus("rbl", "Провайдер удален.", "success");
  setProviderFormStatus("anti_phishing", "Провайдер удален.", "success");
}

async function saveRblProvider(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const providerId = form.provider_id.value;
  const payload = {
    organization_id: Number(form.organization_id.value || 1),
    name: form.name.value.trim(),
    kind: "rbl",
    enabled: form.enabled.checked,
    settings: {
      zone: form.zone.value.trim(),
    },
  };
  await api(providerId ? `/providers/${providerId}` : "/providers", {
    method: providerId ? "PATCH" : "POST",
    body: JSON.stringify(payload),
  });
  resetProviderForm("rbl");
  setProviderFormStatus("rbl", providerId ? "RBL-провайдер обновлен." : "RBL-провайдер добавлен.", "success");
  await loadProviders();
}

async function savePhishingProvider(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const providerId = form.provider_id.value;
  const payload = {
    organization_id: Number(form.organization_id.value || 1),
    name: form.name.value.trim(),
    kind: "anti_phishing",
    enabled: form.enabled.checked,
    base_url: form.base_url.value.trim() || null,
    settings: {
      blocked_domains: parseDomainList(form.blocked_domains.value),
    },
  };
  await api(providerId ? `/providers/${providerId}` : "/providers", {
    method: providerId ? "PATCH" : "POST",
    body: JSON.stringify(payload),
  });
  resetProviderForm("anti_phishing");
  setProviderFormStatus(
    "anti_phishing",
    providerId ? "Phishing-провайдер обновлен." : "Phishing-провайдер добавлен.",
    "success"
  );
  await loadProviders();
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

async function saveListEntry(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const payload = {
    organization_id: Number(form.organization_id.value || 1),
    list_type: form.list_type.value,
    match_type: form.match_type.value,
    value: form.value.value,
    action: form.action.value,
    enabled: form.enabled.checked,
    comment: form.comment.value || null,
  };
  await api("/lists", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  form.reset();
  form.organization_id.value = "1";
  form.action.value = payload.list_type === "allow" ? "accept" : "reject";
  form.enabled.checked = true;
  await loadLists();
}

async function toggleListEntry(id, enabled) {
  await api(`/lists/${id}`, {
    method: "PATCH",
    body: JSON.stringify({ enabled }),
  });
  await loadLists();
}

async function deleteListEntry(id) {
  await api(`/lists/${id}`, {
    method: "DELETE",
  });
  await loadLists();
}

window.toggleListEntry = toggleListEntry;
window.deleteListEntry = deleteListEntry;
window.editProvider = editProvider;
window.deleteProvider = deleteProvider;
window.resetProviderForm = resetProviderForm;

function showPageError(error) {
  const candidates = [
    "stats-grid",
    "rbl-providers-table",
    "phishing-providers-table",
    "other-providers-table",
    "lists-table",
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

  if (byId("rbl-providers-table")) {
    renderProviderHints();
    byId("rbl-provider-form")?.addEventListener("submit", async (event) => {
      try {
        await saveRblProvider(event);
      } catch (error) {
        setProviderFormStatus("rbl", `Ошибка: ${error.message}`, "error");
      }
    });
    byId("phishing-provider-form")?.addEventListener("submit", async (event) => {
      try {
        await savePhishingProvider(event);
      } catch (error) {
        setProviderFormStatus("anti_phishing", `Ошибка: ${error.message}`, "error");
      }
    });
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

  if (byId("lists-form")) {
    byId("lists-form").addEventListener("submit", saveListEntry);
    tasks.push(loadLists());
  }

  await Promise.all(tasks);
}

bootstrap().catch(showPageError);

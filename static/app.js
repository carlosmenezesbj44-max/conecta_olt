const state = {
  dashboard: null,
  history: null,
  olts: [],
  onus: [],
  profiles: [],
  requests: [],
  vendors: [],
  connections: [],
  connectionTemplates: [],
  events: [],
  users: [],
  permissionCatalog: [],
  auth: {
    authenticated: false,
    bootstrap_required: false,
    user: null,
    permissions: {},
    permission_catalog: [],
  },
  activeTab: "dashboard",
  requestsOperationStatus: null,
  requestPreviewsById: {},
  requestPreviewLoadingById: {},
  requestAuthorizeProgressById: {},
  requestDraftsById: {},
  oltVlansByOltId: {},
  oltVlanFilter: "",
  selectedOltVlanId: null,
  activeOltPanelTab: "infra",
  onuHistory: null,
  activeOltId: null,
  selectedOnuId: null,
  onuFilter: "",
  onuPage: 1,
  onuPageSize: 100,
  pollProgress: {},
  onuLiveStatus: {},
  onuActionResult: {},
  onuDeleteProgress: {},
  onuLiveSeriesByOnuId: {},
  onuPhysicalStatusByOnuId: {},
  liveMonitorOnuId: null,
  liveMonitorTimerId: null,
  liveMonitorRunToken: 0,
  liveMonitorInFlight: false,
  liveMonitorNextRunAtMs: null,
  onuTableSignalVerifyInFlight: false,
  onuTableSignalVerifiedAtByOnuId: {},
  onuSignalRefreshOnuId: null,
  onuSignalRefreshTimerId: null,
  onuSignalRefreshCountdown: 30,
  onuSignalRefreshPendingOnuId: null,
  usersFeedback: null,
};

let usersFeedbackTimerId = null;

const ONU_SIGNAL_AUTO_REFRESH_INTERVAL_SEC = 30;
const ONU_LIVE_MONITOR_INTERVAL_MS = 5000;
const ONU_TABLE_SIGNAL_VERIFY_FIELDS = ["status", "signal", "signal_tx", "signal_olt_rx", "power", "fiber", "ethernet"];
const ONU_TABLE_SIGNAL_VERIFY_BATCH_SIZE = 1;
const ONU_TABLE_SIGNAL_VERIFY_COOLDOWN_MS = 90_000;
const ONU_SIGNAL_AUTO_REFRESH_FIELDS = ["signal", "signal_tx", "signal_olt_rx", "temperature", "status"];
const ONU_DETAIL_LIVE_FIELDS = [
  "signal",
  "signal_tx",
  "signal_olt_rx",
  "temperature",
  "vlan",
  "status",
  "profile",
  "power",
  "fiber",
  "ethernet",
];
const ONU_FULL_REFRESH_FIELDS = [
  ...ONU_DETAIL_LIVE_FIELDS,
  "traffic_down",
  "traffic_up",
];
const EMPTY_DASHBOARD = {
  summary: {
    olts: 0,
    active_onus: 0,
    pending_requests: 0,
    ports_near_capacity: 0,
  },
  alerts: [],
  traffic_chart: [],
  signal_chart: [],
};
const EMPTY_HISTORY = {
  olt_history: [],
  onu_history: [],
};
const TAB_PERMISSION_MAP = {
  dashboard: "dashboard_view",
  olts: "olts_view",
  onus: "onus_view",
  requests: "requests_view",
  collection: "collection_view",
  users: "users_view",
};
const USER_PERMISSION_PRESETS = [
  {
    key: "noc_read",
    label: "NOC Leitura",
    description: "Somente visualizacao operacional.",
    is_admin: false,
    permissions: ["dashboard_view", "olts_view", "onus_view", "requests_view", "collection_view"],
  },
  {
    key: "noc_ops",
    label: "NOC Operacao",
    description: "Visualizacao + operacao de ONUs, solicitacoes e coleta.",
    is_admin: false,
    permissions: [
      "dashboard_view",
      "olts_view",
      "onus_view",
      "onus_manage",
      "requests_view",
      "requests_manage",
      "collection_view",
      "collection_manage",
    ],
  },
  {
    key: "admin",
    label: "Administrador",
    description: "Acesso total.",
    is_admin: true,
    permissions: [],
  },
];

async function fetchJson(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(payload.error || payload.message || payload.details || payload.stage || "Falha na requisicao.");
    error.status = response.status;
    error.payload = payload;
    throw error;
  }
  return payload;
}

function hasPermission(permissionKey) {
  const auth = state.auth || {};
  if (!permissionKey) {
    return Boolean(auth.authenticated);
  }
  if (auth?.user?.is_admin) {
    return true;
  }
  return Boolean(auth?.permissions?.[permissionKey]);
}

function requirePermission(permissionKey, message) {
  if (hasPermission(permissionKey)) {
    return;
  }
  throw new Error(message || "Sem permissao para esta acao.");
}

function defaultDashboardPayload() {
  return {
    summary: { ...EMPTY_DASHBOARD.summary },
    alerts: [],
    traffic_chart: [],
    signal_chart: [],
  };
}

function defaultHistoryPayload() {
  return {
    olt_history: [],
    onu_history: [],
  };
}

async function loadData() {
  const canDashboard = hasPermission("dashboard_view");
  const canOlts = hasPermission("olts_view");
  const canOnus = hasPermission("onus_view");
  const canRequests = hasPermission("requests_view");
  const canCollection = hasPermission("collection_view");
  const canUsers = hasPermission("users_view");

  const [
    dashboard,
    olts,
    onus,
    profiles,
    requests,
    vendors,
    connections,
    connectionTemplates,
    history,
    events,
    usersPayload,
  ] = await Promise.all([
    canDashboard ? fetchJson("/api/dashboard") : Promise.resolve(defaultDashboardPayload()),
    canOlts ? fetchJson("/api/olts") : Promise.resolve([]),
    canOnus ? fetchJson("/api/onus") : Promise.resolve([]),
    canRequests ? fetchJson("/api/profiles") : Promise.resolve([]),
    canRequests ? fetchJson("/api/authorization-requests") : Promise.resolve([]),
    canDashboard ? fetchJson("/api/vendors") : Promise.resolve([]),
    canCollection ? fetchJson("/api/connections") : Promise.resolve([]),
    canCollection ? fetchJson("/api/connection-templates") : Promise.resolve([]),
    canDashboard ? fetchJson("/api/history/dashboard") : Promise.resolve(defaultHistoryPayload()),
    canCollection ? fetchJson("/api/events") : Promise.resolve([]),
    canUsers ? fetchJson("/api/users") : Promise.resolve({ items: [], permission_catalog: state.permissionCatalog }),
  ]);

  state.dashboard = dashboard || defaultDashboardPayload();
  state.olts = Array.isArray(olts) ? olts : [];
  state.onus = Array.isArray(onus) ? onus : [];
  state.profiles = Array.isArray(profiles) ? profiles : [];
  state.requests = Array.isArray(requests) ? requests : [];
  state.vendors = Array.isArray(vendors) ? vendors : [];
  state.connections = Array.isArray(connections) ? connections : [];
  state.connectionTemplates = Array.isArray(connectionTemplates) ? connectionTemplates : [];
  state.history = history || defaultHistoryPayload();
  state.events = Array.isArray(events) ? events : [];
  state.users = Array.isArray(usersPayload?.items) ? usersPayload.items : [];
  if (Array.isArray(usersPayload?.permission_catalog) && usersPayload.permission_catalog.length) {
    state.permissionCatalog = usersPayload.permission_catalog;
  } else if (Array.isArray(state.auth?.permission_catalog) && state.auth.permission_catalog.length) {
    state.permissionCatalog = state.auth.permission_catalog;
  }

  const requestIds = new Set(state.requests.map((item) => Number(item.id)));
  Object.keys(state.requestPreviewsById).forEach((key) => {
    if (!requestIds.has(Number(key))) {
      delete state.requestPreviewsById[key];
    }
  });
  Object.keys(state.requestPreviewLoadingById).forEach((key) => {
    if (!requestIds.has(Number(key))) {
      delete state.requestPreviewLoadingById[key];
    }
  });
  Object.keys(state.requestAuthorizeProgressById).forEach((key) => {
    if (!requestIds.has(Number(key))) {
      delete state.requestAuthorizeProgressById[key];
    }
  });
  Object.keys(state.requestDraftsById).forEach((key) => {
    if (!requestIds.has(Number(key))) {
      delete state.requestDraftsById[key];
    }
  });
  const onuIds = new Set(state.onus.map((item) => Number(item.id)));
  Object.keys(state.onuPhysicalStatusByOnuId).forEach((key) => {
    if (!onuIds.has(Number(key))) {
      delete state.onuPhysicalStatusByOnuId[key];
    }
  });
  Object.keys(state.onuTableSignalVerifiedAtByOnuId).forEach((key) => {
    if (!onuIds.has(Number(key))) {
      delete state.onuTableSignalVerifiedAtByOnuId[key];
    }
  });

  if ((!state.activeOltId || !state.olts.some((olt) => olt.id === state.activeOltId)) && state.olts.length) {
    state.activeOltId = state.olts[0].id;
  } else if (!state.olts.length) {
    state.activeOltId = null;
  }
  if ((!state.selectedOnuId || !state.onus.some((onu) => onu.id === state.selectedOnuId)) && state.onus.length) {
    state.selectedOnuId = state.onus[0].id;
  } else if (!state.onus.length) {
    state.selectedOnuId = null;
  }

  if (canOlts) {
    try {
      await refreshOltVlans();
    } catch (_) {
      if (state.activeOltId) {
        state.oltVlansByOltId[state.activeOltId] = [];
      }
    }
  } else {
    state.oltVlansByOltId = {};
    state.activeOltId = null;
  }

  if (canOnus) {
    await refreshOnuHistory();
  } else {
    state.selectedOnuId = null;
    state.onuHistory = null;
    stopOnuLiveMonitor();
  }

  applyPermissionVisibility();
  renderAll();
  if (canOnus && hasPermission("onus_manage")) {
    syncOnuSignalAutoRefresh();
  } else {
    syncOnuSignalAutoRefresh(true);
  }
}

function clearAppDataForLogout() {
  state.dashboard = defaultDashboardPayload();
  state.history = defaultHistoryPayload();
  state.olts = [];
  state.onus = [];
  state.profiles = [];
  state.requests = [];
  state.vendors = [];
  state.connections = [];
  state.connectionTemplates = [];
  state.events = [];
  state.users = [];
  state.activeOltId = null;
  state.selectedOnuId = null;
  state.onuHistory = null;
  state.oltVlansByOltId = {};
  state.requestPreviewsById = {};
  state.requestPreviewLoadingById = {};
  state.requestAuthorizeProgressById = {};
  state.requestDraftsById = {};
  state.onuLiveStatus = {};
  state.onuActionResult = {};
  state.onuDeleteProgress = {};
  state.onuLiveSeriesByOnuId = {};
  state.onuPhysicalStatusByOnuId = {};
  state.usersFeedback = null;
  if (usersFeedbackTimerId) {
    window.clearTimeout(usersFeedbackTimerId);
    usersFeedbackTimerId = null;
  }
  stopOnuLiveMonitor();
}

function getVisibleTabIds() {
  return Array.from(document.querySelectorAll(".tab-button"))
    .filter((button) => !button.classList.contains("hidden"))
    .map((button) => button.dataset.tab)
    .filter(Boolean);
}

function activateTab(tabId) {
  const visibleTabs = getVisibleTabIds();
  const selectedTabId = visibleTabs.includes(tabId) ? tabId : visibleTabs[0] || null;
  if (!selectedTabId) {
    return;
  }
  state.activeTab = selectedTabId;
  document.querySelectorAll(".tab-button").forEach((button) => {
    button.classList.toggle("active", button.dataset.tab === selectedTabId);
  });
  document.querySelectorAll(".tab-panel").forEach((panel) => {
    panel.classList.toggle("active", panel.id === selectedTabId);
  });
}

function applyPermissionVisibility() {
  Object.entries(TAB_PERMISSION_MAP).forEach(([tabId, permissionKey]) => {
    const tabButton = document.querySelector(`.tab-button[data-tab="${tabId}"]`);
    const panel = document.getElementById(tabId);
    const allowed = hasPermission(permissionKey);
    if (tabButton) {
      tabButton.classList.toggle("hidden", !allowed);
    }
    if (panel && !allowed) {
      panel.classList.remove("active");
    }
  });
  const candidate = hasPermission(TAB_PERMISSION_MAP[state.activeTab]) ? state.activeTab : null;
  activateTab(candidate || getVisibleTabIds()[0] || "dashboard");

  const syncButton = document.getElementById("syncButton");
  if (syncButton) {
    const allowed = hasPermission("collection_manage");
    syncButton.disabled = !allowed;
    syncButton.title = allowed ? "" : "Sem permissao de coleta";
  }

  const canManageOlts = hasPermission("olts_manage");
  const oltForm = document.getElementById("createOltForm");
  if (oltForm) {
    oltForm.querySelectorAll("input, select").forEach((node) => {
      if (node.name === "editing_olt_id") {
        return;
      }
      node.disabled = !canManageOlts;
    });
  }
  ["createOltButton", "updateOltButton", "connectOltButton", "clearOltFormButton", "addOltVlanButton"].forEach((id) => {
    const button = document.getElementById(id);
    if (button) {
      button.disabled = !canManageOlts;
    }
  });
  const connectButton = document.getElementById("connectOltButton");
  if (connectButton) {
    connectButton.disabled = !canManageOlts || !hasPermission("collection_manage");
  }

  const canManageRequests = hasPermission("requests_manage");
  ["runAutofindAllButton", "syncOltProfilesButton"].forEach((id) => {
    const button = document.getElementById(id);
    if (button) {
      button.disabled = !canManageRequests;
    }
  });
}

function setAuthStatus(message = "", isError = false) {
  const statusNode = document.getElementById("authStatus");
  if (!statusNode) {
    return;
  }
  statusNode.textContent = message || "";
  statusNode.style.color = isError ? "#9f3f35" : "";
}

function setUsersFeedback(message = "", isError = false, timeoutMs = 5000) {
  const normalizedMessage = String(message || "").trim();
  state.usersFeedback = normalizedMessage
    ? {
      message: normalizedMessage,
      isError: Boolean(isError),
    }
    : null;
  if (usersFeedbackTimerId) {
    window.clearTimeout(usersFeedbackTimerId);
    usersFeedbackTimerId = null;
  }
  renderUsers();
  if (state.usersFeedback && timeoutMs > 0) {
    usersFeedbackTimerId = window.setTimeout(() => {
      state.usersFeedback = null;
      usersFeedbackTimerId = null;
      renderUsers();
    }, timeoutMs);
  }
}

function showAuthScreen() {
  const authScreen = document.getElementById("authScreen");
  const appShell = document.getElementById("appShell");
  const loginForm = document.getElementById("loginForm");
  const bootstrapForm = document.getElementById("bootstrapForm");
  const bootstrapRequired = Boolean(state.auth?.bootstrap_required);

  authScreen?.classList.remove("hidden");
  appShell?.classList.add("hidden");
  if (loginForm) {
    loginForm.classList.toggle("hidden", bootstrapRequired);
  }
  if (bootstrapForm) {
    bootstrapForm.classList.toggle("hidden", !bootstrapRequired);
  }
}

function showAppShell() {
  const authScreen = document.getElementById("authScreen");
  const appShell = document.getElementById("appShell");
  authScreen?.classList.add("hidden");
  appShell?.classList.remove("hidden");
}

function renderSessionBadge() {
  const badge = document.getElementById("sessionUserBadge");
  const logoutButton = document.getElementById("logoutButton");
  const user = state.auth?.user;
  if (!badge || !logoutButton || !user) {
    if (badge) {
      badge.classList.add("hidden");
      badge.textContent = "";
    }
    if (logoutButton) {
      logoutButton.classList.add("hidden");
    }
    return;
  }
  badge.textContent = `${user.display_name || user.username} (${user.is_admin ? "admin" : "operador"})`;
  badge.classList.remove("hidden");
  logoutButton.classList.remove("hidden");
}

function renderUserPermissionInputs(form, permissionCatalog, selectedPermissions = {}) {
  if (!form) {
    return;
  }
  const container = form.querySelector("[data-permission-container]") || form.querySelector(".user-permission-grid");
  if (!container) {
    return;
  }
  const catalogRows = Array.isArray(permissionCatalog) ? permissionCatalog : [];
  container.innerHTML = catalogRows
    .map((item) => {
      const key = String(item?.key || "").trim();
      if (!key) {
        return "";
      }
      const label = String(item?.label || key);
      return `
        <label class="checkbox-row">
          <input type="checkbox" name="perm_${escapeHtml(key)}" data-permission-key="${escapeHtml(key)}" ${
            selectedPermissions?.[key] ? "checked" : ""
          }>
          ${escapeHtml(label)}
        </label>
      `;
    })
    .join("");
}

function collectPermissionsFromForm(form) {
  const permissions = {};
  if (!form) {
    return permissions;
  }
  form.querySelectorAll("[data-permission-key]").forEach((input) => {
    const key = input.dataset.permissionKey;
    if (!key) {
      return;
    }
    permissions[key] = Boolean(input.checked);
  });
  return permissions;
}

function toggleUserPermissionInputs(form, disabled) {
  if (!form) {
    return;
  }
  form.querySelectorAll("[data-permission-key]").forEach((input) => {
    input.disabled = Boolean(disabled);
  });
}

async function refreshAuthSession() {
  const session = await fetchJson("/api/auth/session");
  state.auth = session || {
    authenticated: false,
    bootstrap_required: false,
    user: null,
    permissions: {},
    permission_catalog: [],
  };
  if (Array.isArray(state.auth?.permission_catalog) && state.auth.permission_catalog.length) {
    state.permissionCatalog = state.auth.permission_catalog;
  }
  return state.auth;
}

async function performLogin() {
  const form = document.getElementById("loginForm");
  if (!form) {
    return;
  }
  const payload = {
    username: form.username.value.trim(),
    password: form.password.value,
  };
  const session = await fetchJson("/api/auth/login", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  state.auth = session;
  if (Array.isArray(session?.permission_catalog) && session.permission_catalog.length) {
    state.permissionCatalog = session.permission_catalog;
  }
  form.reset();
  setAuthStatus("");
  showAppShell();
  renderSessionBadge();
  applyPermissionVisibility();
  await loadData();
}

async function performBootstrap() {
  const form = document.getElementById("bootstrapForm");
  if (!form) {
    return;
  }
  const payload = {
    username: form.username.value.trim(),
    display_name: form.display_name.value.trim(),
    password: form.password.value,
  };
  const session = await fetchJson("/api/auth/bootstrap", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  state.auth = session;
  if (Array.isArray(session?.permission_catalog) && session.permission_catalog.length) {
    state.permissionCatalog = session.permission_catalog;
  }
  form.reset();
  setAuthStatus("");
  showAppShell();
  renderSessionBadge();
  applyPermissionVisibility();
  await loadData();
}

async function performLogout() {
  await fetchJson("/api/auth/logout", { method: "POST", body: "{}" });
  clearAppDataForLogout();
  await refreshAuthSession();
  renderSessionBadge();
  applyPermissionVisibility();
  showAuthScreen();
}

async function ensureAuthenticatedAndLoad() {
  await refreshAuthSession();
  if (!state.auth?.authenticated) {
    clearAppDataForLogout();
    renderSessionBadge();
    showAuthScreen();
    setAuthStatus(
      state.auth?.bootstrap_required
        ? "Nenhum usuario cadastrado. Crie o administrador inicial."
        : "Entre com seu usuario para continuar."
    );
    return;
  }
  setAuthStatus("");
  showAppShell();
  renderSessionBadge();
  applyPermissionVisibility();
  await loadData();
}

async function refreshOltVlans() {
  if (!state.activeOltId) {
    return;
  }
  const rows = await fetchJson(`/api/olts/${state.activeOltId}/vlans`);
  state.oltVlansByOltId[state.activeOltId] = rows;
  const selectedExists = rows.some((item) => item.vlan_id === Number(state.selectedOltVlanId));
  if (!selectedExists) {
    state.selectedOltVlanId = rows.length ? rows[0].vlan_id : null;
  }
}

async function refreshOnuHistory() {
  if (!state.selectedOnuId) {
    state.onuHistory = null;
    return;
  }
  state.onuHistory = await fetchJson(`/api/onus/${state.selectedOnuId}/history`);
}

async function selectOnuAndRender(onuId, options = {}) {
  state.selectedOnuId = Number(onuId);
  syncOnuSignalAutoRefresh(true);
  if (state.liveMonitorOnuId && state.liveMonitorOnuId !== state.selectedOnuId) {
    stopOnuLiveMonitor();
  }
  try {
    await refreshOnuHistory();
  } catch (_) {
    state.onuHistory = null;
  }
  renderOnuTable();
  renderOnuDetailsPanel();
  renderOnuHistory();
  collectOnuLive(state.selectedOnuId, ONU_DETAIL_LIVE_FIELDS).catch(() => {
    // O painel segue funcional mesmo sem leitura detalhada.
  });
}

function openOnuModal() {
  const modal = document.getElementById("onuModal");
  const modalBody = document.getElementById("onuModalBody");
  const panel = document.getElementById("onuDetailsPanel");
  if (!modal || !modalBody || !panel) {
    return;
  }
  modalBody.innerHTML = panel.innerHTML;
  modal.classList.remove("hidden");
  modal.setAttribute("aria-hidden", "false");
}

function closeOnuModal() {
  const modal = document.getElementById("onuModal");
  if (!modal) {
    return;
  }
  modal.classList.add("hidden");
  modal.setAttribute("aria-hidden", "true");
}

function syncOnuModalFromPanel() {
  const modal = document.getElementById("onuModal");
  const modalBody = document.getElementById("onuModalBody");
  const panel = document.getElementById("onuDetailsPanel");
  if (!modal || !modalBody || !panel || modal.classList.contains("hidden")) {
    return;
  }
  modalBody.innerHTML = panel.innerHTML;
}

function defaultPortForTransport(transportType) {
  return {
    ssh: 22,
    telnet: 23,
    snmp: 161,
    api: 443,
  }[(transportType || "ssh").toLowerCase()] || 22;
}

function setOltConnectStatus(status, message) {
  const badge = document.getElementById("oltConnectBadge");
  const messageNode = document.getElementById("oltConnectMessage");
  const normalizedStatus = status || "warning";
  const badgeLabel = normalizedStatus === "ok" ? "conectado" : normalizedStatus === "critical" ? "erro" : "sem teste";
  badge.className = `status-pill ${normalizedStatus}`;
  badge.textContent = badgeLabel;
  messageNode.textContent = message || "Sem teste de conexao.";
}

function normalizeTemplateIdentity(value) {
  return String(value ?? "").trim().toLowerCase();
}

function isTemplateValuePresent(value) {
  if (value === false || value === 0) {
    return true;
  }
  if (value === null || value === undefined || value === "") {
    return false;
  }
  if (Array.isArray(value)) {
    return value.length > 0;
  }
  if (typeof value === "object") {
    return Object.keys(value).length > 0;
  }
  return true;
}

function formatCatalogIdentity(value, kind = "generic") {
  const normalized = normalizeTemplateIdentity(value);
  if (!normalized) {
    return "";
  }
  if (kind === "brand") {
    return normalized
      .split(/[\s_-]+/)
      .filter(Boolean)
      .map((token) => token.charAt(0).toUpperCase() + token.slice(1))
      .join(" ");
  }
  return normalized.toUpperCase();
}

function sortTemplateValues(values) {
  return Array.from(values || []).sort((left, right) => left.localeCompare(right, "pt-BR"));
}

function renderTemplateSelectOptions(selectNode, options, placeholder, selectedValue = "") {
  if (!selectNode) {
    return;
  }
  const rows = Array.isArray(options) ? options : [];
  selectNode.innerHTML = [
    `<option value="">${escapeHtml(placeholder)}</option>`,
    ...rows.map((item) => `<option value="${escapeHtml(item.value)}">${escapeHtml(item.label)}</option>`),
  ].join("");

  const selected = normalizeTemplateIdentity(selectedValue);
  const matched = rows.find((item) => normalizeTemplateIdentity(item.value) === selected);
  selectNode.value = matched ? matched.value : "";
}

function buildOltTemplateCatalogIndex() {
  const rows = Array.isArray(state.connectionTemplates) ? state.connectionTemplates : [];
  const templatesByKey = new Map();
  const brands = new Set();
  const modelsByBrand = new Map();
  const firmwaresByBrandModel = new Map();

  rows.forEach((template) => {
    const brand = normalizeTemplateIdentity(template.brand);
    const model = normalizeTemplateIdentity(template.model || "*") || "*";
    const firmware = normalizeTemplateIdentity(template.firmware || "*") || "*";
    if (!brand) {
      return;
    }
    templatesByKey.set(`${brand}|${model}|${firmware}`, template);
    brands.add(brand);

    if (model !== "*") {
      if (!modelsByBrand.has(brand)) {
        modelsByBrand.set(brand, new Set());
      }
      modelsByBrand.get(brand).add(model);

      if (firmware !== "*") {
        const key = `${brand}|${model}`;
        if (!firmwaresByBrandModel.has(key)) {
          firmwaresByBrandModel.set(key, new Set());
        }
        firmwaresByBrandModel.get(key).add(firmware);
      }
    }
  });

  return {
    rows,
    templatesByKey,
    brands: sortTemplateValues(brands),
    modelsByBrand,
    firmwaresByBrandModel,
  };
}

function resolveTemplateExtraForIdentity(brand, model, firmware, catalogIndex = null) {
  const index = catalogIndex || buildOltTemplateCatalogIndex();
  const brandIdentity = normalizeTemplateIdentity(brand);
  const modelIdentity = normalizeTemplateIdentity(model);
  const firmwareIdentity = normalizeTemplateIdentity(firmware);
  if (!brandIdentity) {
    return { extra: {}, defaults: {}, matched: [] };
  }

  const candidates = [
    [brandIdentity, "*", "*"],
    [brandIdentity, modelIdentity || "*", "*"],
    [brandIdentity, modelIdentity || "*", firmwareIdentity || "*"],
  ];

  const extra = {};
  const defaults = {};
  const matched = [];
  candidates.forEach(([candidateBrand, candidateModel, candidateFirmware]) => {
    const template = index.templatesByKey.get(`${candidateBrand}|${candidateModel}|${candidateFirmware}`);
    if (!template) {
      return;
    }
    matched.push({
      brand: candidateBrand,
      model: candidateModel,
      firmware: candidateFirmware,
      template,
    });
    const templateExtra = template.extra_config || {};
    Object.entries(templateExtra).forEach(([key, value]) => {
      if (!isTemplateValuePresent(value)) {
        return;
      }
      extra[key] = value;
    });
    const templateDefaults = template.defaults || {};
    Object.entries(templateDefaults).forEach(([key, value]) => {
      if (!isTemplateValuePresent(value)) {
        return;
      }
      defaults[key] = value;
    });
  });
  return { extra, defaults, matched };
}

function applyResolvedTemplateToOltForm(form, resolved) {
  if (!form || !resolved || !resolved.matched?.length) {
    return;
  }
  const defaults = resolved.defaults || {};
  const setValue = (name, value) => {
    if (!isTemplateValuePresent(value)) {
      return;
    }
    const field = form.querySelector(`[name='${name}']`);
    if (!field) {
      return;
    }
    field.value = value;
  };

  setValue("username", defaults.username);
  setValue("password", defaults.password);
  if (isTemplateValuePresent(defaults.transport_type)) {
    const transportField = form.querySelector("[name='transport_type']");
    if (transportField) {
      transportField.value = defaults.transport_type;
      transportField.dataset.lastTransport = defaults.transport_type;
    }
  }
  setValue("port", defaults.port);
  setValue("status", defaults.status);
  setValue("board_model", defaults.board_model);
  setValue("board_slots", defaults.board_slots);
  setValue("ports_per_board", defaults.ports_per_board);
  setValue("capacity_onu", defaults.capacity_onu);
}

function countTemplateOidEntries(extraConfig) {
  return Object.entries(extraConfig || {}).filter(
    ([key, value]) =>
      key.startsWith("snmp_") &&
      key.endsWith("_oid") &&
      isTemplateValuePresent(value)
  ).length;
}

function countTemplateCommandEntries(extraConfig) {
  const overrides = extraConfig?.command_overrides;
  if (!overrides || typeof overrides !== "object") {
    return 0;
  }
  return ["ont_summary", "service_port", "vlan_inventory"].filter((key) => {
    const value = String(overrides[key] || "").trim();
    return Boolean(value);
  }).length;
}

function refreshOltTemplateCatalog() {
  const form = document.getElementById("createOltForm");
  if (!form) {
    return;
  }

  const brandSelect = form.querySelector("select[name='catalog_brand']");
  const modelSelect = form.querySelector("select[name='catalog_model']");
  const firmwareSelect = form.querySelector("select[name='catalog_firmware']");
  const countNode = document.getElementById("oltTemplateCatalogCount");
  const summaryNode = document.getElementById("oltTemplateCatalogSummary");
  if (!brandSelect || !modelSelect || !firmwareSelect) {
    return;
  }

  const catalog = buildOltTemplateCatalogIndex();
  if (countNode) {
    countNode.textContent = `${catalog.rows.length} templates`;
  }

  const selectedBrand = normalizeTemplateIdentity(form.brand.value);
  const selectedModel = normalizeTemplateIdentity(form.model.value);
  const selectedFirmware = normalizeTemplateIdentity(form.firmware.value);

  renderTemplateSelectOptions(
    brandSelect,
    catalog.brands.map((value) => ({ value, label: formatCatalogIdentity(value, "brand") })),
    "Fabricante (catalogo)",
    selectedBrand
  );

  const currentBrand = normalizeTemplateIdentity(brandSelect.value);
  const modelOptions = currentBrand
    ? sortTemplateValues(catalog.modelsByBrand.get(currentBrand) || []).map((value) => ({
        value,
        label: formatCatalogIdentity(value, "model"),
      }))
    : [];
  renderTemplateSelectOptions(modelSelect, modelOptions, "Modelo (catalogo)", selectedModel);

  const currentModel = normalizeTemplateIdentity(modelSelect.value);
  const firmwareOptions =
    currentBrand && currentModel
      ? sortTemplateValues(catalog.firmwaresByBrandModel.get(`${currentBrand}|${currentModel}`) || []).map(
          (value) => ({
            value,
            label: formatCatalogIdentity(value, "firmware"),
          })
        )
      : [];
  renderTemplateSelectOptions(firmwareSelect, firmwareOptions, "Firmware (catalogo)", selectedFirmware);

  if (!summaryNode) {
    return;
  }
  if (!selectedBrand || !selectedModel || !selectedFirmware) {
    summaryNode.textContent = "Preencha marca, modelo e firmware para conferir o template aplicado.";
    return;
  }

  const resolved = resolveTemplateExtraForIdentity(selectedBrand, selectedModel, selectedFirmware, catalog);
  if (!resolved.matched.length) {
    summaryNode.textContent = `Sem template para ${formatCatalogIdentity(selectedBrand, "brand")} / ${formatCatalogIdentity(selectedModel, "model")} / ${formatCatalogIdentity(selectedFirmware, "firmware")}.`;
    return;
  }

  const matchedScopes = resolved.matched
    .map((item) => `${formatCatalogIdentity(item.brand, "brand")} / ${item.model === "*" ? "*" : formatCatalogIdentity(item.model, "model")} / ${item.firmware === "*" ? "*" : formatCatalogIdentity(item.firmware, "firmware")}`)
    .join(" + ");
  const profile = String(
    resolved.extra.collector_profile ||
      resolved.extra.collector_profile_detected ||
      "auto"
  ).trim();
  const oidCount = countTemplateOidEntries(resolved.extra);
  const commandCount = countTemplateCommandEntries(resolved.extra);
  const transportLabel = resolved.defaults?.transport_type
    ? `${String(resolved.defaults.transport_type).toUpperCase()}:${resolved.defaults.port || "-"}`
    : "n/d";
  const boardLabel = resolved.defaults?.board_slots
    ? `${resolved.defaults.board_model || "placa"} @ ${resolved.defaults.board_slots}`
    : "n/d";
  summaryNode.textContent =
    `Template ativo: ${matchedScopes}. ` +
    `Perfil CLI: ${profile}. Transporte: ${transportLabel}. Placas: ${boardLabel}. OIDs: ${oidCount}. Comandos: ${commandCount}.`;
}

function applyOltTemplateCatalogSelection(level) {
  const form = document.getElementById("createOltForm");
  if (!form) {
    return;
  }
  const brandSelect = form.querySelector("select[name='catalog_brand']");
  const modelSelect = form.querySelector("select[name='catalog_model']");
  const firmwareSelect = form.querySelector("select[name='catalog_firmware']");
  if (!brandSelect || !modelSelect || !firmwareSelect) {
    return;
  }

  const brand = normalizeTemplateIdentity(brandSelect.value);
  const model = normalizeTemplateIdentity(modelSelect.value);
  const firmware = normalizeTemplateIdentity(firmwareSelect.value);

  if (level === "brand") {
    form.brand.value = brand ? formatCatalogIdentity(brand, "brand") : "";
    form.model.value = "";
    form.firmware.value = "";
  } else if (level === "model") {
    if (brand) {
      form.brand.value = formatCatalogIdentity(brand, "brand");
    }
    form.model.value = model ? formatCatalogIdentity(model, "model") : "";
    form.firmware.value = "";
  } else if (level === "firmware") {
    if (brand) {
      form.brand.value = formatCatalogIdentity(brand, "brand");
    }
    if (model) {
      form.model.value = formatCatalogIdentity(model, "model");
    }
    form.firmware.value = firmware ? formatCatalogIdentity(firmware, "firmware") : "";
  }

  const resolved = resolveTemplateExtraForIdentity(
    form.brand.value,
    form.model.value,
    form.firmware.value
  );
  applyResolvedTemplateToOltForm(form, resolved);
  refreshOltTemplateCatalog();
}

function renderAll() {
  renderSummary();
  renderInstantCharts();
  renderAlerts();
  renderVendors();
  renderDashboardHistory();
  populateOltFormFromActive();
  renderOltTabs();
  renderOltPanelTabs();
  renderOltPanels();
  renderOltDetails();
  renderOltVlans();
  renderOnuTable();
  renderOnuDetailsPanel();
  renderOnuHistory();
  renderRequests();
  renderConnections();
  renderConnectionTemplates();
  renderEvents();
  renderUsers();
}

function renderSummary() {
  const summary = state.dashboard.summary;
  const cards = [
    ["OLTs", summary.olts],
    ["ONUs ativas", summary.active_onus],
    ["Pendencias", summary.pending_requests],
    ["Portas em alerta", summary.ports_near_capacity],
  ];
  document.getElementById("summaryCards").innerHTML = cards
    .map(
      ([label, value]) => `
        <article class="stat-card">
          <h3>${label}</h3>
          <span class="stat-value">${value}</span>
        </article>
      `
    )
    .join("");
  const heroHighlights = document.getElementById("heroHighlights");
  if (heroHighlights) {
    const heroCards = [
      ["OLTs", summary.olts, "base monitorada"],
      ["ONUs ativas", summary.active_onus, "em operacao"],
      ["Pendencias", summary.pending_requests, "fila operacional"],
      ["Alertas", summary.ports_near_capacity, "capacidade critica"],
    ];
    heroHighlights.innerHTML = heroCards
      .map(
        ([label, value, meta]) => `
          <article class="hero-highlight">
            <span class="hero-highlight-label">${label}</span>
            <strong>${value}</strong>
            <small>${meta}</small>
          </article>
        `
      )
      .join("");
  }
}

function renderInstantCharts() {
  const trafficMax = Math.max(
    1,
    ...state.dashboard.traffic_chart.flatMap((item) => [item.down_mbps, item.up_mbps])
  );
  document.getElementById("trafficChart").innerHTML = state.dashboard.traffic_chart
    .map(
      (item) => `
        <div class="chart-row double">
          <strong>${item.label}</strong>
          <div class="bar-track">
            <div class="bar-fill down" style="width:${(item.down_mbps / trafficMax) * 100}%"></div>
          </div>
          <div class="bar-track">
            <div class="bar-fill up" style="width:${(item.up_mbps / trafficMax) * 100}%"></div>
          </div>
        </div>
        <div class="muted">${item.down_mbps} Mbps down / ${item.up_mbps} Mbps up</div>
      `
    )
    .join("");

  const signalMax = Math.max(1, ...state.dashboard.signal_chart.map((item) => item.count));
  document.getElementById("signalChart").innerHTML = state.dashboard.signal_chart
    .map(
      (item) => `
        <div class="chart-row">
          <strong>${item.label}</strong>
          <div class="bar-track">
            <div class="bar-fill signal" style="width:${(item.count / signalMax) * 100}%"></div>
          </div>
          <span>${item.count}</span>
        </div>
      `
    )
    .join("");
}

function renderAlerts() {
  const alerts = state.dashboard.alerts;
  document.getElementById("alertsList").innerHTML = alerts.length
    ? alerts
        .map(
          (alert) => `
            <article class="alert-card">
              <div class="panel-head">
                <strong>${alert.olt_name} / ${alert.board_slot} / ${alert.port_name}</strong>
                <span class="status-pill ${alert.level}">${alert.usage_pct}%</span>
              </div>
              <div class="muted">${alert.used_onu} de ${alert.capacity_onu} ONUs ocupadas</div>
            </article>
          `
        )
        .join("")
    : '<div class="muted">Nenhuma porta acima do limite de alerta.</div>';
}

function renderVendors() {
  document.getElementById("vendorsList").innerHTML = state.vendors
    .map(
      (vendor) => `
        <article class="vendor-card">
          <h3>${vendor.name}</h3>
          <p class="muted">Autorizacao: ${vendor.authorization_modes.join(", ")}</p>
          <p class="muted">Profiles: ${vendor.profile_fields.join(", ")}</p>
          <p class="muted">Coleta: ${vendor.collection_protocols.join(", ")}</p>
          <span class="status-pill ok">${vendor.move_supported ? "Move suportado" : "Sem move"}</span>
        </article>
      `
    )
    .join("");
}

function renderDashboardHistory() {
  const infra = state.history?.olt_history || [];
  const onuHistory = state.history?.onu_history || [];
  document.getElementById("infraHistory").innerHTML = infra.length
    ? infra.map(renderInfraCard).join("")
    : '<div class="muted">Sem historico de infraestrutura.</div>';
  document.getElementById("dashboardOnuHistory").innerHTML = onuHistory.length
    ? onuHistory.map(renderDashboardOnuCard).join("")
    : '<div class="muted">Sem historico de ONUs.</div>';
}

function renderInfraCard(item) {
  const latest = item.points[item.points.length - 1];
  return `
    <article class="history-card">
      <div class="panel-head">
        <strong>${item.label}</strong>
        <span class="muted">${latest ? formatTime(latest.collected_at) : "-"}</span>
      </div>
      <div class="mini-points">
        ${item.points
          .map(
            (point) => `
              <div class="mini-point">
                <span>${formatTime(point.collected_at)}</span>
                <strong>${point.temperature_c} C</strong>
                <div class="bar-track slim">
                  <div class="bar-fill down" style="width:${Math.min(point.cpu_usage, 100)}%"></div>
                </div>
                <small>CPU ${point.cpu_usage}% / MEM ${point.memory_usage}%</small>
              </div>
            `
          )
          .join("")}
      </div>
    </article>
  `;
}

function renderDashboardOnuCard(item) {
  return `
    <article class="history-card">
      <div class="panel-head">
        <strong>${item.label}</strong>
        <span class="muted">${item.points.length} pontos</span>
      </div>
      <div class="mini-points">
        ${item.points
          .map(
            (point) => `
              <div class="mini-point">
                <span>${formatTime(point.collected_at)}</span>
                <div class="bar-track slim">
                  <div class="bar-fill signal" style="width:${signalPercent(point.signal_dbm)}%"></div>
                </div>
                <small>${point.signal_dbm ? `${point.signal_dbm} dBm` : "-"} / ${point.temperature_c ? `${point.temperature_c} C` : "-"}</small>
              </div>
            `
          )
          .join("")}
      </div>
    </article>
  `;
}

function renderOltTabs() {
  if (!state.olts.length) {
    document.getElementById("oltTabs").innerHTML = '<div class="muted">Nenhuma OLT cadastrada.</div>';
    return;
  }
  document.getElementById("oltTabs").innerHTML = state.olts
    .map(
      (olt) => `
        <button class="subtab-button ${state.activeOltId === olt.id ? "active" : ""}" data-olt-id="${olt.id}">
          ${olt.name}
        </button>
      `
    )
    .join("");
}

function renderOltPanelTabs() {
  document.querySelectorAll("[data-olt-panel-tab]").forEach((button) => {
    button.classList.toggle("active", button.dataset.oltPanelTab === state.activeOltPanelTab);
  });
}

function renderOltPanels() {
  const infra = document.getElementById("oltInfraPanel");
  const vlans = document.getElementById("oltVlansPanel");
  if (!infra || !vlans) {
    return;
  }
  const showInfra = state.activeOltPanelTab !== "vlans";
  infra.classList.toggle("hidden", !showInfra);
  vlans.classList.toggle("hidden", showInfra);
}

function renderOltDetails() {
  const canManageOlts = hasPermission("olts_manage");
  const olt = state.olts.find((item) => item.id === state.activeOltId);
  const container = document.getElementById("oltDetails");
  if (!olt) {
    container.innerHTML = '<div class="muted">Nenhuma OLT encontrada.</div>';
    return;
  }

  container.innerHTML = `
    <div class="olt-header">
      <span class="status-pill ${olt.status === "online" ? "ok" : "warning"}">${olt.status}</span>
      <strong>${olt.brand} ${olt.model}</strong>
      <span class="muted">Host ${olt.host}</span>
      <span class="muted">Firmware ${olt.firmware}</span>
      <span class="muted">${olt.temperature_c} C</span>
      <span class="muted">CPU ${olt.cpu_usage}%</span>
      <span class="muted">MEM ${olt.memory_usage}%</span>
      <button type="button" class="secondary-button" data-delete-olt-id="${olt.id}" ${canManageOlts ? "" : "disabled"}>Excluir OLT</button>
    </div>
    <div class="olt-summary">
      <div class="summary-chip"><strong>${olt.summary.boards}</strong><div class="muted">Placas</div></div>
      <div class="summary-chip"><strong>${olt.summary.ports}</strong><div class="muted">Portas GPON</div></div>
      <div class="summary-chip"><strong>${olt.summary.used_onu}</strong><div class="muted">ONUs em uso</div></div>
      <div class="summary-chip"><strong>${olt.summary.total_capacity}</strong><div class="muted">Capacidade total</div></div>
      <div class="summary-chip"><strong>${olt.summary.usage_pct}%</strong><div class="muted">Uso geral</div></div>
    </div>
    <div class="boards-grid">
      ${olt.boards_data.map(renderBoardCard).join("")}
    </div>
  `;
  syncOnuModalFromPanel();
}

function renderOltVlans() {
  const canManageOlts = hasPermission("olts_manage");
  const container = document.getElementById("oltVlanList");
  const form = document.getElementById("addOltVlanForm");
  if (!container || !form) {
    return;
  }
  form.querySelectorAll("input, button, select").forEach((node) => {
    node.disabled = !canManageOlts;
  });
  const olt = state.olts.find((item) => item.id === state.activeOltId);
  if (!olt) {
    container.innerHTML = '<div class="muted">Selecione uma OLT para gerenciar VLANs.</div>';
    return;
  }
  const rows = state.oltVlansByOltId[state.activeOltId] || [];
  const filter = String(state.oltVlanFilter || "").trim().toLowerCase();
  const filteredRows = rows.filter((item) => {
    if (!filter) {
      return true;
    }
    return `${item.vlan_id} ${item.name || ""} ${item.description || ""} ${item.source || ""}`
      .toLowerCase()
      .includes(filter);
  });
  const selectedVlanId = Number(state.selectedOltVlanId);
  const selected = filteredRows.find((item) => item.vlan_id === selectedVlanId) || filteredRows[0] || null;
  if (selected && selected.vlan_id !== state.selectedOltVlanId) {
    state.selectedOltVlanId = selected.vlan_id;
  }
  if (!selected) {
    state.selectedOltVlanId = null;
  }
  container.innerHTML = rows.length
    ? `
      <div class="vlan-list">
        <div class="inline-two">
          <input id="oltVlanFilter" class="search" placeholder="Buscar VLAN por numero, nome ou descricao" value="${state.oltVlanFilter || ""}">
          <select id="oltVlanSelect" class="search">
            ${filteredRows
              .map(
                (item) => `
                  <option value="${item.vlan_id}" ${selected && selected.vlan_id === item.vlan_id ? "selected" : ""}>
                    VLAN ${item.vlan_id} (${item.source})
                  </option>
                `
              )
              .join("")}
          </select>
        </div>
        <div class="muted">${filteredRows.length} de ${rows.length} VLANs exibidas</div>
        <article class="alert-card">
          <div class="panel-head">
            <strong>VLAN ${selected ? selected.vlan_id : "-"}</strong>
            <div class="request-actions">
              <span class="status-pill ${selected?.source === "manual" ? "ok" : "warning"}">${selected?.source || "-"}</span>
              <button type="button" class="secondary-button" data-olt-vlan-action="save" ${selected && canManageOlts ? "" : "disabled"}>Salvar</button>
              <button type="button" class="secondary-button" data-olt-vlan-action="delete" ${selected && canManageOlts ? "" : "disabled"}>Excluir</button>
            </div>
          </div>
          <div class="inline-two">
            <input id="selectedVlanName" class="search" value="${selected?.name || ""}" placeholder="Nome da VLAN" ${selected && canManageOlts ? "" : "disabled"}>
            <input id="selectedVlanDescription" class="search" value="${selected?.description || ""}" placeholder="Descricao da VLAN" ${selected && canManageOlts ? "" : "disabled"}>
          </div>
          <div class="muted">Atualizada em ${selected?.updated_at ? formatDateTime(selected.updated_at) : "-"}</div>
        </article>
      </div>
    `
    : '<div class="muted">Nenhuma VLAN cadastrada para esta OLT.</div>';
}

function populateOltFormFromActive() {
  const form = document.getElementById("createOltForm");
  const olt = state.olts.find((item) => item.id === state.activeOltId);
  const connection = state.connections.find((item) => item.olt_id === state.activeOltId);
  if (!olt) {
    clearOltForm(false);
    return;
  }
  const boardSlots = olt.boards_data.map((board) => board.slot).join(",");
  const boardModel = olt.boards_data[0]?.model || "";
  const portsPerBoard = olt.boards_data[0]?.ports_total || 4;
  const capacityOnu = olt.boards_data[0]?.ports?.[0]?.capacity_onu || 128;
  form.editing_olt_id.value = olt.id;
  form.name.value = olt.name;
  form.host.value = olt.host;
  form.brand.value = olt.brand;
  form.model.value = olt.model;
  form.username.value = connection?.username || "";
  form.password.value = connection?.password || "";
  form.transport_type.value = connection?.transport_type || "ssh";
  form.transport_type.dataset.lastTransport = form.transport_type.value;
  form.port.value = connection?.port || defaultPortForTransport(form.transport_type.value);
  form.firmware.value = olt.firmware || "";
  form.board_model.value = boardModel;
  form.board_slots.value = boardSlots;
  form.ports_per_board.value = portsPerBoard;
  form.capacity_onu.value = capacityOnu;
  form.status.value = olt.status || "online";
  setOltConnectStatus(
    connection?.last_connect_status === "connected"
      ? "ok"
      : connection?.last_connect_status === "error"
        ? "critical"
        : "warning",
    connection?.last_connect_message || "Sem teste de conexao."
  );
  refreshOltTemplateCatalog();
}

function clearOltForm(resetSelection = true) {
  const form = document.getElementById("createOltForm");
  form.reset();
  form.editing_olt_id.value = "";
  form.ports_per_board.value = 4;
  form.capacity_onu.value = 128;
  form.status.value = "online";
  form.transport_type.value = "ssh";
  form.transport_type.dataset.lastTransport = "ssh";
  form.port.value = 22;
  setOltConnectStatus("warning", "Sem teste de conexao.");
  refreshOltTemplateCatalog();
  if (resetSelection) {
    state.activeOltId = null;
    renderOltTabs();
    renderOltPanelTabs();
    renderOltPanels();
    renderOltDetails();
    renderOltVlans();
  }
}

function renderBoardCard(board) {
  return `
    <article class="board-card">
      <div class="panel-head">
        <h3>Placa ${board.slot}</h3>
        <span class="status-pill ${board.status === "online" ? "ok" : "warning"}">${board.status}</span>
      </div>
      <div class="muted">${board.model} - ${board.ports_total} portas</div>
      <table class="ports-table">
        <thead>
          <tr>
            <th>Porta</th>
            <th>ONUs</th>
            <th>Uso</th>
            <th>Alerta</th>
          </tr>
        </thead>
        <tbody>
          ${board.ports
            .map(
              (port) => `
                <tr>
                  <td>${port.name}</td>
                  <td>${port.used_onu}/${port.capacity_onu}</td>
                  <td>${port.usage_pct}%</td>
                  <td><span class="status-pill ${port.alert_level}">${port.alert_level}</span></td>
                </tr>
              `
            )
            .join("")}
        </tbody>
      </table>
    </article>
  `;
}

function renderOnuTable() {
  const filter = state.onuFilter.trim().toLowerCase();
  const rows = state.onus.filter((onu) => {
    if (!filter) {
      return true;
    }
    return [
      onu.client_name,
      onu.serial,
      onu.city,
      onu.olt_name,
      onu.port_name,
      onu.model,
    ]
      .join(" ")
      .toLowerCase()
      .includes(filter);
  });
  const total = rows.length;
  const pageSize = Math.max(1, Number(state.onuPageSize || 100));
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  if (state.onuPage > totalPages) {
    state.onuPage = totalPages;
  }
  if (state.onuPage < 1) {
    state.onuPage = 1;
  }
  const start = (state.onuPage - 1) * pageSize;
  const end = Math.min(start + pageSize, total);
  const pageRows = rows.slice(start, end);
  const pagination = buildOnuPagination(state.onuPage, totalPages);

  document.getElementById("onuTable").innerHTML = `
    <div class="onu-toolbar">
      <div class="onu-pager">
        ${pagination
          .map(
            (item) => `
              <button type="button" class="pager-button ${item.active ? "active" : ""}" data-onu-page="${item.page}">
                ${item.label}
              </button>
            `
          )
          .join("")}
      </div>
      <div class="onu-count">${total ? `${start + 1}-${end}` : "0"} ONUs de ${total} exibidas</div>
    </div>
    <table class="onu-table">
      <thead>
        <tr>
          <th>Status</th>
          <th>View</th>
          <th>Name</th>
          <th>SN / MAC</th>
          <th>ONU</th>
          <th>Zone</th>
          <th>ODB</th>
          <th>Sinal</th>
          <th>B/R</th>
          <th>VLAN</th>
          <th>VoIP</th>
          <th>TV</th>
          <th>Type</th>
          <th>Auth date</th>
        </tr>
      </thead>
      <tbody>
        ${pageRows
          .map(
            (onu) => {
              const onuMode = getOnuMode(onu);
              const rowClasses = [
                state.selectedOnuId === onu.id ? "table-row-active" : "",
                onu?.data_quality?.stale ? "table-row-stale" : "",
              ]
                .filter(Boolean)
                .join(" ");
              return `
              <tr class="${rowClasses}" data-onu-id="${onu.id}">
                <td>${renderOnuTableStatusCell(onu)}</td>
                <td><button type="button" class="view-button" data-onu-view-id="${onu.id}">View</button></td>
                <td>${onu.client_name || "-"}</td>
                <td>${onu.serial}</td>
                <td>${formatOnuPath(onu)}</td>
                <td>${onu.neighborhood || "-"}<br>${onu.city || "-"}</td>
                <td>None</td>
                <td>${formatSignalCell(onu)}</td>
                <td><span class="bridge-badge ${onuMode === "route" ? "route-mode" : ""}">${formatOnuModeLabel(onuMode)}</span></td>
                <td>${formatVlanValue(onu.vlan_id)}</td>
                <td>${hasVoip(onu) ? '<span class="service-badge">VoIP</span>' : "-"}</td>
                <td>${hasTv(onu) ? '<span class="service-badge">CATV</span>' : "-"}</td>
                <td>${onu.model || "-"}</td>
                <td>${formatAuthDate(onu.updated_at)}</td>
              </tr>
            `;
            }
          )
          .join("")}
      </tbody>
    </table>
  `;
  queueOnuTableSignalVerification(pageRows);
}

function shouldVerifyOnuSignalInTable(onu) {
  if (!onu || normalizeOnuStatusValue(onu.status) !== "warning") {
    return false;
  }
  return hasSignalValue(onu.signal_dbm) || hasSignalValue(onu.signal_olt_rx_dbm);
}

function queueOnuTableSignalVerification(pageRows) {
  if (state.onuTableSignalVerifyInFlight || document.visibilityState !== "visible") {
    return;
  }
  const rows = Array.isArray(pageRows) ? pageRows : [];
  if (!rows.length) {
    return;
  }
  const now = Date.now();
  const candidateIds = rows
    .filter((onu) => shouldVerifyOnuSignalInTable(onu))
    .map((onu) => Number(onu.id))
    .filter(Boolean)
    .filter((onuId) => {
      const lastVerifiedAt = Number(state.onuTableSignalVerifiedAtByOnuId[onuId] || 0);
      return !lastVerifiedAt || now - lastVerifiedAt >= ONU_TABLE_SIGNAL_VERIFY_COOLDOWN_MS;
    })
    .slice(0, ONU_TABLE_SIGNAL_VERIFY_BATCH_SIZE);
  if (!candidateIds.length) {
    return;
  }
  runOnuTableSignalVerification(candidateIds);
}

async function runOnuTableSignalVerification(onuIds) {
  if (state.onuTableSignalVerifyInFlight) {
    return;
  }
  const queue = Array.isArray(onuIds) ? onuIds.map((item) => Number(item)).filter(Boolean) : [];
  if (!queue.length) {
    return;
  }
  state.onuTableSignalVerifyInFlight = true;
  let hasUpdates = false;
  try {
    for (const onuId of queue) {
      if (document.visibilityState !== "visible") {
        break;
      }
      state.onuTableSignalVerifiedAtByOnuId[onuId] = Date.now();
      try {
        const result = await collectOnuLive(onuId, ONU_TABLE_SIGNAL_VERIFY_FIELDS);
        if (result?.onu) {
          hasUpdates = true;
        }
      } catch (_) {
        // Falha pontual nao interrompe o lote.
      }
      await sleep(120);
    }
  } finally {
    state.onuTableSignalVerifyInFlight = false;
  }
  if (hasUpdates) {
    renderOnuTable();
  }
}

function buildOnuPagination(page, totalPages) {
  const items = [];
  const start = Math.max(1, page - 2);
  const end = Math.min(totalPages, page + 2);
  for (let idx = start; idx <= end; idx += 1) {
    items.push({ page: idx, label: String(idx), active: idx === page });
  }
  return items;
}

function formatOnuPath(onu) {
  return `${onu.olt_name} ${onu.board_slot}/${(onu.port_name || "").replace("PON ", "")}:${onu.pon_position ?? "-"}`;
}

function hasSignalValue(value) {
  if (value === null || value === undefined || value === "") {
    return false;
  }
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return false;
  }
  return Math.abs(numeric) > 0.001;
}

function formatDbmValue(value) {
  return hasSignalValue(value) ? `${value} dBm` : "-";
}

function formatSignalCell(onu) {
  const rx = onu?.signal_dbm;
  const tx = onu?.signal_tx_dbm;
  const oltRx = onu?.signal_olt_rx_dbm;
  if (!hasSignalValue(rx) && !hasSignalValue(tx) && !hasSignalValue(oltRx)) {
    return "-";
  }
  const referenceSignal = hasSignalValue(rx) ? rx : hasSignalValue(oltRx) ? oltRx : tx;
  const bars = Math.round(Math.max(1, Math.min(5, signalPercent(referenceSignal) / 20)));
  const label = `${hasSignalValue(rx) ? `RX ${rx} dBm` : "RX -"} / ${hasSignalValue(tx) ? `TX ${tx} dBm` : "TX -"} / ${hasSignalValue(oltRx) ? `RET ${oltRx} dBm` : "RET -"}`;
  return `
    <span class="signal-visual">
      <span class="signal-bars">${"|".repeat(bars)}</span>
      <small>${label}</small>
    </span>
  `;
}

function formatVlanValue(vlanId) {
  const numeric = Number(vlanId);
  if (!Number.isFinite(numeric) || numeric < 1) {
    return "-";
  }
  return String(Math.trunc(numeric));
}

function normalizeOnuMode(value, fallback = "bridge") {
  const normalizedValue = String(value || "").trim().toLowerCase();
  if (["route", "router", "routing"].includes(normalizedValue)) {
    return "route";
  }
  if (["bridge", "bridging"].includes(normalizedValue)) {
    return "bridge";
  }
  return String(fallback || "bridge").trim().toLowerCase() || "bridge";
}

function inferOnuModeFromProfiles(lineProfile, serviceProfile, fallback = "bridge") {
  const profileNames = [lineProfile, serviceProfile]
    .map((value) => String(value || "").trim().toLowerCase())
    .filter(Boolean)
    .join(" ");
  if (!profileNames) {
    return normalizeOnuMode(fallback);
  }
  if (profileNames.includes("router") || profileNames.includes("route")) {
    return "route";
  }
  if (profileNames.includes("bridge") || profileNames.includes("smartolt") || profileNames.includes("generic_")) {
    return "bridge";
  }
  return normalizeOnuMode(fallback);
}

function getOnuMode(onu) {
  return normalizeOnuMode(onu?.onu_mode, inferOnuModeFromProfiles(onu?.line_profile, onu?.service_profile, "bridge"));
}

function formatOnuModeLabel(mode) {
  return normalizeOnuMode(mode) === "route" ? "Route" : "Bridge";
}

function hasVoip(onu) {
  return String(onu.profile_name || "").toLowerCase().includes("voip");
}

function hasTv(onu) {
  const profile = String(onu.profile_name || "").toLowerCase();
  return profile.includes("catv") || profile.includes("iptv");
}

function formatAuthDate(value) {
  if (!value) {
    return "-";
  }
  const date = new Date(value);
  const day = String(date.getDate()).padStart(2, "0");
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const year = date.getFullYear();
  return `${day}-${month}-${year}`;
}

function formatRelativeAgeSeconds(value) {
  const seconds = Math.max(0, Number(value || 0));
  if (!Number.isFinite(seconds)) {
    return "-";
  }
  if (seconds < 5) {
    return "agora";
  }
  if (seconds < 60) {
    return `${Math.round(seconds)}s`;
  }
  if (seconds < 3600) {
    return `${Math.round(seconds / 60)} min`;
  }
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.round((seconds % 3600) / 60);
  return minutes ? `${hours}h ${minutes}m` : `${hours}h`;
}

function formatFieldSourceLabel(source) {
  const normalized = String(source || "").trim().toLowerCase();
  if (!normalized) {
    return "Sem fonte";
  }
  const labels = {
    poll: "Poll",
    "poll-snmp": "Poll SNMP",
    "poll-pon": "Poll PON",
    "live-snmp": "Ao vivo SNMP",
    "live-cli": "Ao vivo CLI",
    "live-pon-snmp": "LIVE PON",
    "live-profile": "Perfil local",
    "live-gate": "Bloqueio LIVE",
    "mixed-live": "Misto ao vivo",
    cli: "CLI",
    metrics: "Metricas",
    status: "Status",
    signal: "Sinal",
    traffic: "Trafego",
  };
  return labels[normalized] || normalized;
}

function formatConfidenceLabel(confidence) {
  const normalized = String(confidence || "").trim().toLowerCase();
  if (normalized === "high") {
    return "Confianca alta";
  }
  if (normalized === "medium") {
    return "Confianca media";
  }
  if (normalized === "low") {
    return "Confianca baixa";
  }
  return "Confianca indefinida";
}

function getMetaPillClass(meta) {
  if (!meta || typeof meta !== "object") {
    return "warning";
  }
  if (meta.stale) {
    return "warning";
  }
  if (String(meta.confidence || "").toLowerCase() === "low") {
    return "critical";
  }
  if (String(meta.confidence || "").toLowerCase() === "medium") {
    return "warning";
  }
  return "ok";
}

function getQualitySummaryLabel(quality) {
  const freshness = String(quality?.freshness || "").toLowerCase();
  if (freshness === "live") {
    return "Ao vivo";
  }
  if (quality?.stale) {
    return "Possivel dado antigo";
  }
  if (freshness === "aging") {
    return "Fora do ultimo ciclo";
  }
  return "Atual";
}

function renderOnuFieldMetaItem(label, meta) {
  const statusClass = getMetaPillClass(meta);
  const sourceLabel = formatFieldSourceLabel(meta?.source);
  const freshnessLabel = meta?.stale
    ? "Possivel antigo"
    : String(meta?.freshness || "").toLowerCase() === "live"
      ? "Ao vivo"
      : "Atual";
  const updatedAt = meta?.updated_at ? formatDateTime(meta.updated_at) : "-";
  const ageLabel = meta?.age_sec != null ? formatRelativeAgeSeconds(meta.age_sec) : "-";
  const detail = meta?.detail || "Sem detalhe adicional.";
  return `
    <article class="onu-quality-item">
      <strong>${label}</strong>
      <div class="onu-quality-chips">
        <span class="status-pill ${statusClass}">${escapeHtml(sourceLabel)}</span>
        <span class="status-pill ${statusClass}">${escapeHtml(formatConfidenceLabel(meta?.confidence))}</span>
      </div>
      <small>${escapeHtml(freshnessLabel)}. ${escapeHtml(detail)}</small>
      <small>Atualizado ${escapeHtml(updatedAt)}${ageLabel !== "-" ? ` (${escapeHtml(ageLabel)})` : ""}</small>
    </article>
  `;
}

function renderOnuDataQualityCard(onu) {
  const quality = onu?.data_quality || {};
  const summaryClass = getMetaPillClass(quality);
  const summaryLabel = getQualitySummaryLabel(quality);
  const updatedAt = quality?.updated_at ? formatDateTime(quality.updated_at) : "-";
  const ageLabel = quality?.age_sec != null ? formatRelativeAgeSeconds(quality.age_sec) : "-";
  return `
    <div class="onu-quality-card">
      <div class="panel-head">
        <strong>Origem e qualidade da leitura</strong>
        <span class="status-pill ${summaryClass}">${summaryLabel}</span>
      </div>
      <div class="onu-quality-summary">
        <span class="muted">Ultima coleta ${updatedAt}${ageLabel !== "-" ? ` (${ageLabel})` : ""}</span>
        <span class="muted">Janela esperada ${Math.max(1, Math.round(Number(quality?.stale_after_sec || 0) / 60))} min</span>
      </div>
      <div class="onu-quality-grid">
        ${renderOnuFieldMetaItem("Status", onu?.field_meta?.status)}
        ${renderOnuFieldMetaItem("Sinal", onu?.field_meta?.signal)}
        ${renderOnuFieldMetaItem("Trafego PON", onu?.field_meta?.traffic)}
        ${renderOnuFieldMetaItem("Temperatura", onu?.field_meta?.temperature)}
      </div>
    </div>
  `;
}

function normalizeOnuStatusValue(status) {
  return String(status || "").trim().toLowerCase();
}

function getOnuStatusPresentation(onu) {
  const normalized = normalizeOnuStatusValue(onu?.status);
  const stale = Boolean(onu?.data_quality?.stale);
  const hasSignal =
    hasSignalValue(onu?.signal_dbm) ||
    hasSignalValue(onu?.signal_tx_dbm) ||
    hasSignalValue(onu?.signal_olt_rx_dbm);

  if (normalized === "active" || normalized === "online" || normalized === "up") {
    return {
      label: stale ? "Online (dado antigo)" : "Online",
      dotClass: "ok",
      isOnline: true,
    };
  }
  if (normalized === "warning") {
    return {
      label: hasSignal ? "Warning (com sinal)" : "Warning",
      dotClass: "warning",
      isOnline: false,
    };
  }
  if (normalized === "offline" || normalized === "down" || normalized === "inactive" || normalized === "disabled") {
    return { label: "Offline", dotClass: "warning", isOnline: false };
  }
  if (!normalized) {
    return { label: "Sem status", dotClass: "warning", isOnline: false };
  }
  return { label: normalized.toUpperCase(), dotClass: "warning", isOnline: false };
}

function renderOnuTableStatusCell(onu) {
  const statusView = getOnuStatusPresentation(onu);
  const quality = onu?.data_quality || {};
  const summaryClass = getMetaPillClass(quality);
  const sourceMeta = onu?.field_meta?.status || quality;
  const sourceClass = getMetaPillClass(sourceMeta);
  const sourceLabel = formatFieldSourceLabel(sourceMeta?.source || quality?.source);
  const updatedAt = quality?.updated_at ? formatDateTime(quality.updated_at) : "-";
  const ageLabel = quality?.age_sec != null ? formatRelativeAgeSeconds(quality.age_sec) : "-";
  return `
    <div class="onu-status-cell">
      <div class="onu-status-main">
        <span class="onu-status-dot ${statusView.dotClass}"></span>
        <div class="onu-status-copy">
          <strong>${escapeHtml(statusView.label)}</strong>
          <div class="onu-status-badges">
            <span class="status-pill ${summaryClass}">${escapeHtml(getQualitySummaryLabel(quality))}</span>
            ${sourceLabel !== "Sem fonte" ? `<span class="status-pill ${sourceClass}">${escapeHtml(sourceLabel)}</span>` : ""}
          </div>
          <small>Atualizado ${escapeHtml(updatedAt)}${ageLabel !== "-" ? ` (${escapeHtml(ageLabel)})` : ""}</small>
        </div>
      </div>
    </div>
  `;
}

function extractCoverageSummary(details) {
  if (!details || typeof details !== "object") {
    return null;
  }
  const touched = Number(details.onus_touched);
  const total = Number(details.onus_total);
  let ratio = Number(details.coverage_ratio);
  if (!Number.isFinite(ratio) && Number.isFinite(touched) && Number.isFinite(total) && total > 0) {
    ratio = touched / total;
  }
  if (!Number.isFinite(ratio) && !Number.isFinite(touched) && !Number.isFinite(total)) {
    return null;
  }
  return {
    ratio: Number.isFinite(ratio) ? ratio : null,
    touched: Number.isFinite(touched) ? touched : null,
    total: Number.isFinite(total) ? total : null,
    staleOnus: Number.isFinite(Number(details.stale_onus)) ? Number(details.stale_onus) : null,
    mode: String(details.mode || "").trim(),
  };
}

function formatCoverageMode(mode) {
  const normalized = String(mode || "").trim().toLowerCase();
  if (normalized === "fast-stale-onu-reset") {
    return "Fast com ajuste";
  }
  if (normalized === "fast-partial-skip") {
    return "Fast parcial";
  }
  if (normalized === "fast") {
    return "Fast";
  }
  return normalized || "Cobertura";
}

function renderCoverageSummary(coverage, extraClass = "") {
  if (!coverage) {
    return "";
  }
  const ratioLabel = coverage.ratio != null ? `${Math.round(coverage.ratio * 100)}%` : "-";
  const touchedLabel =
    coverage.touched != null && coverage.total != null ? `${coverage.touched}/${coverage.total} ONUs` : "ONUs";
  return `
    <div class="coverage-row ${extraClass}">
      <span class="status-pill ${coverage.ratio != null && coverage.ratio < 0.5 ? "critical" : "warning"}">Cobertura ${ratioLabel}</span>
      <span class="status-pill warning">${escapeHtml(touchedLabel)}</span>
      <span class="status-pill warning">${escapeHtml(formatCoverageMode(coverage.mode))}</span>
      ${coverage.staleOnus ? `<span class="status-pill warning">${coverage.staleOnus} warning</span>` : ""}
    </div>
  `;
}

function findSelectedOnu() {
  return state.onus.find((item) => item.id === state.selectedOnuId) || null;
}

function getOnuSignalRefreshStatus(onuId) {
  const normalizedOnuId = Number(onuId);
  const remainingSeconds = Math.max(
    0,
    Number.isFinite(Number(state.onuSignalRefreshCountdown))
      ? Number(state.onuSignalRefreshCountdown)
      : ONU_SIGNAL_AUTO_REFRESH_INTERVAL_SEC
  );
  if (!normalizedOnuId || normalizedOnuId !== Number(state.selectedOnuId)) {
    return { text: `${ONU_SIGNAL_AUTO_REFRESH_INTERVAL_SEC}s`, statusClass: "warning" };
  }
  if (Number(state.onuSignalRefreshPendingOnuId) === normalizedOnuId) {
    return { text: "Atualizando...", statusClass: "warning" };
  }
  if (document.visibilityState !== "visible") {
    return { text: `Pausado ${remainingSeconds}s`, statusClass: "warning" };
  }
  return { text: `${remainingSeconds}s`, statusClass: "ok" };
}

function getOnuLiveMonitorStatus(onuId) {
  const normalizedOnuId = Number(onuId);
  const intervalSeconds = Math.max(1, Math.round(ONU_LIVE_MONITOR_INTERVAL_MS / 1000));
  if (!normalizedOnuId || Number(state.liveMonitorOnuId) !== normalizedOnuId) {
    return { text: `LIVE ${intervalSeconds}s`, statusClass: "warning" };
  }
  if (state.liveMonitorInFlight) {
    return { text: "LIVE atualizando...", statusClass: "warning" };
  }
  const nextRunAtMs = Number(state.liveMonitorNextRunAtMs);
  const remainingSeconds = Number.isFinite(nextRunAtMs)
    ? Math.max(0, Math.ceil((nextRunAtMs - Date.now()) / 1000))
    : intervalSeconds;
  if (document.visibilityState !== "visible") {
    return { text: `LIVE pausado ${remainingSeconds}s`, statusClass: "warning" };
  }
  return { text: `LIVE ${remainingSeconds}s`, statusClass: "ok" };
}

function updateOnuSignalAutoRefreshUi() {
  const countdownNodes = document.querySelectorAll("[data-onu-signal-countdown]");
  countdownNodes.forEach((node) => {
    const status = getOnuSignalRefreshStatus(node.dataset.onuSignalCountdown);
    node.textContent = status.text;
    node.className = `status-pill ${status.statusClass}`;
  });
  updateOnuLiveMonitorUi();
}

function updateOnuLiveMonitorUi() {
  const countdownNodes = document.querySelectorAll("[data-onu-live-countdown]");
  countdownNodes.forEach((node) => {
    const status = getOnuLiveMonitorStatus(node.dataset.onuLiveCountdown);
    node.textContent = status.text;
    node.className = `status-pill ${status.statusClass}`;
  });
}

function stopOnuSignalAutoRefreshTimer() {
  if (state.onuSignalRefreshTimerId) {
    clearInterval(state.onuSignalRefreshTimerId);
    state.onuSignalRefreshTimerId = null;
  }
}

function resetOnuSignalAutoRefreshCountdown(onuId) {
  const normalizedOnuId = Number(onuId);
  if (!normalizedOnuId || normalizedOnuId !== Number(state.selectedOnuId)) {
    return;
  }
  state.onuSignalRefreshOnuId = normalizedOnuId;
  state.onuSignalRefreshCountdown = ONU_SIGNAL_AUTO_REFRESH_INTERVAL_SEC;
  updateOnuSignalAutoRefreshUi();
}

async function runOnuSignalAutoRefreshCycle(onuId) {
  state.onuSignalRefreshPendingOnuId = Number(onuId);
  updateOnuSignalAutoRefreshUi();
  try {
    await collectOnuLive(onuId, ONU_SIGNAL_AUTO_REFRESH_FIELDS);
  } catch (_) {
    // O erro ja aparece via state.onuLiveStatus.
  } finally {
    if (Number(state.onuSignalRefreshPendingOnuId) === Number(onuId)) {
      state.onuSignalRefreshPendingOnuId = null;
    }
    if (Number(state.selectedOnuId) === Number(onuId)) {
      state.onuSignalRefreshCountdown = ONU_SIGNAL_AUTO_REFRESH_INTERVAL_SEC;
    }
    updateOnuSignalAutoRefreshUi();
  }
}

async function tickOnuSignalAutoRefresh() {
  const selectedOnuId = Number(state.selectedOnuId);
  if (!selectedOnuId) {
    stopOnuSignalAutoRefreshTimer();
    updateOnuSignalAutoRefreshUi();
    return;
  }
  if (document.visibilityState !== "visible") {
    stopOnuSignalAutoRefreshTimer();
    updateOnuSignalAutoRefreshUi();
    return;
  }
  if (Number(state.onuSignalRefreshPendingOnuId) === selectedOnuId) {
    updateOnuSignalAutoRefreshUi();
    return;
  }
  state.onuSignalRefreshCountdown = Math.max(0, Number(state.onuSignalRefreshCountdown || 0) - 1);
  updateOnuSignalAutoRefreshUi();
  if (state.onuSignalRefreshCountdown > 0) {
    return;
  }
  await runOnuSignalAutoRefreshCycle(selectedOnuId);
}

function startOnuSignalAutoRefreshTimer() {
  if (state.onuSignalRefreshTimerId || document.visibilityState !== "visible" || !state.selectedOnuId) {
    return;
  }
  state.onuSignalRefreshTimerId = setInterval(() => {
    tickOnuSignalAutoRefresh();
  }, 1000);
}

function syncOnuSignalAutoRefresh(resetCountdown = false) {
  const selectedOnuId = Number(state.selectedOnuId);
  if (!selectedOnuId) {
    state.onuSignalRefreshOnuId = null;
    state.onuSignalRefreshCountdown = ONU_SIGNAL_AUTO_REFRESH_INTERVAL_SEC;
    state.onuSignalRefreshPendingOnuId = null;
    stopOnuSignalAutoRefreshTimer();
    updateOnuSignalAutoRefreshUi();
    return;
  }
  if (resetCountdown || state.onuSignalRefreshOnuId !== selectedOnuId) {
    state.onuSignalRefreshOnuId = selectedOnuId;
    state.onuSignalRefreshCountdown = ONU_SIGNAL_AUTO_REFRESH_INTERVAL_SEC;
  }
  if (document.visibilityState !== "visible") {
    stopOnuSignalAutoRefreshTimer();
    updateOnuSignalAutoRefreshUi();
    return;
  }
  startOnuSignalAutoRefreshTimer();
  updateOnuSignalAutoRefreshUi();
}

function handleDocumentVisibilityChange() {
  if (document.visibilityState === "visible") {
    syncOnuSignalAutoRefresh();
    renderOnuTable();
    return;
  }
  stopOnuSignalAutoRefreshTimer();
  updateOnuSignalAutoRefreshUi();
}

function getOnuPhysicalStatusEntry(onu, field) {
  const liveStatus = state.onuPhysicalStatusByOnuId?.[onu.id]?.[field];
  if (liveStatus?.state) {
    return liveStatus;
  }
  const normalizedStatus = normalizeOnuStatusValue(onu?.status);
  const isStatusOnline = ["active", "online", "up"].includes(normalizedStatus);
  const hasOpticalSignal = hasSignalValue(onu?.signal_dbm) || hasSignalValue(onu?.signal_olt_rx_dbm);
  if (field === "power" && isStatusOnline) {
    return { state: "on", label: "Ligada", detail: "ONU online.", source: "status" };
  }
  if (field === "power" && hasOpticalSignal) {
    const detail = hasSignalValue(onu?.signal_dbm)
      ? `Sinal RX presente: ${formatDbmValue(onu.signal_dbm)}`
      : `Sinal ONU->OLT presente: ${formatDbmValue(onu.signal_olt_rx_dbm)}`;
    return { state: "on", label: "Ligada (inferido)", detail, source: "signal" };
  }
  if (field === "fiber" && hasSignalValue(onu.signal_dbm) && isStatusOnline) {
    return { state: "up", label: "UP", detail: `RX ${formatDbmValue(onu.signal_dbm)}`, source: "signal" };
  }
  if (field === "fiber" && hasOpticalSignal) {
    const detail = hasSignalValue(onu?.signal_dbm)
      ? `RX ${formatDbmValue(onu.signal_dbm)}`
      : `ONU->OLT ${formatDbmValue(onu.signal_olt_rx_dbm)}`;
    return { state: "up", label: "UP (inferido)", detail, source: "signal" };
  }
  const trafficDown = Number(onu.traffic_down_mbps || 0);
  const trafficUp = Number(onu.traffic_up_mbps || 0);
  if (field === "ethernet" && (isStatusOnline || hasOpticalSignal) && (trafficDown > 0.01 || trafficUp > 0.01)) {
    return {
      state: "up",
      label: "UP",
      detail: `Down ${trafficDown.toFixed(2)} Mbps / Up ${trafficUp.toFixed(2)} Mbps`,
      source: "traffic",
    };
  }
  if (!isStatusOnline && !hasOpticalSignal) {
    if (field === "power") {
      return {
        state: "unconfirmed",
        label: "Sem confirmacao",
        detail: "OLT nao confirma falta de energia sem evento claro.",
        source: "",
      };
    }
    if (field === "fiber") {
      return {
        state: "unconfirmed",
        label: "Sem confirmacao",
        detail: "OLT nao confirma se ainda existe ONU energizada na fibra.",
        source: "",
      };
    }
    return {
      state: "unconfirmed",
      label: "Sem confirmacao",
      detail: "OLT nao confirma o link RJ45 desta ONU enquanto ela estiver offline.",
      source: "",
    };
  }
  return { state: "unknown", label: "Sem leitura", detail: "Aguardando leitura da ONU.", source: "" };
}

function getOnuDisconnectReasonEntry(onu) {
  const liveReason = state.onuPhysicalStatusByOnuId?.[onu.id]?.disconnect_reason;
  if (liveReason?.state) {
    return liveReason;
  }
  const power = getOnuPhysicalStatusEntry(onu, "power");
  const fiber = getOnuPhysicalStatusEntry(onu, "fiber");
  const ethernet = getOnuPhysicalStatusEntry(onu, "ethernet");
  if (String(onu?.status || "").toLowerCase() === "active") {
    return { state: "online", label: "ONU online", detail: "Sem causa de queda no momento.", source: "status" };
  }
  if (String(power?.state || "").toLowerCase() === "on" && String(fiber?.state || "").toLowerCase() === "up") {
    return {
      state: "online",
      label: "ONU com sinal optico",
      detail: fiber?.detail || "Sem causa de queda: enlace optico em funcionamento.",
      source: fiber?.source || power?.source || "signal",
    };
  }
  if (String(power?.state || "").toLowerCase() === "probable-off") {
    return { ...power, state: "probable-power-off" };
  }
  if (String(fiber?.state || "").toLowerCase() === "probable-loss") {
    return { ...fiber, state: "probable-fiber-cut", label: "Provavel rompimento/perda de fibra" };
  }
  if (String(ethernet?.state || "").toLowerCase() === "probable-down") {
    return { ...ethernet, state: "probable-ethernet-down", label: "Provavel falha no RJ45" };
  }
  return {
    state: "unconfirmed",
    label: "Sem conclusao da OLT",
    detail: "A OLT nao retornou DGi, LOS, LOFi ou outra causa conclusiva para a queda desta ONU.",
    source: "",
  };
}

function getOnuPhysicalMeta(onu) {
  return state.onuPhysicalStatusByOnuId?.[onu.id]?.meta || null;
}

function renderOnuPhysicalMeta(onu) {
  const meta = getOnuPhysicalMeta(onu);
  if (!meta) {
    return `
      <div class="onu-physical-meta">
        <div><strong>Run state</strong><span>-</span></div>
        <div><strong>Last down cause</strong><span>-</span></div>
        <div><strong>alarm-state</strong><span>Sem leitura</span></div>
      </div>
    `;
  }
  const runState = String(meta.run_state || "").trim() || "-";
  const lastDownCause = String(meta.last_down_cause || "").trim() || "-";
  const alarmState = meta.alarm_output_available ? "Respondeu" : "Sem resposta";
  return `
    <div class="onu-physical-meta">
      <div><strong>Run state</strong><span>${escapeHtml(runState)}</span></div>
      <div><strong>Last down cause</strong><span>${escapeHtml(lastDownCause)}</span></div>
      <div><strong>alarm-state</strong><span>${escapeHtml(alarmState)}</span></div>
    </div>
  `;
}

function physicalStatusPillClass(status) {
  const stateValue = String(status?.state || "").toLowerCase();
  if (["on", "up", "online"].includes(stateValue)) {
    return "ok";
  }
  if (["off", "down", "loss"].includes(stateValue)) {
    return "critical";
  }
  if (
    [
      "probable-off",
      "probable-loss",
      "probable-down",
      "probable-power-off",
      "probable-fiber-cut",
      "probable-ethernet-down",
      "unconfirmed",
    ].includes(stateValue)
  ) {
    return "warning";
  }
  return "warning";
}

function renderOnuPhysicalPortIcon(kind, status) {
  const accentClass = physicalStatusPillClass(status);
  if (kind === "power") {
    return `
      <svg viewBox="0 0 64 64" class="onu-physical-icon-svg ${accentClass}" aria-hidden="true">
        <circle cx="32" cy="34" r="18"></circle>
        <path d="M32 10 v16"></path>
      </svg>
    `;
  }
  if (kind === "fiber") {
    return `
      <svg viewBox="0 0 64 64" class="onu-physical-icon-svg ${accentClass}" aria-hidden="true">
        <circle cx="18" cy="32" r="7"></circle>
        <path d="M25 32 h14"></path>
        <path d="M39 20 c11 5 11 19 0 24"></path>
        <path d="M34 24 c7 4 7 12 0 16"></path>
      </svg>
    `;
  }
  return `
    <svg viewBox="0 0 64 64" class="onu-physical-icon-svg ${accentClass}" aria-hidden="true">
      <path d="M16 18 h32 v20 l-6 8 h-20 l-6 -8 z"></path>
      <path d="M24 18 v8"></path>
      <path d="M30 18 v8"></path>
      <path d="M36 18 v8"></path>
      <path d="M42 18 v8"></path>
    </svg>
  `;
}

function renderOnuPhysicalPort(kind, label, status) {
  const statusClass = physicalStatusPillClass(status);
  return `
    <article class="onu-physical-port ${statusClass}">
      <div class="onu-physical-icon-wrap">
        ${renderOnuPhysicalPortIcon(kind, status)}
      </div>
      <div class="onu-physical-copy">
        <strong>${label}</strong>
        <span class="status-pill ${statusClass}">${escapeHtml(status?.label || "Sem leitura")}</span>
        <small>${escapeHtml(status?.detail || "Sem detalhe.")}</small>
        ${status?.source ? `<small>Fonte ${escapeHtml(formatFieldSourceLabel(status.source))}</small>` : ""}
      </div>
    </article>
  `;
}

function renderOnuPhysicalStatusCard(onu) {
  if (!onu) {
    return "";
  }
  const power = getOnuPhysicalStatusEntry(onu, "power");
  const fiber = getOnuPhysicalStatusEntry(onu, "fiber");
  const ethernet = getOnuPhysicalStatusEntry(onu, "ethernet");
  const disconnectReason = getOnuDisconnectReasonEntry(onu);
  const reasonClass = physicalStatusPillClass(disconnectReason);
  return `
    <div class="onu-physical-card">
      <div class="panel-head">
        <strong>Portas fisicas da ONU</strong>
        <span class="muted">Energia, fibra e RJ45 com inferencia da OLT</span>
      </div>
      <div class="onu-physical-reason ${reasonClass}">
        <div class="onu-physical-reason-head">
          <strong>Motivo provavel da desconexao</strong>
          <span class="status-pill ${reasonClass}">${escapeHtml(disconnectReason?.label || "Sem leitura")}</span>
        </div>
        <small>${escapeHtml(disconnectReason?.detail || "Sem detalhe adicional.")}</small>
        ${disconnectReason?.source ? `<small>Fonte ${escapeHtml(formatFieldSourceLabel(disconnectReason.source))}</small>` : ""}
        ${renderOnuPhysicalMeta(onu)}
      </div>
      <div class="onu-physical-grid">
        ${renderOnuPhysicalPort("power", "Energia", power)}
        ${renderOnuPhysicalPort("fiber", "Fibra", fiber)}
        ${renderOnuPhysicalPort("ethernet", "RJ45", ethernet)}
      </div>
    </div>
  `;
}

function renderOnuDetailsPanel() {
  const container = document.getElementById("onuDetailsPanel");
  if (!container) {
    return;
  }
  const canManageOnus = hasPermission("onus_manage");
  const onu = findSelectedOnu();
  if (!onu) {
    container.innerHTML = '<div class="muted">Selecione uma ONU para ver os detalhes.</div>';
    return;
  }

  const zone = `${onu.neighborhood || "Nao informado"} / ${onu.city || "Nao informado"}`;
  const signalRx = formatDbmValue(onu.signal_dbm);
  const signalTx = formatDbmValue(onu.signal_tx_dbm);
  const signalOltRx = formatDbmValue(onu.signal_olt_rx_dbm);
  const temp = onu.temperature_c ? `${onu.temperature_c} C` : "-";
  const statusView = getOnuStatusPresentation(onu);
  const statusText = statusView.label;
  const points = state.onuHistory?.points || [];
  const maxDown = points.length ? Math.max(...points.map((point) => Number(point.traffic_down_mbps || 0))) : 0;
  const maxUp = points.length ? Math.max(...points.map((point) => Number(point.traffic_up_mbps || 0))) : 0;
  const maxSignal = points.length ? Math.max(...points.map((point) => Number(point.signal_dbm || -99))) : null;
  const liveStatus = state.onuLiveStatus[onu.id];
  const actionResult = state.onuActionResult[onu.id];
  const deleteProgress = state.onuDeleteProgress[onu.id];
  const liveMessage =
    liveStatus?.status === "running"
      ? "Coletando dados desta ONU..."
      : liveStatus?.status === "ok"
        ? `Coleta sob demanda: ${formatDateTime(liveStatus.updated_at)}`
        : liveStatus?.status === "warning"
          ? liveStatus.message
        : liveStatus?.status === "error"
          ? `Falha na coleta sob demanda: ${liveStatus.message || ""}`
          : "";
  const actionMessage =
    actionResult?.status === "running"
      ? `Executando ${actionResult.action || "comando"} na OLT...`
      : actionResult?.status === "ok"
        ? `${actionResult.action || "acao"} executada em ${formatDateTime(actionResult.updated_at)}`
        : actionResult?.status === "error"
          ? `Falha na acao ${actionResult.action || ""}: ${actionResult.output || ""}`
          : "";
  const deleteMessage =
    deleteProgress?.status === "running"
      ? `${deleteProgress.stage || "Excluindo ONU..."}`
      : deleteProgress?.status === "ok"
        ? deleteProgress.stage || "ONU excluida com sucesso."
        : deleteProgress?.status === "error"
          ? deleteProgress.details || "Falha ao excluir a ONU."
          : "";
  const liveActive = state.liveMonitorOnuId === onu.id;
  const liveCountdownStatus = getOnuLiveMonitorStatus(onu.id);
  const deleteActive = deleteProgress?.status === "running";
  const liveSeries = getOnuLiveSeries(onu.id);
  const onuMode = getOnuMode(onu);
  const ponAlertThreshold = getPonAlertThresholdMbps(onu);
  const currentPonLoad = Number(onu.traffic_down_mbps || 0) + Number(onu.traffic_up_mbps || 0);
  const ponLoadRatio = ponAlertThreshold > 0 ? currentPonLoad / ponAlertThreshold : 0;
  const ponAlertLevel =
    ponLoadRatio >= 1 ? "critical" : ponLoadRatio >= 0.75 ? "warning" : "ok";
  const downTrend = getTrendDirection(liveSeries, "down_mbps");
  const upTrend = getTrendDirection(liveSeries, "up_mbps");
  const liveChart = buildLiveSparkline(liveSeries);

  container.innerHTML = `
    <div class="onu-notice">This ONU uses ${onu.profile_name || "default"} custom profile.</div>
    ${liveMessage ? `<div class="muted">${liveMessage}</div>` : ""}
    <div class="onu-detail-grid">
      <div class="onu-detail-col">
        <div><strong>OLT</strong><span>${onu.olt_name}</span></div>
        <div><strong>Board</strong><span>${onu.board_slot}</span></div>
        <div><strong>Port</strong><span>${onu.port_name}</span></div>
        <div><strong>ONU</strong><span>${formatOnuPath(onu)}</span></div>
        <div><strong>SN</strong><span>${onu.serial}</span></div>
        <div><strong>ONU type</strong><span>${onu.model || "-"}</span></div>
        <div><strong>Zone</strong><span>${zone}</span></div>
        <div><strong>ODB (Splitter)</strong><span>None</span></div>
        <div><strong>Name</strong><span>${onu.client_name || "-"}</span></div>
        <div><strong>Authorization date</strong><span>${formatDateTime(onu.updated_at)}</span></div>
        <div><strong>ONU external ID</strong><span>${onu.serial}</span></div>
      </div>
      <div class="onu-detail-col">
        <div><strong>Status</strong><span>${statusText}</span></div>
        <div class="onu-signal-refresh-row">
          <strong>Atualizacao do sinal</strong>
          <span class="status-pill ok" data-onu-signal-countdown="${onu.id}">${getOnuSignalRefreshStatus(onu.id).text}</span>
        </div>
        <div><strong>ONU/OLT Rx/Tx signal</strong><span>RX ${signalRx} / TX ${signalTx}</span></div>
        <div><strong>ONU->OLT return signal</strong><span>${signalOltRx}</span></div>
        <div><strong>Temperature</strong><span>${temp}</span></div>
        <div><strong>Attached VLANs</strong><span>${formatVlanValue(onu.vlan_id)}</span></div>
        <div><strong>ONU mode</strong><span>${onuMode === "route" ? "Routing" : "Bridging"} - Main vlan ${formatVlanValue(onu.vlan_id)}</span></div>
        <div><strong>TR069</strong><span>Inactive</span></div>
        <div><strong>Mgmt IP</strong><span>Inactive</span></div>
      </div>
    </div>
    ${renderOnuDataQualityCard(onu)}
    ${renderOnuPhysicalStatusCard(onu)}
    <div class="onu-kpi-grid">
      <article class="onu-kpi-card">
        <h4>Traffic/Signal (PON)</h4>
        <div class="onu-live-meta">
          <span class="status-pill ${ponAlertLevel}">Carga PON ${(ponLoadRatio * 100).toFixed(0)}%</span>
          <span class="status-pill ${liveCountdownStatus.statusClass}" data-onu-live-countdown="${onu.id}">${liveCountdownStatus.text}</span>
          <span class="muted">Limite ${ponAlertThreshold.toFixed(0)} Mbps</span>
          <span class="muted">Download: ${trendLabel(downTrend)} | Upload: ${trendLabel(upTrend)}</span>
        </div>
        <p>Upload atual (PON): ${(onu.traffic_up_mbps || 0).toFixed(2)} Mbps | Max: ${maxUp.toFixed(2)} Mbps</p>
        <p>Download atual (PON): ${(onu.traffic_down_mbps || 0).toFixed(2)} Mbps | Max: ${maxDown.toFixed(2)} Mbps</p>
        <p class="muted">LIVE PON mostra consumo da PON vinculada a esta ONU. Se a ONU estiver offline, a leitura e bloqueada para evitar trafego falso.</p>
        <div class="onu-live-chart-wrap">
          ${liveChart}
          <div class="onu-live-legend">
            <span><i class="dot down"></i>Download</span>
            <span><i class="dot up"></i>Upload</span>
            <span class="muted">Janela de 60s</span>
          </div>
        </div>
        <p>Sinal max historico: ${maxSignal !== null ? `${maxSignal.toFixed(2)} dBm` : "-"}</p>
      </article>
      <article class="onu-kpi-card">
        <h4>Speed profiles</h4>
        <table class="onu-mini-table">
          <thead><tr><th>Service-port ID</th><th>User-VLAN</th><th>Download</th><th>Upload</th></tr></thead>
          <tbody><tr><td>${onu.id}</td><td>${formatVlanValue(onu.vlan_id)}</td><td>1G</td><td>1G</td></tr></tbody>
        </table>
      </article>
    </div>
    <div class="onu-kpi-card">
      <h4>Ethernet ports</h4>
      <table class="onu-mini-table">
        <thead><tr><th>Port</th><th>Admin state</th><th>Mode</th><th>DHCP</th><th>Action</th></tr></thead>
        <tbody>
          <tr><td>eth_0/1</td><td>Enabled</td><td>Access VLAN: ${formatVlanValue(onu.vlan_id)}</td><td>No control</td><td>Configure</td></tr>
          <tr><td>eth_0/2</td><td>Enabled</td><td>Access VLAN: ${formatVlanValue(onu.vlan_id)}</td><td>No control</td><td>Configure</td></tr>
          <tr><td>eth_0/3</td><td>Enabled</td><td>Access VLAN: ${formatVlanValue(onu.vlan_id)}</td><td>No control</td><td>Configure</td></tr>
          <tr><td>eth_0/4</td><td>Enabled</td><td>Access VLAN: ${formatVlanValue(onu.vlan_id)}</td><td>No control</td><td>Configure</td></tr>
        </tbody>
      </table>
      <div class="onu-service-line">VoIP: ${hasVoip(onu) ? "Enabled" : "Disabled"} | IPTV: Inactive | CATV: ${hasTv(onu) ? "Enable" : "Disable"}</div>
      <div class="onu-actions">
        <button type="button" class="primary-button" data-onu-quick-action="refresh-all" ${canManageOnus ? "" : "disabled"}>Atualizar ONU</button>
        <button type="button" class="secondary-button" data-onu-quick-action="status" ${canManageOnus ? "" : "disabled"}>Get status</button>
        <button type="button" class="secondary-button" data-onu-quick-action="running" ${canManageOnus ? "" : "disabled"}>Show running-config</button>
        <button type="button" class="secondary-button" data-onu-quick-action="swinfo" ${canManageOnus ? "" : "disabled"}>SW info</button>
        <button type="button" class="primary-button" data-onu-quick-action="live" ${canManageOnus ? "" : "disabled"}>${liveActive ? "Parar LIVE" : "LIVE PON"}</button>
        <button type="button" class="secondary-button" data-onu-delete-id="${onu.id}" ${deleteActive || !canManageOnus ? "disabled" : ""}>${deleteActive ? "Excluindo..." : "Excluir ONU"}</button>
      </div>
      ${deleteMessage ? renderOnuDeleteProgress(deleteProgress) : ""}
      ${actionMessage ? `<div class="muted">${actionMessage}</div>` : ""}
      ${actionResult?.output ? `
        <div class="onu-command-output">
          <strong>Comando: ${escapeHtml(actionResult.command || "-")}</strong>
          <pre>${escapeHtml(actionResult.output)}</pre>
        </div>
      ` : ""}
    </div>
  `;
  updateOnuSignalAutoRefreshUi();
  syncOnuModalFromPanel();
}

function renderOnuDeleteProgress(progress) {
  if (!progress) {
    return "";
  }
  const statusClass =
    progress.status === "ok" ? "ok" : progress.status === "error" ? "critical" : "warning";
  const steps = Array.isArray(progress.steps) ? progress.steps : [];
  return `
    <div class="onu-delete-progress">
      <div class="panel-head">
        <strong>Progresso da exclusao</strong>
        <span class="status-pill ${statusClass}">${Math.max(0, Number(progress.progress_pct || 0))}%</span>
      </div>
      <div class="muted">${escapeHtml(progress.stage || "")}</div>
      ${progress.details ? `<div class="muted">${escapeHtml(progress.details)}</div>` : ""}
      ${
        steps.length
          ? `<div class="onu-delete-steps">
              ${steps
                .map(
                  (step) => `
                    <div class="onu-delete-step ${step.state || "pending"}">
                      <span class="onu-delete-step-dot"></span>
                      <div>
                        <strong>${escapeHtml(step.label || "")}</strong>
                        ${step.details ? `<div class="muted">${escapeHtml(step.details)}</div>` : ""}
                      </div>
                    </div>
                  `
                )
                .join("")}
            </div>`
          : ""
      }
    </div>
  `;
}

function renderOnuHistory() {
  const select = document.getElementById("onuHistorySelect");
  if (!state.onus.length) {
    select.innerHTML = "";
    document.getElementById("onuHistoryChart").innerHTML =
      '<div class="muted">Nenhuma ONU cadastrada.</div>';
    return;
  }
  select.innerHTML = state.onus
    .map(
      (onu) => `
        <option value="${onu.id}" ${state.selectedOnuId === onu.id ? "selected" : ""}>
          ${onu.client_name} (${onu.serial})
        </option>
      `
    )
    .join("");

  const container = document.getElementById("onuHistoryChart");
  if (!state.onuHistory || !state.onuHistory.points.length) {
    container.innerHTML = '<div class="muted">Sem historico para a ONU selecionada.</div>';
    return;
  }

  container.innerHTML = `
    <div class="panel-head">
      <strong>${state.onuHistory.label}</strong>
      <span class="muted">${state.onuHistory.points.length} coletas</span>
    </div>
    <div class="mini-points">
      ${state.onuHistory.points
        .map(
          (point) => `
            <div class="mini-point">
              <span>${formatTime(point.collected_at)}</span>
              <div class="bar-track slim">
                <div class="bar-fill signal" style="width:${signalPercent(point.signal_dbm)}%"></div>
              </div>
              <small>Sinal ${point.signal_dbm ? `${point.signal_dbm} dBm` : "-"}</small>
              <small>Temp ${point.temperature_c ? `${point.temperature_c} C` : "-"}</small>
              <small>${point.traffic_down_mbps}/${point.traffic_up_mbps} Mbps</small>
            </div>
          `
        )
        .join("")}
    </div>
  `;
}

function renderRequests() {
  const currentOperation = state.requestsOperationStatus;
  const running = currentOperation?.status === "running";
  const autofindButton = document.getElementById("runAutofindAllButton");
  if (autofindButton) {
    autofindButton.disabled = running;
    autofindButton.textContent =
      running && currentOperation?.type === "autofind" ? "Executando..." : "Autofind All";
  }
  const syncProfilesButton = document.getElementById("syncOltProfilesButton");
  if (syncProfilesButton) {
    syncProfilesButton.disabled = running;
    syncProfilesButton.textContent =
      running && currentOperation?.type === "profile-sync" ? "Sincronizando..." : "Sincronizar perfis OLT";
  }
  const statusNode = document.getElementById("requestsStatus");
  if (statusNode) {
    const current = state.requestsOperationStatus;
    if (!current?.message) {
      statusNode.textContent = "";
    } else if (current.updated_at) {
      statusNode.textContent = `${current.message} (${formatDateTime(current.updated_at)})`;
    } else {
      statusNode.textContent = current.message;
    }
  }
  const html = state.requests.length
    ? state.requests.map((request) => renderRequestCard(request)).join("")
    : '<div class="muted">Sem solicitacoes pendentes.</div>';
  document.getElementById("requestsList").innerHTML = html;
  document.querySelectorAll("form[data-request-id]").forEach((form) => {
    syncRequestProvisioningForm(form);
  });
}

const REQUEST_FIXED_PROFILE_OPTIONS = [
  {
    key: "smartolt-flexible",
    label: "SmartOLT Flexible",
    onuMode: "bridge",
    lineNames: ["SMARTOLT_FLEXIBLE_GPON"],
    serviceNames: ["2301"],
  },
  {
    key: "router-huawei",
    label: "Router Huawei",
    onuMode: "route",
    lineNames: ["ONT-ROUTER", "EG8145X6-10-ROUTER"],
    serviceNames: ["EG8145X6-ROUTER", "EG8145X6-10-ROUTER"],
  },
  {
    key: "onu-bridge",
    label: "ONU Bridge",
    onuMode: "bridge",
    lineNames: ["ONU-BRIDGE"],
    serviceNames: ["ONU-BRIDGE"],
  },
  {
    key: "generic-bridge",
    label: "Generic Bridge",
    onuMode: "bridge",
    lineNames: ["GENERIC_BRIDGE", "AN5506-04-F-BRIDGE", "AN5506-BRIDGE-CUSTOM", "AN5506_BRIDGE_BRANCA"],
    serviceNames: ["GENERIC_BRIDGE", "AN5506-04-F-BRIDGE", "AN5506-BRIDGE-CUSTOM", "AN5506_BRIDGE_BRANCA"],
  },
];

function findRequestById(requestId) {
  const normalizedRequestId = Number(requestId);
  return state.requests.find((item) => Number(item.id) === normalizedRequestId) || null;
}

function readRequestDraftValue(draft, key, fallback) {
  return Object.prototype.hasOwnProperty.call(draft || {}, key) ? draft[key] : fallback;
}

function captureRequestFormDraft(form) {
  if (!form) {
    return null;
  }
  const requestId = Number(form.dataset.requestId || 0);
  if (!requestId) {
    return null;
  }
  const profileSelect = form.querySelector("[data-request-profile-select]");
  const selectedModeInput = form.querySelector('input[name="onu_mode"]:checked');
  return {
    requestId,
    onu_mode: selectedModeInput ? selectedModeInput.value : "bridge",
    profile_choice: profileSelect ? profileSelect.value : "",
    vlan_id: form.vlan_id ? form.vlan_id.value : "",
    client_name: form.client_name ? form.client_name.value : "",
    neighborhood: form.neighborhood ? form.neighborhood.value : "",
    city: form.city ? form.city.value : "",
  };
}

function storeRequestDraft(form) {
  const draft = captureRequestFormDraft(form);
  if (!draft) {
    return;
  }
  state.requestDraftsById[draft.requestId] = draft;
}

function normalizeRequestProfileName(value) {
  return String(value || "").trim().toLowerCase();
}

function findRequestOltProfileOption(options, ...preferredNames) {
  const normalizedNames = preferredNames.map((value) => normalizeRequestProfileName(value)).filter(Boolean);
  for (const name of normalizedNames) {
    const matched = (options || []).find((item) => normalizeRequestProfileName(item.name) === name);
    if (matched) {
      return matched;
    }
  }
  return null;
}

function parseRequestFamilyProfile(name) {
  const normalizedName = String(name || "").trim();
  const match = normalizedName.match(/^(.*)_V(\d{1,4})$/i);
  if (!match) {
    return null;
  }
  const base = String(match[1] || "").trim();
  const vlanId = Number(match[2] || 0);
  if (!base || !vlanId) {
    return null;
  }
  return { base, vlanId };
}

function buildRequestFamilyChoices(lineProfiles, serviceProfiles) {
  const serviceByName = new Map(
    (Array.isArray(serviceProfiles) ? serviceProfiles : []).map((item) => [normalizeRequestProfileName(item.name), item])
  );
  const families = new Map();
  (Array.isArray(lineProfiles) ? lineProfiles : []).forEach((lineProfile) => {
    const parsed = parseRequestFamilyProfile(lineProfile.name);
    if (!parsed) {
      return;
    }
    const serviceProfile = serviceByName.get(normalizeRequestProfileName(lineProfile.name));
    if (!serviceProfile) {
      return;
    }
    const familyKey = normalizeRequestProfileName(parsed.base);
    const score = Math.min(
      Number(lineProfile.binding_times || 0) || 0,
      Number(serviceProfile.binding_times || 0) || 0
    );
    const current =
      families.get(familyKey) ||
      {
        key: `family:${parsed.base}`,
        mode: "family",
        onuMode: "bridge",
        label: parsed.base,
        profileName: parsed.base,
        mappings: [],
        vlanDefault: null,
        popularity: -1,
        sortOrder: 2,
      };
    current.mappings.push({
      vlanId: parsed.vlanId,
      lineProfile: lineProfile.name,
      serviceProfile: serviceProfile.name,
      score,
    });
    if (score > current.popularity || current.vlanDefault === null) {
      current.popularity = score;
      current.vlanDefault = parsed.vlanId;
      current.lineProfile = lineProfile.name;
      current.serviceProfile = serviceProfile.name;
    }
    families.set(familyKey, current);
  });
  return Array.from(families.values())
    .map((item) => ({
      ...item,
      mappings: item.mappings.sort((left, right) => left.vlanId - right.vlanId),
      meta: `${item.mappings.length} VLAN${item.mappings.length === 1 ? "" : "s"}`,
    }))
    .sort(
      (left, right) =>
        (right.popularity || 0) - (left.popularity || 0) ||
        String(left.label || "").localeCompare(String(right.label || ""), "pt-BR")
    );
}

function buildRequestFixedChoices(lineProfiles, serviceProfiles) {
  return REQUEST_FIXED_PROFILE_OPTIONS.map((item) => {
    const lineProfile = findRequestOltProfileOption(lineProfiles, ...(item.lineNames || []));
    const serviceProfile = findRequestOltProfileOption(serviceProfiles, ...(item.serviceNames || []));
    if (!lineProfile || !serviceProfile) {
      return null;
    }
    return {
      key: `fixed:${item.key}`,
      mode: "fixed",
      label: item.label,
      profileName: item.label,
      onuMode: normalizeOnuMode(item.onuMode, inferOnuModeFromProfiles(lineProfile.name, serviceProfile.name, "bridge")),
      lineProfile: lineProfile.name,
      serviceProfile: serviceProfile.name,
      vlanDefault: null,
      popularity: Math.min(
        Number(lineProfile.binding_times || 0) || 0,
        Number(serviceProfile.binding_times || 0) || 0
      ),
      sortOrder: 1,
      meta: `${lineProfile.name} + ${serviceProfile.name}`,
    };
  })
    .filter(Boolean)
    .sort(
      (left, right) =>
        (right.popularity || 0) - (left.popularity || 0) ||
        String(left.label || "").localeCompare(String(right.label || ""), "pt-BR")
    );
}

function buildRequestProvisioningChoices(request) {
  const duplicate = request?.existing_onu;
  const globalChoices = (Array.isArray(request?.profiles) ? request.profiles : []).map((profile) => {
    const profileId = Number(profile.id || 0);
    return {
      key: `global:${profileId}`,
      mode: "global",
      label: profile.name || `Profile ${profileId}`,
      profileName: profile.name || `Profile ${profileId}`,
      profileId,
      onuMode: inferOnuModeFromProfiles(profile.line_profile, profile.service_profile, "bridge"),
      onuModel: profile.onu_model || "",
      lineProfile: profile.line_profile || "",
      serviceProfile: profile.service_profile || "",
      vlanDefault: Number(profile.vlan_default || 0) || null,
      popularity: 10000 - profileId,
      sortOrder: 0,
      meta: profile.onu_model ? `modelo ${profile.onu_model}` : "custom profile",
    };
  });
  const duplicateChoice =
    duplicate && (duplicate.line_profile || duplicate.service_profile)
      ? [
          {
            key: "existing:current",
            mode: "fixed",
            label: "Perfil atual",
            profileName: "Perfil atual",
            onuMode: normalizeOnuMode(
              duplicate.onu_mode,
              inferOnuModeFromProfiles(duplicate.line_profile, duplicate.service_profile, "bridge")
            ),
            lineProfile: duplicate.line_profile || "",
            serviceProfile: duplicate.service_profile || "",
            vlanDefault: Number(duplicate.vlan_id || 0) || null,
            popularity: 9500,
            sortOrder: 1,
            meta: "ONU atual",
          },
        ]
      : [];
  const seen = new Set();
  return [
    ...globalChoices,
    ...duplicateChoice,
    ...buildRequestFixedChoices(request?.olt_line_profiles, request?.olt_service_profiles),
    ...buildRequestFamilyChoices(request?.olt_line_profiles, request?.olt_service_profiles),
  ]
    .filter((item) => {
      const signature =
        item.mode === "global"
          ? item.key
          : `${normalizeRequestProfileName(item.lineProfile)}|${normalizeRequestProfileName(item.serviceProfile)}`;
      if (seen.has(signature)) {
        return false;
      }
      seen.add(signature);
      return true;
    })
    .sort(
    (left, right) =>
      (left.sortOrder || 0) - (right.sortOrder || 0) ||
      (right.popularity || 0) - (left.popularity || 0) ||
      String(left.label || "").localeCompare(String(right.label || ""), "pt-BR")
    );
}

function buildRequestProvisioningChoicesForMode(request, onuMode) {
  const normalizedMode = normalizeOnuMode(onuMode, "bridge");
  return buildRequestProvisioningChoices(request).filter(
    (item) => normalizeOnuMode(item.onuMode, "bridge") === normalizedMode
  );
}

function findRequestProvisioningChoice(choices, key) {
  const normalizedKey = String(key || "").trim();
  return (choices || []).find((item) => item.key === normalizedKey) || null;
}

function pickSuggestedRequestProvisioningChoice(request, choices) {
  const rows = Array.isArray(choices) ? choices : [];
  if (!rows.length) {
    return "";
  }
  const duplicate = request?.existing_onu;
  if (duplicate) {
    const normalizedLine = normalizeRequestProfileName(duplicate.line_profile);
    const normalizedService = normalizeRequestProfileName(duplicate.service_profile);
    const directMatch = rows.find(
      (item) =>
        normalizeRequestProfileName(item.lineProfile) === normalizedLine &&
        normalizeRequestProfileName(item.serviceProfile) === normalizedService
    );
    if (directMatch) {
      return directMatch.key;
    }
    const parsedFamily = parseRequestFamilyProfile(duplicate.line_profile);
    if (parsedFamily && normalizedLine === normalizedService) {
      const familyMatch = rows.find(
        (item) =>
          item.mode === "family" && normalizeRequestProfileName(item.profileName) === normalizeRequestProfileName(parsedFamily.base)
      );
      if (familyMatch) {
        return familyMatch.key;
      }
    }
  }
  const modelMatch = rows.find(
    (item) =>
      item.mode === "global" &&
      normalizeRequestProfileName(item.onuModel) === normalizeRequestProfileName(request?.detected_model)
  );
  if (modelMatch) {
    return modelMatch.key;
  }
  return rows[0].key;
}

function renderRequestProvisioningChoiceOptions(choices, selectedKey) {
  const rows = Array.isArray(choices) ? choices : [];
  const normalizedSelectedKey = String(selectedKey || "").trim();
  if (!rows.length) {
    return '<option value="">Sincronize os perfis da OLT</option>';
  }
  return rows
    .map((choice, index) => {
      const selected = normalizedSelectedKey ? choice.key === normalizedSelectedKey : index === 0;
      const meta = choice.meta ? ` - ${choice.meta}` : "";
      return `
        <option value="${escapeHtml(choice.key)}" ${selected ? "selected" : ""}>
          ${escapeHtml(`${choice.label}${meta}`)}
        </option>
      `;
    })
    .join("");
}

function appendRequestVlanCatalogEntry(catalog, vlanId, source = "", name = "", description = "") {
  const numericVlanId = Number(vlanId || 0);
  if (!Number.isFinite(numericVlanId) || numericVlanId < 1 || numericVlanId > 4094) {
    return;
  }
  const normalizedVlanId = Math.trunc(numericVlanId);
  const current =
    catalog.get(normalizedVlanId) || {
      vlan_id: normalizedVlanId,
      name: "",
      description: "",
      sources: new Set(),
    };
  const normalizedName = String(name || "").trim();
  const normalizedDescription = String(description || "").trim();
  const normalizedSource = String(source || "").trim();
  if (normalizedName && !current.name) {
    current.name = normalizedName;
  }
  if (normalizedDescription && !current.description) {
    current.description = normalizedDescription;
  }
  if (normalizedSource) {
    current.sources.add(normalizedSource);
  }
  catalog.set(normalizedVlanId, current);
}

function normalizeRequestVlanCatalog(request) {
  const catalog = new Map();
  const oltRows = Array.isArray(request?.olt_vlans) ? request.olt_vlans : [];
  oltRows.forEach((row) => {
    appendRequestVlanCatalogEntry(
      catalog,
      row?.vlan_id,
      row?.source || "olt",
      row?.name || "",
      row?.description || ""
    );
  });
  const choices = buildRequestProvisioningChoices(request);
  choices.forEach((choice) => {
    appendRequestVlanCatalogEntry(catalog, choice?.vlanDefault, "profile");
    if (choice?.mode === "family") {
      (Array.isArray(choice.mappings) ? choice.mappings : []).forEach((mapping) => {
        appendRequestVlanCatalogEntry(catalog, mapping?.vlanId, "profile");
      });
    }
  });
  appendRequestVlanCatalogEntry(catalog, request?.existing_onu?.vlan_id, "onu");
  return Array.from(catalog.values())
    .map((item) => {
      const sourceLabel = Array.from(item.sources).filter(Boolean).join(", ");
      return {
        vlan_id: item.vlan_id,
        name: item.name,
        description: item.description,
        source: sourceLabel,
      };
    })
    .sort((left, right) => left.vlan_id - right.vlan_id);
}

function buildRequestVlanSelectState(request, selectedVlanValue, fallbackVlanValue = 0) {
  const catalog = normalizeRequestVlanCatalog(request);
  const preferredVlanId = Number(selectedVlanValue || 0) || Number(fallbackVlanValue || 0) || catalog[0]?.vlan_id || 0;
  const hasPreferred = preferredVlanId > 0;
  const hasPreferredInCatalog = catalog.some((item) => item.vlan_id === preferredVlanId);
  const options = [];

  if (hasPreferred && !hasPreferredInCatalog) {
    options.push(`
      <option value="${preferredVlanId}" selected>
        VLAN ${preferredVlanId} (fora do inventario)
      </option>
    `);
  }

  catalog.forEach((item) => {
    const details = [item.name, item.description].filter(Boolean).join(" - ");
    const source = item.source ? ` (${item.source})` : "";
    const label = details ? `VLAN ${item.vlan_id} - ${details}${source}` : `VLAN ${item.vlan_id}${source}`;
    options.push(`
      <option value="${item.vlan_id}" ${item.vlan_id === preferredVlanId ? "selected" : ""}>
        ${escapeHtml(label)}
      </option>
    `);
  });

  if (!options.length) {
    return {
      optionsHtml: '<option value="">Sem VLAN cadastrada para esta OLT</option>',
      disabled: true,
    };
  }

  return {
    optionsHtml: options.join(""),
    disabled: false,
  };
}

function ensureRequestVlanOption(field, vlanValue) {
  if (!field || !field.options) {
    return;
  }
  const normalizedVlan = String(vlanValue || "").trim();
  if (!normalizedVlan) {
    return;
  }
  const exists = Array.from(field.options).some((option) => String(option.value || "").trim() === normalizedVlan);
  if (exists) {
    return;
  }
  const option = document.createElement("option");
  option.value = normalizedVlan;
  option.textContent = `VLAN ${normalizedVlan} (fora do inventario)`;
  field.appendChild(option);
}

function resolveRequestProvisioningChoice(request, selectedKey, vlanValue, onuMode = "bridge") {
  const normalizedMode = normalizeOnuMode(onuMode, "bridge");
  const choices = buildRequestProvisioningChoicesForMode(request, normalizedMode);
  const choice =
    findRequestProvisioningChoice(choices, selectedKey) ||
    findRequestProvisioningChoice(choices, pickSuggestedRequestProvisioningChoice(request, choices)) ||
    choices[0] ||
    null;
  const requestedVlanId = Number(vlanValue || 0) || 0;
  const result = {
    choice,
    choiceKey: choice?.key || "",
    onuMode: normalizedMode,
    profileId: Number(choice?.profileId || 0) || 0,
    profileLabel: choice?.profileName || "Perfil de liberacao",
    requestedVlanId,
    resolvedVlanId: Number(choice?.vlanDefault || 0) || 0,
    suggestedVlanId: Number(choice?.vlanDefault || 0) || 0,
    lineProfile: "",
    serviceProfile: "",
    error: "",
  };
  if (!choice) {
    result.error = `Nenhum perfil de ${normalizedMode === "route" ? "route" : "bridge"} encontrado para esta OLT.`;
    return result;
  }
  if (choice.mode === "family") {
    const mappings = Array.isArray(choice.mappings) ? choice.mappings : [];
    const defaultMapping =
      mappings.find((item) => item.vlanId === Number(choice.vlanDefault || 0)) ||
      mappings[0] ||
      null;
    let mapping = defaultMapping;
    if (requestedVlanId) {
      mapping = mappings.find((item) => item.vlanId === requestedVlanId) || defaultMapping;
      result.resolvedVlanId = requestedVlanId;
    } else {
      result.resolvedVlanId = Number(mapping?.vlanId || 0) || 0;
      result.suggestedVlanId = result.resolvedVlanId;
    }
    if (!mapping) {
      result.error = `Nenhuma combinacao encontrada para ${choice.label}.`;
      return result;
    }
    result.lineProfile = mapping.lineProfile;
    result.serviceProfile = mapping.serviceProfile;
    if (!requestedVlanId) {
      result.resolvedVlanId = Number(mapping.vlanId || 0) || result.resolvedVlanId;
      result.suggestedVlanId = result.resolvedVlanId;
    } else if (!result.suggestedVlanId) {
      result.suggestedVlanId = Number(mapping.vlanId || 0) || 0;
    }
    return result;
  }
  result.lineProfile = String(choice.lineProfile || "").trim();
  result.serviceProfile = String(choice.serviceProfile || "").trim();
  if (!result.lineProfile || !result.serviceProfile) {
    result.error = `${choice.label} ainda nao tem line/service profile resolvidos.`;
  }
  if (!result.resolvedVlanId && requestedVlanId) {
    result.resolvedVlanId = requestedVlanId;
    result.suggestedVlanId = requestedVlanId;
  }
  return result;
}

function buildRequestResolvedProfileSummary(profileLabel, resolution) {
  if (resolution?.error) {
    return resolution.error;
  }
  const normalizedProfile = String(profileLabel || "").trim() || "Perfil de liberacao";
  const normalizedLine = String(resolution?.lineProfile || "").trim();
  const normalizedService = String(resolution?.serviceProfile || "").trim();
  if (resolution?.choice?.mode === "family" && normalizedLine && normalizedService) {
    return `${normalizedProfile} aplica ${normalizedLine} + ${normalizedService}; VLAN pode ser definida manualmente.`;
  }
  if (normalizedLine && normalizedService) {
    return `${normalizedProfile} aplica ${normalizedLine} + ${normalizedService} na OLT.`;
  }
  if (normalizedLine || normalizedService) {
    return `${normalizedProfile} usa ${normalizedLine || "-"} + ${normalizedService || "-"} na OLT.`;
  }
  return "Selecione um perfil de liberacao para continuar.";
}

function renderRequestCard(request) {
  const canManageRequests = hasPermission("requests_manage");
  const canPreviewRequests = hasPermission("requests_view");
  const allChoices = buildRequestProvisioningChoices(request);
  const draft = state.requestDraftsById[request.id] || {};
  const availableModes = {
    bridge: allChoices.some((item) => normalizeOnuMode(item.onuMode, "bridge") === "bridge"),
    route: allChoices.some((item) => normalizeOnuMode(item.onuMode, "bridge") === "route"),
  };
  const defaultOnuMode = normalizeOnuMode(
    readRequestDraftValue(
      draft,
      "onu_mode",
      request.existing_onu?.onu_mode || inferOnuModeFromProfiles(request.existing_onu?.line_profile, request.existing_onu?.service_profile, "bridge")
    ),
    availableModes.bridge ? "bridge" : "route"
  );
  const selectedOnuMode =
    availableModes[defaultOnuMode] ? defaultOnuMode : availableModes.bridge ? "bridge" : availableModes.route ? "route" : defaultOnuMode;
  const choices = buildRequestProvisioningChoicesForMode(request, selectedOnuMode);
  const suggestedChoiceKey = pickSuggestedRequestProvisioningChoice(request, choices);
  const selectedChoiceKey = readRequestDraftValue(draft, "profile_choice", suggestedChoiceKey);
  const initialVlanValue = request.existing_onu ? request.existing_onu.vlan_id : "";
  const draftVlanValue = readRequestDraftValue(draft, "vlan_id", initialVlanValue);
  let selectedResolution = resolveRequestProvisioningChoice(request, selectedChoiceKey, draftVlanValue, selectedOnuMode);
  const renderedVlanValue =
    String(draftVlanValue || "").trim() || String(selectedResolution.suggestedVlanId || selectedResolution.resolvedVlanId || "");
  selectedResolution = resolveRequestProvisioningChoice(request, selectedChoiceKey, renderedVlanValue, selectedOnuMode);
  const vlanSelectState = buildRequestVlanSelectState(
    request,
    renderedVlanValue,
    selectedResolution.suggestedVlanId || selectedResolution.resolvedVlanId || ""
  );
  const profileHelp =
    choices.length
      ? `<div class="muted">Modo ${selectedOnuMode === "route" ? "Route" : "Bridge"} ativo. O app resolve line e service profile automaticamente.</div>`
      : `<div class="muted">Sem perfis de ${selectedOnuMode === "route" ? "route" : "bridge"} resolvidos para esta OLT.</div>`;
  const resolvedProfileSummary = buildRequestResolvedProfileSummary(selectedResolution.profileLabel, selectedResolution);
  const preview = state.requestPreviewsById[request.id];
  const previewLoading = !!state.requestPreviewLoadingById[request.id];
  const authorizeProgress = state.requestAuthorizeProgressById[request.id];
  const authorizeRunning = authorizeProgress?.status === "running";
  const duplicateBlock = request.existing_onu
    ? `
      <div class="request-note">
        <strong>ONU ja cadastrada</strong>
        <div class="muted">${request.existing_onu.client_name} em ${request.existing_onu.olt_name} / ${request.existing_onu.board_slot} / ${request.existing_onu.port_name}</div>
        <div class="muted">Acao sugerida: mover para ${request.olt_name} / ${request.board_slot} / ${request.port_name}</div>
      </div>
    `
    : `
      <div class="request-note">
        <strong>Nova liberacao</strong>
        <div class="muted">Cadastro de cliente e autorizacao na porta detectada.</div>
      </div>
    `;

  return `
    <article class="request-card">
      <div class="panel-head">
        <h3>${request.serial}</h3>
        <span class="status-pill ${request.suggested_action === "move" ? "warning" : "ok"}">${request.suggested_action}</span>
      </div>
      <div class="muted">${request.olt_name} / ${request.board_slot} / ${request.port_name}</div>
      <div class="muted">Modelo ${request.detected_model} - Sinal ${request.requested_signal_dbm} dBm - Temp ${request.requested_temperature_c} C</div>
      <p class="muted">${request.notes || ""}</p>
      ${duplicateBlock}
      ${profileHelp}
      <form data-request-id="${request.id}">
        <div class="request-mode-switch">
          <label class="request-field-label">Modo da ONU</label>
          <div class="request-mode-options">
            <label class="request-mode-option ${selectedOnuMode === "bridge" ? "active" : ""} ${availableModes.bridge ? "" : "disabled"}">
              <input type="radio" name="onu_mode" value="bridge" ${selectedOnuMode === "bridge" ? "checked" : ""} ${availableModes.bridge && canManageRequests ? "" : "disabled"}>
              <span>Bridge</span>
            </label>
            <label class="request-mode-option ${selectedOnuMode === "route" ? "active" : ""} ${availableModes.route ? "" : "disabled"}">
              <input type="radio" name="onu_mode" value="route" ${selectedOnuMode === "route" ? "checked" : ""} ${availableModes.route && canManageRequests ? "" : "disabled"}>
              <span>Route</span>
            </label>
          </div>
        </div>
        <input
          name="client_name"
          placeholder="Nome do cliente"
          value="${escapeHtml(readRequestDraftValue(draft, "client_name", request.existing_onu ? request.existing_onu.client_name : ""))}"
          ${request.existing_onu || !canManageRequests ? "disabled" : ""}
        >
        <div class="inline-two">
          <input
            name="neighborhood"
            placeholder="Bairro"
            value="${escapeHtml(readRequestDraftValue(draft, "neighborhood", ""))}"
            ${request.existing_onu || !canManageRequests ? "disabled" : ""}
          >
          <input
            name="city"
            placeholder="Cidade"
            value="${escapeHtml(readRequestDraftValue(draft, "city", ""))}"
            ${request.existing_onu || !canManageRequests ? "disabled" : ""}
          >
        </div>
        <div class="inline-two">
          <div class="request-field">
            <label class="request-field-label">VLAN</label>
            <select name="vlan_id" ${vlanSelectState.disabled || !canManageRequests ? "disabled" : ""}>
              ${vlanSelectState.optionsHtml}
            </select>
          </div>
          <div class="request-field">
            <label class="request-field-label">Perfil de liberacao</label>
            <select name="profile_choice" data-request-profile-select ${canManageRequests ? "" : "disabled"}>
              ${renderRequestProvisioningChoiceOptions(choices, selectedChoiceKey)}
            </select>
          </div>
        </div>
        <div class="request-profile-summary" data-request-profile-summary>${escapeHtml(resolvedProfileSummary)}</div>
        <div class="request-profile-pairs">
          <article class="request-profile-pair">
            <span>Line profile</span>
            <strong data-request-resolved-line>${escapeHtml(selectedResolution.lineProfile || "-")}</strong>
          </article>
          <article class="request-profile-pair">
            <span>Service profile</span>
            <strong data-request-resolved-service>${escapeHtml(selectedResolution.serviceProfile || "-")}</strong>
          </article>
        </div>
        <div class="request-actions">
          <button type="button" class="secondary-button" data-preview-request-id="${request.id}" ${previewLoading || authorizeRunning || !canPreviewRequests ? "disabled" : ""}>
            ${previewLoading ? "Gerando preview..." : "Preview OLT"}
          </button>
          ${
            canManageRequests
              ? request.suggested_action === "move"
                ? `<button type="button" class="primary-button" data-action="move" data-request-id="${request.id}" ${authorizeRunning ? "disabled" : ""}>Mover ONU</button>`
                : `<button type="button" class="primary-button" data-action="authorize" data-request-id="${request.id}" ${authorizeRunning ? "disabled" : ""}>${authorizeRunning ? "Autorizando..." : "Autorizar ONU"}</button>`
              : '<span class="muted">Somente leitura</span>'
          }
        </div>
        ${renderRequestAuthorizeProgress(authorizeProgress)}
        ${renderRequestPreview(preview)}
      </form>
    </article>
  `;
}

function syncRequestProvisioningForm(form, options = {}) {
  if (!form) {
    return;
  }
  const request = findRequestById(form.dataset.requestId);
  if (!request) {
    return;
  }
  const profileSelect = form.querySelector("[data-request-profile-select]");
  const selectedModeInput = form.querySelector('input[name="onu_mode"]:checked');
  const vlanInput = form.querySelector('[name="vlan_id"]');
  const summaryNode = form.querySelector("[data-request-profile-summary]");
  const lineNode = form.querySelector("[data-request-resolved-line]");
  const serviceNode = form.querySelector("[data-request-resolved-service]");
  const selectedKey = profileSelect?.value || "";
  const selectedOnuMode = selectedModeInput ? selectedModeInput.value : "bridge";
  let currentVlanValue = vlanInput ? vlanInput.value : "";
  ensureRequestVlanOption(vlanInput, currentVlanValue);
  let resolution = resolveRequestProvisioningChoice(request, selectedKey, currentVlanValue, selectedOnuMode);
  const shouldAutofillVlan = vlanInput && !String(currentVlanValue || "").trim();
  if (shouldAutofillVlan && resolution.suggestedVlanId) {
    ensureRequestVlanOption(vlanInput, resolution.suggestedVlanId);
    vlanInput.value = String(resolution.suggestedVlanId);
    currentVlanValue = vlanInput.value;
    resolution = resolveRequestProvisioningChoice(request, selectedKey, currentVlanValue, selectedOnuMode);
  }
  if (summaryNode) {
    summaryNode.textContent = buildRequestResolvedProfileSummary(resolution.profileLabel, resolution);
  }
  if (lineNode) {
    lineNode.textContent = resolution.lineProfile || "-";
  }
  if (serviceNode) {
    serviceNode.textContent = resolution.serviceProfile || "-";
  }
  storeRequestDraft(form);
}

function renderRequestAuthorizeProgress(progress) {
  if (!progress) {
    return "";
  }
  const statusClass =
    progress.status === "ok" ? "ok" : progress.status === "error" ? "critical" : "warning";
  const steps = Array.isArray(progress.steps) ? progress.steps : [];
  return `
    <div class="onu-delete-progress request-progress">
      <div class="panel-head">
        <strong>Progresso da autorizacao</strong>
        <span class="status-pill ${statusClass}">${Math.max(0, Number(progress.progress_pct || 0))}%</span>
      </div>
      <div class="muted">${escapeHtml(progress.stage || "")}</div>
      ${progress.details ? `<div class="muted">${escapeHtml(progress.details)}</div>` : ""}
      ${
        steps.length
          ? `<div class="onu-delete-steps">
              ${steps
                .map(
                  (step) => `
                    <div class="onu-delete-step ${step.state || "pending"}">
                      <span class="onu-delete-step-dot"></span>
                      <div>
                        <strong>${escapeHtml(step.label || "")}</strong>
                        ${step.details ? `<div class="muted">${escapeHtml(step.details)}</div>` : ""}
                      </div>
                    </div>
                  `
                )
                .join("")}
            </div>`
          : ""
      }
    </div>
  `;
}

function renderRequestPreview(preview) {
  if (!preview) {
    return "";
  }
  const warnings = Array.isArray(preview.warnings) ? preview.warnings.filter(Boolean) : [];
  const notes = Array.isArray(preview.notes) ? preview.notes.filter(Boolean) : [];
  const commands = Array.isArray(preview.commands) ? preview.commands : [];
  const commandText = commands
    .map((item, index) => {
      const header = `# ${index + 1}. ${item.step || "Comando"}`;
      return `${header}\n${item.command || ""}`;
    })
    .join("\n\n");
  const template = preview.template || {};
  const templateSummary = preview.supported
    ? `
      <div class="muted">
        Gemport ${template.gemport ?? "-"} / Inbound ${template.inbound_traffic_table ?? "-"} / Outbound ${template.outbound_traffic_table ?? "-"} / Tag ${template.tag_transform ?? "-"} / Fonte ${template.source ?? "-"}
      </div>
    `
    : "";
  return `
    <div class="request-note request-preview">
      <strong>Preview de provisionamento</strong>
      ${preview.context ? `<div class="muted">${preview.context.olt_name} / ${preview.context.board_slot} / ${preview.context.port_name}</div>` : ""}
      ${templateSummary}
      ${warnings.map((item) => `<div class="muted preview-warning">${escapeHtml(item)}</div>`).join("")}
      ${notes.map((item) => `<div class="muted">${escapeHtml(item)}</div>`).join("")}
      ${
        commandText
          ? `<div class="onu-command-output"><pre>${escapeHtml(commandText)}</pre></div>`
          : '<div class="muted">Nenhum comando disponivel para esta solicitacao.</div>'
      }
    </div>
  `;
}

function captureConnectionFormState() {
  const valuesByOltId = {};
  document.querySelectorAll("form[data-connection-olt-id]").forEach((form) => {
    const oltId = String(form.dataset.connectionOltId || "").trim();
    if (!oltId) {
      return;
    }
    const values = {};
    form.querySelectorAll("input[name], select[name], textarea[name]").forEach((field) => {
      const name = String(field.name || "").trim();
      if (!name) {
        return;
      }
      if (field.type === "checkbox") {
        values[name] = Boolean(field.checked);
      } else {
        values[name] = field.value;
      }
    });
    valuesByOltId[oltId] = values;
  });

  let focus = null;
  const active = document.activeElement;
  if (active?.closest && active?.name) {
    const activeForm = active.closest("form[data-connection-olt-id]");
    if (activeForm) {
      focus = {
        oltId: String(activeForm.dataset.connectionOltId || "").trim(),
        name: String(active.name || "").trim(),
      };
      if ("selectionStart" in active && "selectionEnd" in active) {
        focus.selectionStart = active.selectionStart;
        focus.selectionEnd = active.selectionEnd;
      }
    }
  }
  return { valuesByOltId, focus };
}

function restoreConnectionFormState(snapshot) {
  const valuesByOltId = snapshot?.valuesByOltId || {};
  Object.entries(valuesByOltId).forEach(([oltId, values]) => {
    const form = document.querySelector(`form[data-connection-olt-id="${Number(oltId)}"]`);
    if (!form) {
      return;
    }
    const fieldsByName = {};
    form.querySelectorAll("input[name], select[name], textarea[name]").forEach((field) => {
      const name = String(field.name || "").trim();
      if (!name || fieldsByName[name]) {
        return;
      }
      fieldsByName[name] = field;
    });
    Object.entries(values || {}).forEach(([name, value]) => {
      const field = fieldsByName[name];
      if (!field) {
        return;
      }
      if (field.type === "checkbox") {
        field.checked = Boolean(value);
      } else if (typeof value === "string") {
        field.value = value;
      }
    });
  });

  const focus = snapshot?.focus;
  if (!focus?.oltId || !focus?.name) {
    return;
  }
  const form = document.querySelector(`form[data-connection-olt-id="${Number(focus.oltId)}"]`);
  if (!form) {
    return;
  }
  const focusField = Array.from(form.querySelectorAll("input[name], select[name], textarea[name]")).find(
    (field) => String(field.name || "").trim() === focus.name
  );
  if (!focusField || focusField.disabled) {
    return;
  }
  focusField.focus({ preventScroll: true });
  if (
    "selectionStart" in focusField &&
    "selectionEnd" in focusField &&
    Number.isInteger(focus.selectionStart) &&
    Number.isInteger(focus.selectionEnd)
  ) {
    try {
      focusField.setSelectionRange(focus.selectionStart, focus.selectionEnd);
    } catch (_) {
      // Ignora campos que nao aceitam selecao de cursor.
    }
  }
}

function renderConnections() {
  const canManageCollection = hasPermission("collection_manage");
  const formSnapshot = captureConnectionFormState();
  if (!state.connections.length) {
    document.getElementById("connectionsList").innerHTML =
      '<div class="muted">Nenhuma conexao cadastrada. Cadastre uma OLT primeiro.</div>';
    return;
  }
  document.getElementById("connectionsList").innerHTML = state.connections
    .map(
      (connection) => `
        <article class="connection-card">
          <div class="panel-head">
            <div>
              <strong>${connection.olt_name}</strong>
              <div class="muted">${connection.olt_brand} / ${connection.olt_host}</div>
              <div class="muted">Transporte: ${connection.transport_type || "ssh"}:${connection.port || 22}</div>
            </div>
            <span class="status-pill ${connection.last_poll_status === "error" ? "critical" : "ok"}">${connection.last_poll_status || "idle"}</span>
          </div>
          <form data-connection-olt-id="${connection.olt_id}">
            <div class="inline-two">
              <select name="protocol">
                ${["native", "mock", "json-file", "command", "api"]
                  .map(
                    (protocol) => `
                      <option value="${protocol}" ${connection.protocol === protocol ? "selected" : ""}>
                        ${protocol}
                      </option>
                    `
                  )
                  .join("")}
              </select>
              <input name="host_info" value="${connection.olt_host}" disabled>
            </div>
            <div class="inline-two">
              <select name="collector_profile">
                ${[
                  { value: "auto", label: "Perfil CLI: Auto" },
                  { value: "huawei_ma5800", label: "Perfil CLI: Huawei MA5800" },
                  { value: "huawei_ma56xx", label: "Perfil CLI: Huawei MA56xx" },
                ]
                  .map(
                    (item) => `
                      <option value="${item.value}" ${(connection.extra_config?.collector_profile || "auto") === item.value ? "selected" : ""}>
                        ${item.label}
                      </option>
                    `
                  )
                  .join("")}
              </select>
              <input
                name="collector_profile_detected"
                value="Detectado: ${connection.extra_config?.collector_profile_detected || "-"}"
                disabled
              >
            </div>
            <div class="inline-two">
              <input name="username" placeholder="Usuario" value="${connection.username || ""}">
              <div class="password-field">
                <input type="password" name="password" placeholder="Senha ou token curto" value="${connection.password || ""}">
                <button type="button" class="secondary-button toggle-password" data-password-target="connection-${connection.olt_id}">Mostrar</button>
              </div>
            </div>
            <div class="inline-two">
              <input name="api_base_url" placeholder="API URL" value="${connection.api_base_url || ""}">
              <input name="api_token" placeholder="API token" value="${connection.api_token || ""}">
            </div>
            <div class="inline-two">
              <input name="source_path" placeholder="Arquivo JSON local" value="${connection.source_path || ""}">
              <input name="command_line" placeholder="Comando que retorna JSON" value="${connection.command_line || ""}">
            </div>
            <div class="inline-two">
              <input name="port" type="number" placeholder="Porta" value="${connection.port || 22}">
              <input name="poll_interval_sec" type="number" placeholder="Intervalo" value="${connection.poll_interval_sec || 300}">
            </div>
            <div class="inline-two">
              <input name="command_timeout_sec" type="number" placeholder="Timeout" value="${connection.command_timeout_sec || 20}">
              <label class="checkbox-row">
                <input type="checkbox" name="enabled" ${connection.enabled ? "checked" : ""}>
                Coleta habilitada
              </label>
            </div>
            <div class="inline-two">
              <label class="checkbox-row">
                <input type="checkbox" name="fast_poll_enabled" ${(connection.extra_config?.fast_poll_enabled ?? true) ? "checked" : ""}>
                Coleta rapida (sem inventario completo todo poll)
              </label>
              <input name="full_inventory_interval_sec" type="number" placeholder="Intervalo inventario completo (s)" value="${connection.extra_config?.full_inventory_interval_sec || 1800}">
            </div>
            <div class="inline-two">
              <select name="snmp_version">
                ${["2c", "1"]
                  .map(
                    (version) => `
                      <option value="${version}" ${(connection.extra_config?.snmp_version || "2c") === version ? "selected" : ""}>
                        SNMP v${version}
                      </option>
                    `
                  )
                  .join("")}
              </select>
              <input
                name="snmp_read_community"
                placeholder="SNMP community leitura"
                value="${connection.extra_config?.snmp_read_community || connection.extra_config?.snmp_community || ""}"
              >
            </div>
            <div class="inline-two">
              <input
                name="snmp_write_community"
                placeholder="SNMP community escrita"
                value="${connection.extra_config?.snmp_write_community || ""}"
              >
              <input name="snmp_port" type="number" placeholder="SNMP porta" value="${connection.extra_config?.snmp_port || 161}">
            </div>
            <div class="inline-two">
              <input name="snmp_timeout_sec" type="number" placeholder="SNMP timeout (s)" value="${connection.extra_config?.snmp_timeout_sec || 4}">
              <input name="snmp_retries" type="number" placeholder="SNMP retries" value="${connection.extra_config?.snmp_retries || 2}">
            </div>
            <div class="inline-two">
              <input name="snmp_max_rows" type="number" placeholder="SNMP max rows" value="${connection.extra_config?.snmp_max_rows || 8192}">
              <input name="snmp_bulk_repetitions" type="number" placeholder="SNMP bulk reps" value="${connection.extra_config?.snmp_bulk_repetitions || 25}">
            </div>
            <div class="inline-two">
              <label class="checkbox-row">
                <input type="checkbox" name="snmp_fast_mode" ${(connection.extra_config?.snmp_fast_mode ?? true) ? "checked" : ""}>
                SNMP rapido (pula OIDs pesados)
              </label>
            </div>
            <div class="inline-two">
              <label class="checkbox-row">
                <input type="checkbox" name="snmp_use_cached_serial_index" ${(connection.extra_config?.snmp_use_cached_serial_index ?? true) ? "checked" : ""}>
                Cache indice serial SNMP
              </label>
              <label class="checkbox-row">
                <input type="checkbox" name="fast_partial_onu_updates" ${(connection.extra_config?.fast_partial_onu_updates ?? true) ? "checked" : ""}>
                Atualizar apenas ONUs com metrica nova
              </label>
            </div>
            <div class="inline-two">
              <input name="snmp_serial_oid" placeholder="SNMP OID serial" value="${connection.extra_config?.snmp_serial_oid || ""}">
              <input name="snmp_signal_oid" placeholder="SNMP OID sinal" value="${connection.extra_config?.snmp_signal_oid || ""}">
            </div>
            <div class="inline-two">
              <input name="snmp_signal_tx_oid" placeholder="SNMP OID sinal TX" value="${connection.extra_config?.snmp_signal_tx_oid || "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.3"}">
              <input name="snmp_signal_olt_rx_oid" placeholder="SNMP OID retorno ONU->OLT" value="${connection.extra_config?.snmp_signal_olt_rx_oid || "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.6"}">
            </div>
            <div class="inline-two">
              <input name="snmp_temperature_oid" placeholder="SNMP OID temperatura" value="${connection.extra_config?.snmp_temperature_oid || ""}">
              <input name="snmp_status_oid" placeholder="SNMP OID status ONU" value="${connection.extra_config?.snmp_status_oid || ""}">
            </div>
            <div class="inline-two">
              <input name="snmp_distance_oid" placeholder="SNMP OID distancia ONU" value="${connection.extra_config?.snmp_distance_oid || ""}">
              <input name="snmp_vlan_oid" placeholder="SNMP OID VLAN ONU" value="${connection.extra_config?.snmp_vlan_oid || ""}">
            </div>
            <div class="inline-two">
              <input name="snmp_port_status_oid" placeholder="SNMP OID status porta GPON" value="${connection.extra_config?.snmp_port_status_oid || ""}">
              <input name="snmp_port_count_oid" placeholder="SNMP OID qtd ONUs da porta" value="${connection.extra_config?.snmp_port_count_oid || ""}">
            </div>
            <div class="inline-two">
              <input name="snmp_parallel_walks" type="number" placeholder="SNMP paralelismo" value="${connection.extra_config?.snmp_parallel_walks || 2}">
              <input name="snmp_ifname_oid" placeholder="SNMP OID ifName/ifDescr" value="${connection.extra_config?.snmp_ifname_oid || "1.3.6.1.2.1.31.1.1.1.1"}">
            </div>
            <div class="inline-two">
              <input name="snmp_traffic_down_oid" placeholder="SNMP OID trafego down (ifInOctets)" value="${connection.extra_config?.snmp_traffic_down_oid || "1.3.6.1.2.1.2.2.1.10"}">
              <input name="snmp_traffic_up_oid" placeholder="SNMP OID trafego up (ifOutOctets)" value="${connection.extra_config?.snmp_traffic_up_oid || "1.3.6.1.2.1.2.2.1.16"}">
            </div>
            <div class="inline-two">
              <input name="snmp_live_alert_mbps" type="number" placeholder="Limite LIVE PON (Mbps)" value="${connection.extra_config?.snmp_live_alert_mbps || 200}">
              <div></div>
            </div>
            <div class="inline-two">
              <input name="snmp_signal_multiplier" type="number" step="0.01" placeholder="Sinal multiplicador" value="${connection.extra_config?.snmp_signal_multiplier || 1}">
              <input name="snmp_signal_offset" type="number" step="0.01" placeholder="Sinal offset" value="${connection.extra_config?.snmp_signal_offset || 0}">
            </div>
            <div class="inline-two">
              <input name="snmp_temperature_multiplier" type="number" step="0.01" placeholder="Temp multiplicador" value="${connection.extra_config?.snmp_temperature_multiplier || 1}">
              <input name="snmp_temperature_offset" type="number" step="0.01" placeholder="Temp offset" value="${connection.extra_config?.snmp_temperature_offset || 0}">
            </div>
            <div class="muted">Ultimo poll: ${connection.last_poll_at ? formatDateTime(connection.last_poll_at) : "nunca"}</div>
            <div class="muted">${connection.last_error || "Sem erro registrado."}</div>
            <div class="muted">Ultima conexao: ${connection.last_connect_at ? formatDateTime(connection.last_connect_at) : "nunca"}</div>
            <div class="muted">${connection.last_connect_message || "Sem teste de conexao."}</div>
            ${renderConnectionProgress(connection.olt_id)}
            <div class="request-actions">
              <button type="button" class="secondary-button" data-connection-action="save" data-connection-olt-id="${connection.olt_id}" ${canManageCollection ? "" : "disabled"}>Salvar conexao</button>
              <button type="button" class="secondary-button" data-connection-action="apply-template" data-connection-olt-id="${connection.olt_id}" ${canManageCollection ? "" : "disabled"}>Aplicar template agora</button>
              <button type="button" class="secondary-button" data-connection-action="apply-template-merge" data-connection-olt-id="${connection.olt_id}" ${canManageCollection ? "" : "disabled"}>Aplicar sem sobrescrever</button>
              <button type="button" class="primary-button" data-connection-action="poll" data-connection-olt-id="${connection.olt_id}" ${canManageCollection ? "" : "disabled"}>Executar poll</button>
            </div>
          </form>
        </article>
      `
    )
    .join("");
  restoreConnectionFormState(formSnapshot);
  if (canManageCollection) {
    unlockSnmpFields();
    return;
  }
  document
    .querySelectorAll("form[data-connection-olt-id] input, form[data-connection-olt-id] select, form[data-connection-olt-id] button")
    .forEach((field) => {
      field.disabled = true;
    });
}

function unlockSnmpFields() {
  document
    .querySelectorAll(
      'form[data-connection-olt-id] input[name^="snmp_"], form[data-connection-olt-id] select[name^="snmp_"]'
    )
    .forEach((field) => {
      field.disabled = false;
      field.readOnly = false;
    });
}

function renderConnectionProgress(oltId) {
  const progress = state.pollProgress[oltId];
  if (!progress) {
    return "";
  }
  const pct = Number(progress.progress_pct || 0);
  const statusClass =
    progress.status === "ok" ? "ok" : progress.status === "error" ? "critical" : "warning";
  return `
    <div class="poll-progress-wrap">
      <div class="panel-head">
        <strong>Coleta</strong>
        <span class="status-pill ${statusClass}">${pct}%</span>
      </div>
      <div class="progress-track">
        <div class="progress-fill" style="width:${Math.max(0, Math.min(100, pct))}%"></div>
      </div>
      ${renderCoverageSummary(progress.coverage, "poll-progress-coverage")}
      <div class="muted">${progress.stage || "Coletando..."}</div>
      ${progress.details ? `<div class="muted">${escapeHtml(progress.details)}</div>` : ""}
    </div>
  `;
}

function renderConnectionTemplates() {
  const container = document.getElementById("connectionTemplatesList");
  if (!container) {
    return;
  }
  const canManageCollection = hasPermission("collection_manage");
  const rows = Array.isArray(state.connectionTemplates) ? state.connectionTemplates : [];
  const newTemplate = {
    id: "new",
    brand: "",
    model: "",
    firmware: "",
    defaults: {
      protocol: "native",
      transport_type: "ssh",
      username: "",
      password: "",
      api_base_url: "",
      api_token: "",
      source_path: "",
      command_line: "",
      port: 22,
      poll_interval_sec: 300,
      command_timeout_sec: 20,
      enabled: true,
      verify_tls: false,
      status: "online",
      board_model: "GPON",
      board_slots: "0/1",
      ports_per_board: 4,
      capacity_onu: 128,
    },
    extra_config: {
      collector_profile: "auto",
      snmp_version: "2c",
      snmp_read_community: "",
      snmp_write_community: "",
      snmp_port: 161,
      snmp_serial_oid: "1.3.6.1.4.1.2011.6.128.1.1.2.43.1.3",
      snmp_signal_oid: "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.4",
      snmp_signal_tx_oid: "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.3",
      snmp_signal_olt_rx_oid: "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.6",
      snmp_temperature_oid: "",
      snmp_status_oid: "",
      snmp_vlan_oid: "",
      snmp_traffic_down_oid: "1.3.6.1.2.1.2.2.1.10",
      snmp_traffic_up_oid: "1.3.6.1.2.1.2.2.1.16",
      snmp_ifname_oid: "1.3.6.1.2.1.31.1.1.1.1",
      snmp_live_alert_mbps: 200,
      command_overrides: {
        ont_summary: "",
        service_port: "",
        vlan_inventory: "",
      },
    },
  };
  const cards = [newTemplate, ...rows];
  container.innerHTML = cards
    .map((tpl) => {
      const extra = tpl.extra_config || {};
      const defaults = tpl.defaults || {};
      const isNew = String(tpl.id) === "new";
      return `
        <article class="connection-card">
          <form data-template-id="${tpl.id}">
            <div class="inline-two">
              <input name="brand" placeholder="Marca" value="${tpl.brand || ""}">
              <input name="model" placeholder="Modelo" value="${tpl.model || ""}">
            </div>
            <div class="inline-two">
              <input name="firmware" placeholder="Firmware" value="${tpl.firmware || ""}">
              <select name="transport_type">
                ${["ssh", "telnet", "api"]
                  .map(
                    (value) => `
                      <option value="${value}" ${(defaults.transport_type || "ssh") === value ? "selected" : ""}>
                        Transporte: ${value.toUpperCase()}
                      </option>
                    `
                  )
                  .join("")}
              </select>
            </div>
            <div class="inline-two">
              <input name="username" placeholder="Usuario padrao" value="${defaults.username || ""}">
              <div class="password-field">
                <input type="password" name="password" placeholder="Senha padrao" value="${defaults.password || ""}">
                <button type="button" class="secondary-button toggle-password" data-password-target="template-${tpl.id}">Mostrar</button>
              </div>
            </div>
            <div class="inline-three">
              <input name="port" type="number" placeholder="Porta padrao" value="${defaults.port || 22}">
              <input name="poll_interval_sec" type="number" placeholder="Poll (s)" value="${defaults.poll_interval_sec || 300}">
              <input name="command_timeout_sec" type="number" placeholder="Timeout (s)" value="${defaults.command_timeout_sec || 20}">
            </div>
            <div class="inline-two">
              <input name="board_model" placeholder="Modelo da placa" value="${defaults.board_model || "GPON"}">
              <input name="board_slots" placeholder="Slots da placa" value="${defaults.board_slots || "0/1"}">
            </div>
            <div class="inline-three">
              <input name="ports_per_board" type="number" placeholder="Portas por placa" value="${defaults.ports_per_board || 4}">
              <input name="capacity_onu" type="number" placeholder="Capacidade ONU" value="${defaults.capacity_onu || 128}">
              <select name="status">
                ${["online", "warning", "offline"]
                  .map(
                    (value) => `
                      <option value="${value}" ${(defaults.status || "online") === value ? "selected" : ""}>
                        Status: ${value}
                      </option>
                    `
                  )
                  .join("")}
              </select>
            </div>
            <div class="inline-two">
              <input
                name="snmp_read_community"
                placeholder="SNMP community leitura"
                value="${extra.snmp_read_community || extra.snmp_community || ""}"
              >
              <input
                name="snmp_write_community"
                placeholder="SNMP community escrita"
                value="${extra.snmp_write_community || ""}"
              >
            </div>
            <div class="inline-two">
              <select name="collector_profile">
                ${[
                  { value: "auto", label: "Perfil CLI: Auto" },
                  { value: "huawei_ma5800", label: "Perfil CLI: Huawei MA5800" },
                  { value: "huawei_ma56xx", label: "Perfil CLI: Huawei MA56xx" },
                ]
                  .map(
                    (item) => `
                    <option value="${item.value}" ${(extra.collector_profile || "auto") === item.value ? "selected" : ""}>
                      ${item.label}
                    </option>
                  `
                  )
                  .join("")}
              </select>
              <input name="api_base_url" placeholder="API URL padrao" value="${defaults.api_base_url || ""}">
            </div>
            <div class="inline-two">
              <input name="api_token" placeholder="API token padrao" value="${defaults.api_token || ""}">
              <input name="source_path" placeholder="Arquivo padrao" value="${defaults.source_path || ""}">
            </div>
            <div class="inline-two">
              <input name="command_line" placeholder="Comando padrao" value="${defaults.command_line || ""}">
              <select name="protocol">
                ${["native", "api", "json-file", "command", "mock"]
                  .map(
                    (value) => `
                      <option value="${value}" ${(defaults.protocol || "native") === value ? "selected" : ""}>
                        Protocolo: ${value}
                      </option>
                    `
                  )
                  .join("")}
              </select>
            </div>
            <div class="inline-two">
              <label class="checkbox-row">
                <input type="checkbox" name="enabled" ${defaults.enabled ?? true ? "checked" : ""}>
                Coleta habilitada
              </label>
              <label class="checkbox-row">
                <input type="checkbox" name="verify_tls" ${defaults.verify_tls ? "checked" : ""}>
                Verificar TLS
              </label>
            </div>
            <div class="inline-two">
              <input
                name="command_ont_summary"
                placeholder="Comando ont summary"
                value="${extra.command_overrides?.ont_summary || ""}"
              >
              <input
                name="command_service_port"
                placeholder="Comando service-port"
                value="${extra.command_overrides?.service_port || ""}"
              >
            </div>
            <div class="inline-two">
              <input
                name="command_vlan_inventory"
                placeholder="Comando inventario VLAN"
                value="${extra.command_overrides?.vlan_inventory || ""}"
              >
              <input
                name="telnet_command_timeout_sec"
                type="number"
                placeholder="Timeout telnet (s)"
                value="${extra.telnet_command_timeout_sec || 45}"
              >
            </div>
            <div class="inline-three">
              <input name="snmp_port" type="number" placeholder="SNMP porta" value="${extra.snmp_port || 161}">
              <select name="snmp_version">
                ${["2c", "1"]
                  .map(
                    (version) => `
                    <option value="${version}" ${(extra.snmp_version || "2c") === version ? "selected" : ""}>SNMP v${version}</option>
                  `
                  )
                  .join("")}
              </select>
              <input name="snmp_ifname_oid" placeholder="OID ifName/ifDescr" value="${extra.snmp_ifname_oid || ""}">
            </div>
            <div class="inline-two">
              <input name="snmp_serial_oid" placeholder="OID serial ONU" value="${extra.snmp_serial_oid || ""}">
              <input name="snmp_signal_oid" placeholder="OID sinal RX ONU" value="${extra.snmp_signal_oid || ""}">
            </div>
            <div class="inline-two">
              <input name="snmp_signal_tx_oid" placeholder="OID sinal TX ONU" value="${extra.snmp_signal_tx_oid || ""}">
              <input name="snmp_signal_olt_rx_oid" placeholder="OID RX da OLT" value="${extra.snmp_signal_olt_rx_oid || ""}">
            </div>
            <div class="inline-two">
              <input name="snmp_temperature_oid" placeholder="OID temperatura ONU" value="${extra.snmp_temperature_oid || ""}">
              <input name="snmp_status_oid" placeholder="OID status ONU" value="${extra.snmp_status_oid || ""}">
            </div>
            <div class="inline-two">
              <input name="snmp_vlan_oid" placeholder="OID VLAN ONU" value="${extra.snmp_vlan_oid || ""}">
              <input name="snmp_live_alert_mbps" type="number" placeholder="Limite LIVE (Mbps)" value="${extra.snmp_live_alert_mbps || 200}">
            </div>
            <div class="inline-two">
              <input name="snmp_traffic_down_oid" placeholder="OID down (ifInOctets)" value="${extra.snmp_traffic_down_oid || ""}">
              <input name="snmp_traffic_up_oid" placeholder="OID up (ifOutOctets)" value="${extra.snmp_traffic_up_oid || ""}">
            </div>
            <div class="request-actions">
              <button type="button" class="secondary-button" data-template-action="save" data-template-id="${tpl.id}" ${canManageCollection ? "" : "disabled"}>
                ${isNew ? "Criar template" : "Salvar template"}
              </button>
              ${
                isNew
                  ? ""
                  : `<button type="button" class="secondary-button" data-template-action="delete" data-template-id="${tpl.id}" ${canManageCollection ? "" : "disabled"}>Excluir</button>`
              }
            </div>
          </form>
        </article>
      `;
    })
    .join("");
  if (!canManageCollection) {
    container.querySelectorAll("input, select, button").forEach((field) => {
      field.disabled = true;
    });
  }
}

function renderEvents() {
  document.getElementById("eventsList").innerHTML = state.events.length
    ? state.events
        .map(
          (event) => {
            const coverage = extractCoverageSummary(event.details);
            return `
            <article class="alert-card">
              <div class="panel-head">
                <strong>${event.olt_name}</strong>
                <span class="status-pill ${event.level === "error" ? "critical" : event.level === "warning" ? "warning" : "ok"}">${event.level}</span>
              </div>
              <div>${event.message}</div>
              ${renderCoverageSummary(coverage)}
              <div class="muted">${formatDateTime(event.created_at)}</div>
            </article>
          `;
          }
        )
        .join("")
    : '<div class="muted">Sem eventos de coleta.</div>';
}

function renderUserPermissionCheckboxes(selectedPermissions = {}) {
  const catalog = Array.isArray(state.permissionCatalog) ? state.permissionCatalog : [];
  if (!catalog.length) {
    return '<div class="muted">Sem permissoes disponiveis.</div>';
  }
  return catalog
    .map((item) => {
      const key = String(item?.key || "").trim();
      if (!key) {
        return "";
      }
      const checked = Boolean(selectedPermissions?.[key]);
      return `
        <label class="checkbox-row">
          <input type="checkbox" data-permission-key="${escapeHtml(key)}" ${checked ? "checked" : ""}>
          ${escapeHtml(item?.label || key)}
        </label>
      `;
    })
    .join("");
}

function syncUserFormAdminState(form) {
  if (!form) {
    return;
  }
  const adminInput = form.querySelector("[name='is_admin']");
  const isAdmin = Boolean(adminInput?.checked);
  form.querySelectorAll("[data-permission-key]").forEach((input) => {
    if (isAdmin) {
      input.checked = true;
      input.disabled = true;
      return;
    }
    input.disabled = false;
  });
}

function getUserPermissionPresets() {
  const catalogKeys = new Set(
    (Array.isArray(state.permissionCatalog) ? state.permissionCatalog : [])
      .map((item) => String(item?.key || "").trim())
      .filter(Boolean)
  );
  return USER_PERMISSION_PRESETS.map((preset) => {
    const mappedPermissions = Array.isArray(preset.permissions) ? preset.permissions : [];
    const permissions = catalogKeys.size
      ? mappedPermissions.filter((key) => catalogKeys.has(key))
      : mappedPermissions.slice();
    return {
      ...preset,
      permissions: [...new Set(permissions)],
    };
  });
}

function renderCreateUserPresetActions() {
  const container = document.getElementById("createUserPresetActions");
  if (!container) {
    return;
  }
  const presets = getUserPermissionPresets();
  container.innerHTML = presets
    .map(
      (preset) => `
        <button
          type="button"
          class="secondary-button"
          data-user-preset-key="${escapeHtml(preset.key)}"
          title="${escapeHtml(preset.description || "")}"
        >
          ${escapeHtml(preset.label)}
        </button>
      `
    )
    .join("");
}

function applyUserPresetToForm(form, presetKey) {
  if (!form) {
    return;
  }
  const normalizedKey = String(presetKey || "").trim();
  const preset = getUserPermissionPresets().find((item) => item.key === normalizedKey);
  if (!preset) {
    throw new Error("Perfil rapido invalido.");
  }
  const selectedPermissions = new Set(Array.isArray(preset.permissions) ? preset.permissions : []);
  form.querySelectorAll("[data-permission-key]").forEach((input) => {
    const key = input.dataset.permissionKey;
    input.checked = selectedPermissions.has(key);
  });
  const adminInput = form.querySelector("[name='is_admin']");
  if (adminInput) {
    adminInput.checked = Boolean(preset.is_admin);
  }
  syncUserFormAdminState(form);
}

function renderUsers() {
  const usersListNode = document.getElementById("usersList");
  const createForm = document.getElementById("createUserForm");
  const summaryNode = document.getElementById("usersSummary");
  if (!usersListNode || !createForm || !summaryNode) {
    return;
  }

  renderUserPermissionInputs(
    createForm,
    state.permissionCatalog,
    collectPermissionsFromForm(createForm)
  );
  renderCreateUserPresetActions();
  syncUserFormAdminState(createForm);

  const canViewUsers = hasPermission("users_view");
  const canManageUsers = hasPermission("users_manage");
  createForm.classList.toggle("hidden", !canManageUsers);

  if (!canViewUsers) {
    summaryNode.textContent = "Acesso restrito";
    summaryNode.style.color = "";
    usersListNode.innerHTML = '<div class="muted">Sem permissao para visualizar usuarios.</div>';
    return;
  }

  const usersBaseSummary = `${state.users.length} usuario(s)`;
  if (state.usersFeedback?.message) {
    summaryNode.textContent = `${usersBaseSummary} - ${state.usersFeedback.message}`;
    summaryNode.style.color = state.usersFeedback.isError ? "#9f3f35" : "var(--ok)";
  } else {
    summaryNode.textContent = usersBaseSummary;
    summaryNode.style.color = "";
  }
  if (!state.users.length) {
    usersListNode.innerHTML = '<div class="muted">Nenhum usuario cadastrado.</div>';
    return;
  }

  usersListNode.innerHTML = state.users
    .map((user) => {
      const isCurrent = Number(user.id) === Number(state.auth?.user?.id);
      return `
        <article class="user-card">
          <div class="user-card-head">
            <strong>${escapeHtml(user.display_name || user.username)}</strong>
            <span class="status-pill ${user.is_active ? "ok" : "warning"}">${user.is_active ? "ativo" : "inativo"}</span>
          </div>
          <div class="muted">Login: ${escapeHtml(user.username)}${isCurrent ? " (voce)" : ""}</div>
          <div class="muted">Ultimo login: ${user.last_login_at ? escapeHtml(formatDateTime(user.last_login_at)) : "-"}</div>
          <form class="stack-list" data-user-id="${user.id}">
            <div class="inline-three">
              <input name="username" class="search" value="${escapeHtml(user.username)}" placeholder="Login">
              <input name="display_name" class="search" value="${escapeHtml(user.display_name || "")}" placeholder="Nome de exibicao">
              <input name="password" type="password" class="search" placeholder="Nova senha (opcional)">
            </div>
            <div class="inline-two">
              <label class="checkbox-row">
                <input type="checkbox" name="is_active" ${user.is_active ? "checked" : ""}>
                Usuario ativo
              </label>
              <label class="checkbox-row">
                <input type="checkbox" name="is_admin" ${user.is_admin ? "checked" : ""}>
                Administrador
              </label>
            </div>
            <div class="user-permission-grid" data-permission-container>
              ${renderUserPermissionCheckboxes(user.permissions || {})}
            </div>
            <div class="request-actions">
              <button type="button" class="secondary-button" data-user-action="save" data-user-id="${user.id}" ${
                canManageUsers ? "" : "disabled"
              }>
                Salvar usuario
              </button>
              <button type="button" class="secondary-button" data-user-action="delete" data-user-id="${user.id}" ${
                isCurrent || !canManageUsers ? "disabled" : ""
              }>
                Excluir
              </button>
            </div>
          </form>
        </article>
      `;
    })
    .join("");

  document.querySelectorAll("form[data-user-id]").forEach((form) => {
    syncUserFormAdminState(form);
    if (!canManageUsers) {
      form.querySelectorAll("input, select, button").forEach((node) => {
        node.disabled = true;
      });
    }
  });
}

async function createUser() {
  requirePermission("users_manage", "Sem permissao para criar usuarios.");
  const form = document.getElementById("createUserForm");
  if (!form) {
    return;
  }
  const body = {
    username: form.username.value.trim(),
    display_name: form.display_name.value.trim(),
    password: form.password.value,
    is_admin: Boolean(form.is_admin.checked),
    is_active: true,
    permissions: collectPermissionsFromForm(form),
  };
  const result = await fetchJson("/api/users", {
    method: "POST",
    body: JSON.stringify(body),
  });
  if (Array.isArray(result?.permission_catalog) && result.permission_catalog.length) {
    state.permissionCatalog = result.permission_catalog;
  }
  form.reset();
  renderUserPermissionInputs(form, state.permissionCatalog, {});
  syncUserFormAdminState(form);
  await loadData();
  setUsersFeedback("Usuario criado com sucesso.");
}

function isSamePermissionSet(left, right) {
  const keys = new Set([...Object.keys(left || {}), ...Object.keys(right || {})]);
  for (const key of keys) {
    if (Boolean(left?.[key]) !== Boolean(right?.[key])) {
      return false;
    }
  }
  return true;
}

function buildUserUpdateSuccessMessage(previousUser, payload) {
  if (!previousUser) {
    return payload?.password ? "Senha atualizada com sucesso." : "Cadastro atualizado com sucesso.";
  }
  const changedFields = [];
  if (String(payload?.display_name || "") !== String(previousUser.display_name || "")) {
    changedFields.push("nome");
  }
  if (String(payload?.username || "") !== String(previousUser.username || "")) {
    changedFields.push("login");
  }
  if (String(payload?.password || "") !== "") {
    changedFields.push("senha");
  }
  if (Boolean(payload?.is_active) !== Boolean(previousUser.is_active)) {
    changedFields.push("status");
  }
  if (Boolean(payload?.is_admin) !== Boolean(previousUser.is_admin)) {
    changedFields.push("perfil");
  }
  if (!isSamePermissionSet(payload?.permissions || {}, previousUser.permissions || {})) {
    changedFields.push("permissoes");
  }
  if (changedFields.length === 1) {
    const field = changedFields[0];
    if (field === "senha") {
      return "Senha atualizada com sucesso.";
    }
    if (field === "nome") {
      return "Nome atualizado com sucesso.";
    }
    if (field === "login") {
      return "Login atualizado com sucesso.";
    }
    if (field === "status") {
      return "Status do usuario atualizado com sucesso.";
    }
    if (field === "perfil") {
      return "Perfil do usuario atualizado com sucesso.";
    }
    if (field === "permissoes") {
      return "Permissoes atualizadas com sucesso.";
    }
  }
  if (!changedFields.length) {
    return "Cadastro atualizado com sucesso.";
  }
  return `Cadastro atualizado com sucesso (${changedFields.join(", ")}).`;
}

async function updateUser(userId) {
  requirePermission("users_manage", "Sem permissao para editar usuarios.");
  const form = document.querySelector(`form[data-user-id="${Number(userId)}"]`);
  if (!form) {
    return;
  }
  const previousUser = state.users.find((item) => Number(item.id) === Number(userId)) || null;
  const body = {
    username: form.username.value.trim(),
    display_name: form.display_name.value.trim(),
    password: form.password.value,
    is_admin: Boolean(form.is_admin.checked),
    is_active: Boolean(form.is_active.checked),
    permissions: collectPermissionsFromForm(form),
  };
  const result = await fetchJson(`/api/users/${Number(userId)}`, {
    method: "PUT",
    body: JSON.stringify(body),
  });
  if (Array.isArray(result?.permission_catalog) && result.permission_catalog.length) {
    state.permissionCatalog = result.permission_catalog;
  }
  await loadData();
  setUsersFeedback(buildUserUpdateSuccessMessage(previousUser, body));
}

async function deleteUser(userId) {
  requirePermission("users_manage", "Sem permissao para excluir usuarios.");
  const normalized = Number(userId);
  if (!normalized) {
    return;
  }
  const confirmed = window.confirm("Excluir este usuario?");
  if (!confirmed) {
    return;
  }
  await fetchJson(`/api/users/${normalized}`, { method: "DELETE" });
  await loadData();
  setUsersFeedback("Usuario excluido com sucesso.");
}

function buildRequestFormPayload(requestId) {
  const form = document.querySelector(`form[data-request-id="${requestId}"]`);
  const request = findRequestById(requestId);
  if (!form || !request) {
    throw new Error("Formulario da solicitacao nao encontrado.");
  }
  const profileSelect = form.querySelector("[data-request-profile-select]");
  const selectedModeInput = form.querySelector('input[name="onu_mode"]:checked');
  const selectedOnuMode = selectedModeInput ? selectedModeInput.value : "bridge";
  const resolution = resolveRequestProvisioningChoice(
    request,
    profileSelect ? profileSelect.value : "",
    form.vlan_id ? form.vlan_id.value : "",
    selectedOnuMode
  );
  if (resolution.error) {
    throw new Error(resolution.error);
  }
  return {
    profile_id: Number(resolution.profileId || 0),
    onu_mode: normalizeOnuMode(selectedOnuMode, "bridge"),
    vlan_id: Number(form.vlan_id?.value || resolution.resolvedVlanId || 0),
    line_profile: resolution.lineProfile || "",
    service_profile: resolution.serviceProfile || "",
    client_name: form.client_name ? form.client_name.value : "",
    neighborhood: form.neighborhood ? form.neighborhood.value : "",
    city: form.city ? form.city.value : "",
  };
}

async function processRequest(requestId, action) {
  requirePermission("requests_manage", "Sem permissao para executar solicitacoes.");
  const normalizedRequestId = Number(requestId);
  const body = buildRequestFormPayload(normalizedRequestId);
  if (action === "authorize") {
    await runRequestAuthorizationOperation(normalizedRequestId, body);
    return;
  }
  await fetchJson(`/api/authorization-requests/${normalizedRequestId}/${action}`, {
    method: "POST",
    body: JSON.stringify(body),
  });
  await loadData();
}

async function runRequestAuthorizationOperation(requestId, body) {
  requirePermission("requests_manage", "Sem permissao para autorizar solicitacoes.");
  const normalizedRequestId = Number(requestId);
  state.requestAuthorizeProgressById[normalizedRequestId] = {
    status: "running",
    progress_pct: 1,
    stage: "Enfileirando autorizacao...",
    details: "",
    steps: [],
    updated_at: new Date().toISOString(),
  };
  state.requestsOperationStatus = {
    type: "authorize",
    status: "running",
    message: `Autorizando solicitacao ${normalizedRequestId} na OLT...`,
    updated_at: new Date().toISOString(),
  };
  renderRequests();
  try {
    await fetchJson(`/api/authorization-requests/${normalizedRequestId}/authorize`, {
      method: "POST",
      body: JSON.stringify(body),
    });
    const progress = await monitorRequestAuthorizationProgress(normalizedRequestId);
    state.requestsOperationStatus = {
      type: "authorize",
      status: "ok",
      message: `Autorizacao concluida para a solicitacao ${normalizedRequestId}.`,
      updated_at: progress.updated_at || new Date().toISOString(),
    };
    await loadData();
  } catch (error) {
    state.requestsOperationStatus = {
      type: "authorize",
      status: "error",
      message: `Falha na autorizacao: ${error.message}`,
      updated_at: new Date().toISOString(),
    };
    renderRequests();
    throw error;
  }
}

async function monitorRequestAuthorizationProgress(requestId) {
  const normalizedRequestId = Number(requestId);
  for (;;) {
    const progress = await fetchJson(`/api/authorization-requests/${normalizedRequestId}/progress`);
    state.requestAuthorizeProgressById[normalizedRequestId] = progress;
    renderRequests();
    if (progress.status === "ok") {
      return progress;
    }
    if (progress.status === "error") {
      throw new Error(progress.details || progress.stage || "Falha ao autorizar ONU.");
    }
    await sleep(700);
  }
}

async function previewRequestProvisioning(requestId) {
  requirePermission("requests_view", "Sem permissao para visualizar preview.");
  const body = buildRequestFormPayload(requestId);
  state.requestPreviewLoadingById[requestId] = true;
  renderRequests();
  try {
    const result = await fetchJson(`/api/authorization-requests/${requestId}/preview`, {
      method: "POST",
      body: JSON.stringify(body),
    });
    state.requestPreviewsById[requestId] = result;
    return result;
  } finally {
    delete state.requestPreviewLoadingById[requestId];
    renderRequests();
  }
}

async function runAutofindAllRequests() {
  requirePermission("requests_manage", "Sem permissao para executar autofind.");
  state.requestsOperationStatus = {
    type: "autofind",
    status: "running",
    message: "Executando autofind all nas OLTs habilitadas...",
    updated_at: new Date().toISOString(),
  };
  renderRequests();
  try {
    const result = await fetchJson("/api/authorization-requests/autofind-all", {
      method: "POST",
      body: "{}",
    });
    state.requestsOperationStatus = {
      type: "autofind",
      status: result.olts_error ? "warning" : "ok",
      message: `Autofind concluido: ${result.requests_found || 0} solicitacoes detectadas em ${result.olts_ok || 0} OLT(s)${
        result.olts_error ? `, com ${result.olts_error} falha(s)` : ""
      }.`,
      updated_at: result.updated_at || new Date().toISOString(),
    };
    await loadData();
    return result;
  } catch (error) {
    state.requestsOperationStatus = {
      type: "autofind",
      status: "error",
      message: `Falha no autofind all: ${error.message}`,
      updated_at: new Date().toISOString(),
    };
    renderRequests();
    throw error;
  }
}

async function syncOltProfilesForRequests() {
  requirePermission("requests_manage", "Sem permissao para sincronizar perfis.");
  state.requestsOperationStatus = {
    type: "profile-sync",
    status: "running",
    message: "Sincronizando line profile e service profile das OLTs habilitadas...",
    updated_at: new Date().toISOString(),
  };
  renderRequests();
  try {
    const result = await fetchJson("/api/authorization-requests/sync-olt-profiles", {
      method: "POST",
      body: "{}",
    });
    state.requestsOperationStatus = {
      type: "profile-sync",
      status: result.olts_error ? "warning" : "ok",
      message: `Perfis sincronizados: ${result.line_profiles || 0} line e ${result.service_profiles || 0} service em ${
        result.olts_ok || 0
      } OLT(s)${result.olts_error ? `, com ${result.olts_error} falha(s)` : ""}.`,
      updated_at: result.updated_at || new Date().toISOString(),
    };
    await loadData();
    return result;
  } catch (error) {
    state.requestsOperationStatus = {
      type: "profile-sync",
      status: "error",
      message: `Falha na sincronizacao de perfis: ${error.message}`,
      updated_at: new Date().toISOString(),
    };
    renderRequests();
    throw error;
  }
}

async function saveConnection(oltId) {
  requirePermission("collection_manage", "Sem permissao para editar conexoes.");
  const form = document.querySelector(`form[data-connection-olt-id="${oltId}"]`);
  const read = (name) => form.querySelector(`[name="${name}"]`);
  const currentConnection = state.connections.find((item) => item.olt_id === oltId) || {};
  const extraConfig = { ...(currentConnection.extra_config || {}) };
  extraConfig.collector_profile = read("collector_profile").value || "auto";
  extraConfig.snmp_version = read("snmp_version").value;
  extraConfig.fast_poll_enabled = read("fast_poll_enabled").checked;
  extraConfig.full_inventory_interval_sec = Number(read("full_inventory_interval_sec").value || 1800);
  extraConfig.snmp_read_community = read("snmp_read_community").value;
  extraConfig.snmp_write_community = read("snmp_write_community").value;
  extraConfig.snmp_community = extraConfig.snmp_read_community;
  extraConfig.snmp_port = Number(read("snmp_port").value || 161);
  extraConfig.snmp_serial_oid = read("snmp_serial_oid").value;
  extraConfig.snmp_signal_oid = read("snmp_signal_oid").value;
  extraConfig.snmp_signal_tx_oid = read("snmp_signal_tx_oid").value;
  extraConfig.snmp_signal_olt_rx_oid = read("snmp_signal_olt_rx_oid").value;
  extraConfig.snmp_temperature_oid = read("snmp_temperature_oid").value;
  extraConfig.snmp_status_oid = read("snmp_status_oid").value;
  extraConfig.snmp_distance_oid = read("snmp_distance_oid").value;
  extraConfig.snmp_vlan_oid = read("snmp_vlan_oid").value;
  extraConfig.snmp_port_status_oid = read("snmp_port_status_oid").value;
  extraConfig.snmp_port_count_oid = read("snmp_port_count_oid").value;
  extraConfig.snmp_traffic_down_oid = read("snmp_traffic_down_oid").value;
  extraConfig.snmp_traffic_up_oid = read("snmp_traffic_up_oid").value;
  extraConfig.snmp_ifname_oid = read("snmp_ifname_oid").value;
  extraConfig.snmp_live_alert_mbps = Number(read("snmp_live_alert_mbps").value || 200);
  extraConfig.snmp_parallel_walks = Number(read("snmp_parallel_walks").value || 2);
  extraConfig.snmp_timeout_sec = Number(read("snmp_timeout_sec").value || 4);
  extraConfig.snmp_retries = Number(read("snmp_retries").value || 2);
  extraConfig.snmp_max_rows = Number(read("snmp_max_rows").value || 8192);
  extraConfig.snmp_bulk_repetitions = Number(read("snmp_bulk_repetitions").value || 25);
  extraConfig.snmp_fast_mode = read("snmp_fast_mode").checked;
  extraConfig.snmp_use_cached_serial_index = read("snmp_use_cached_serial_index").checked;
  extraConfig.fast_partial_onu_updates = read("fast_partial_onu_updates").checked;
  extraConfig.snmp_signal_multiplier = Number(read("snmp_signal_multiplier").value || 1);
  extraConfig.snmp_signal_offset = Number(read("snmp_signal_offset").value || 0);
  extraConfig.snmp_temperature_multiplier = Number(read("snmp_temperature_multiplier").value || 1);
  extraConfig.snmp_temperature_offset = Number(read("snmp_temperature_offset").value || 0);

  const body = {
    protocol: form.protocol.value,
    username: form.username.value,
    password: form.password.value,
    api_base_url: form.api_base_url.value,
    api_token: form.api_token.value,
    source_path: form.source_path.value,
    command_line: form.command_line.value,
    port: Number(form.port.value),
    poll_interval_sec: Number(form.poll_interval_sec.value),
    command_timeout_sec: Number(form.command_timeout_sec.value),
    enabled: form.enabled.checked,
    extra_config: extraConfig,
  };
  await fetchJson(`/api/connections/${oltId}`, {
    method: "POST",
    body: JSON.stringify(body),
  });
  await loadData();
}

async function applyConnectionTemplateNow(oltId) {
  requirePermission("collection_manage", "Sem permissao para aplicar template.");
  await fetchJson(`/api/connections/${oltId}/apply-template`, {
    method: "POST",
    body: JSON.stringify({ overwrite: true }),
  });
  await loadData();
}

async function applyConnectionTemplateMerge(oltId) {
  requirePermission("collection_manage", "Sem permissao para aplicar template.");
  await fetchJson(`/api/connections/${oltId}/apply-template`, {
    method: "POST",
    body: JSON.stringify({ overwrite: false }),
  });
  await loadData();
}

async function saveConnectionTemplate(templateId) {
  requirePermission("collection_manage", "Sem permissao para editar templates de conexao.");
  const form = document.querySelector(`form[data-template-id="${templateId}"]`);
  if (!form) {
    return;
  }
  const read = (name) => form.querySelector(`[name="${name}"]`);
  const value = (name) => String(read(name)?.value || "").trim();
  const commandOverrides = {
    ont_summary: value("command_ont_summary"),
    service_port: value("command_service_port"),
    vlan_inventory: value("command_vlan_inventory"),
  };
  const body = {
    id: String(templateId) === "new" ? null : Number(templateId),
    brand: value("brand"),
    model: value("model"),
    firmware: value("firmware"),
    defaults: {
      protocol: value("protocol") || "native",
      transport_type: value("transport_type") || "ssh",
      username: value("username"),
      password: value("password"),
      api_base_url: value("api_base_url"),
      api_token: value("api_token"),
      source_path: value("source_path"),
      command_line: value("command_line"),
      port: Number(value("port") || 22),
      poll_interval_sec: Number(value("poll_interval_sec") || 300),
      command_timeout_sec: Number(value("command_timeout_sec") || 20),
      enabled: Boolean(read("enabled")?.checked),
      verify_tls: Boolean(read("verify_tls")?.checked),
      status: value("status") || "online",
      board_model: value("board_model") || "GPON",
      board_slots: value("board_slots") || "0/1",
      ports_per_board: Number(value("ports_per_board") || 4),
      capacity_onu: Number(value("capacity_onu") || 128),
    },
    extra_config: {
      collector_profile: value("collector_profile") || "auto",
      command_overrides: commandOverrides,
      telnet_command_timeout_sec: Number(value("telnet_command_timeout_sec") || 45),
      snmp_version: value("snmp_version") || "2c",
      snmp_read_community: value("snmp_read_community"),
      snmp_write_community: value("snmp_write_community"),
      snmp_community: value("snmp_read_community"),
      snmp_port: Number(value("snmp_port") || 161),
      snmp_ifname_oid: value("snmp_ifname_oid"),
      snmp_serial_oid: value("snmp_serial_oid"),
      snmp_signal_oid: value("snmp_signal_oid"),
      snmp_signal_tx_oid: value("snmp_signal_tx_oid"),
      snmp_signal_olt_rx_oid: value("snmp_signal_olt_rx_oid"),
      snmp_temperature_oid: value("snmp_temperature_oid"),
      snmp_status_oid: value("snmp_status_oid"),
      snmp_vlan_oid: value("snmp_vlan_oid"),
      snmp_traffic_down_oid: value("snmp_traffic_down_oid"),
      snmp_traffic_up_oid: value("snmp_traffic_up_oid"),
      snmp_live_alert_mbps: Number(value("snmp_live_alert_mbps") || 200),
    },
  };
  await fetchJson("/api/connection-templates", {
    method: "POST",
    body: JSON.stringify(body),
  });
  await loadData();
}

async function deleteConnectionTemplate(templateId) {
  requirePermission("collection_manage", "Sem permissao para excluir templates.");
  const normalized = Number(templateId);
  if (!normalized) {
    return;
  }
  const confirmed = window.confirm("Excluir este template de OLT?");
  if (!confirmed) {
    return;
  }
  await fetchJson(`/api/connection-templates/${normalized}`, {
    method: "DELETE",
  });
  await loadData();
}

async function createOlt() {
  requirePermission("olts_manage", "Sem permissao para criar OLT.");
  const form = document.getElementById("createOltForm");
  const body = {
    name: form.name.value.trim(),
    host: form.host.value.trim(),
    brand: form.brand.value.trim(),
    model: form.model.value.trim(),
    username: form.username.value.trim(),
    password: form.password.value,
    transport_type: form.transport_type.value,
    port: Number(form.port.value),
    firmware: form.firmware.value.trim(),
    board_model: form.board_model.value.trim(),
    board_slots: form.board_slots.value.trim(),
    ports_per_board: Number(form.ports_per_board.value),
    capacity_onu: Number(form.capacity_onu.value),
    status: form.status.value.trim(),
  };
  const result = await fetchJson("/api/olts", {
    method: "POST",
    body: JSON.stringify(body),
  });
  clearOltForm(false);
  state.activeOltId = result.olt_id || null;
  await loadData();
}

async function updateOlt() {
  requirePermission("olts_manage", "Sem permissao para editar OLT.");
  const form = document.getElementById("createOltForm");
  const oltId = Number(form.editing_olt_id.value || state.activeOltId);
  if (!oltId) {
    throw new Error("Selecione uma OLT para editar.");
  }
  const body = {
    name: form.name.value.trim(),
    host: form.host.value.trim(),
    brand: form.brand.value.trim(),
    model: form.model.value.trim(),
    username: form.username.value.trim(),
    password: form.password.value,
    transport_type: form.transport_type.value,
    port: Number(form.port.value),
    firmware: form.firmware.value.trim(),
    board_model: form.board_model.value.trim(),
    board_slots: form.board_slots.value.trim(),
    ports_per_board: Number(form.ports_per_board.value),
    capacity_onu: Number(form.capacity_onu.value),
    status: form.status.value.trim(),
  };
  const result = await fetchJson(`/api/olts/${oltId}`, {
    method: "PUT",
    body: JSON.stringify(body),
  });
  state.activeOltId = result.olt_id || oltId;
  await loadData();
}

async function deleteOlt(oltId) {
  requirePermission("olts_manage", "Sem permissao para excluir OLT.");
  await fetchJson(`/api/olts/${oltId}`, { method: "DELETE" });
  if (state.activeOltId === oltId) {
    state.activeOltId = null;
  }
  await loadData();
}

async function addOltVlan() {
  requirePermission("olts_manage", "Sem permissao para adicionar VLAN.");
  const oltId = Number(state.activeOltId);
  if (!oltId) {
    throw new Error("Selecione uma OLT para adicionar VLAN.");
  }
  const form = document.getElementById("addOltVlanForm");
  const body = {
    vlan_id: Number(form.vlan_id.value),
    name: form.name.value,
    description: form.description.value,
    source: "manual",
  };
  await fetchJson(`/api/olts/${oltId}/vlans`, {
    method: "POST",
    body: JSON.stringify(body),
  });
  form.reset();
  await refreshOltVlans();
  renderOltVlans();
}

async function saveOltVlan(vlanId, name, description) {
  requirePermission("olts_manage", "Sem permissao para editar VLAN.");
  const oltId = Number(state.activeOltId);
  if (!oltId) {
    throw new Error("Selecione uma OLT para salvar VLAN.");
  }
  await fetchJson(`/api/olts/${oltId}/vlans`, {
    method: "POST",
    body: JSON.stringify({
      vlan_id: Number(vlanId),
      name: name || "",
      description: description || "",
      source: "manual",
    }),
  });
  await refreshOltVlans();
  renderOltVlans();
}

async function deleteOltVlan(vlanId) {
  requirePermission("olts_manage", "Sem permissao para remover VLAN.");
  const oltId = Number(state.activeOltId);
  if (!oltId) {
    throw new Error("Selecione uma OLT para remover VLAN.");
  }
  await fetchJson(`/api/olts/${oltId}/vlans/${Number(vlanId)}`, { method: "DELETE" });
  await refreshOltVlans();
  renderOltVlans();
}

async function deleteOnu(onuId) {
  requirePermission("onus_manage", "Sem permissao para excluir ONU.");
  const normalizedOnuId = Number(onuId);
  let removedOnlyLocally = false;
  try {
    await runOnuDeleteOperation(normalizedOnuId, true);
  } catch (error) {
    const confirmedLocalOnly = window.confirm(
      `Falha ao desprovisionar na OLT: ${error.message}\n\nDeseja remover somente do sistema local?`
    );
    if (!confirmedLocalOnly) {
      state.onuDeleteProgress[normalizedOnuId] = {
        status: "error",
        progress_pct: 100,
        stage: "Falha na exclusao da ONU",
        details: error.message,
        steps: [],
        updated_at: new Date().toISOString(),
      };
      if (state.selectedOnuId === normalizedOnuId) {
        renderOnuDetailsPanel();
      }
      throw error;
    }
    await runOnuDeleteOperation(normalizedOnuId, false);
    removedOnlyLocally = true;
  }
  if (state.liveMonitorOnuId === Number(onuId)) {
    stopOnuLiveMonitor();
  }
  if (Number(state.selectedOnuId) === Number(onuId)) {
    state.selectedOnuId = null;
    closeOnuModal();
  }
  await loadData();
  if (removedOnlyLocally) {
    alert("ONU removida apenas do sistema local. A remocao na OLT nao foi concluida.");
    return;
  }
  alert("ONU excluida com sucesso.");
}

async function runOnuDeleteOperation(onuId, live) {
  const normalizedOnuId = Number(onuId);
  state.onuDeleteProgress[normalizedOnuId] = {
    status: "running",
    progress_pct: 1,
    stage: live ? "Iniciando exclusao na OLT..." : "Iniciando remocao local...",
    details: "",
    steps: [],
    updated_at: new Date().toISOString(),
  };
  if (state.selectedOnuId === normalizedOnuId) {
    renderOnuDetailsPanel();
  }

  await fetchJson(`/api/onus/${normalizedOnuId}/delete`, {
    method: "POST",
    body: JSON.stringify({ live }),
  });
  return monitorOnuDeleteProgress(normalizedOnuId);
}

async function monitorOnuDeleteProgress(onuId) {
  const normalizedOnuId = Number(onuId);
  for (;;) {
    const progress = await fetchJson(`/api/onus/${normalizedOnuId}/delete-progress`);
    state.onuDeleteProgress[normalizedOnuId] = progress;
    if (state.selectedOnuId === normalizedOnuId) {
      renderOnuDetailsPanel();
    }
    if (progress.status === "ok") {
      return progress;
    }
    if (progress.status === "error") {
      throw new Error(progress.details || progress.stage || "Falha ao excluir ONU.");
    }
    await sleep(700);
  }
}

async function connectOlt() {
  requirePermission("collection_manage", "Sem permissao para conectar/coletar OLT.");
  const form = document.getElementById("createOltForm");
  const oltId = Number(form.editing_olt_id.value || state.activeOltId);
  if (!oltId) {
    throw new Error("Cadastre ou selecione uma OLT antes de conectar.");
  }
  setOltConnectStatus("warning", "Testando conexao com a OLT...");
  await updateOlt();
  const result = await fetchJson(`/api/olts/${oltId}/connect-test`, {
    method: "POST",
    body: "{}",
  });
  if (result.status !== "connected") {
    const message = result.message || "Falha ao conectar com a OLT.";
    setOltConnectStatus("critical", message);
    throw new Error(message);
  }
  setOltConnectStatus("ok", `${result.message}. Iniciando coleta...`);
  let pollMessage = "Coleta iniciada.";
  try {
    const pollTriggerPromise = fetchJson(`/api/olts/${oltId}/poll`, {
      method: "POST",
      body: "{}",
    });
    const pollResult = await monitorPollProgress(oltId, pollTriggerPromise);
    pollMessage = `Coleta concluida em ${formatDateTime(
      pollResult.collected_at || pollResult.updated_at || new Date().toISOString()
    )}.`;
  } catch (error) {
    setOltConnectStatus("critical", `Conectado, mas a coleta falhou: ${error.message}`);
    throw error;
  }
  setOltConnectStatus("ok", `${result.message}. ${pollMessage}`);
  await loadData();
}

async function pollOlt(oltId) {
  requirePermission("collection_manage", "Sem permissao para executar poll.");
  const pollTriggerPromise = fetchJson(`/api/olts/${oltId}/poll`, {
    method: "POST",
    body: "{}",
  });
  const result = await monitorPollProgress(oltId, pollTriggerPromise);
  document.getElementById("lastSync").textContent = `Ultima coleta manual: ${formatDateTime(
    result.collected_at || result.updated_at || new Date().toISOString()
  )}`;
  await loadData();
}

function mergeOnuInState(onuData) {
  const onuId = Number(onuData?.id);
  if (!onuId) {
    return;
  }
  const index = state.onus.findIndex((item) => item.id === onuId);
  if (index === -1) {
    return;
  }
  state.onus[index] = { ...state.onus[index], ...onuData };
}

function mergeOnuPhysicalStatusInState(onuId, physicalStatus) {
  const normalizedOnuId = Number(onuId);
  if (!normalizedOnuId || !physicalStatus || typeof physicalStatus !== "object") {
    return;
  }
  state.onuPhysicalStatusByOnuId[normalizedOnuId] = {
    ...(state.onuPhysicalStatusByOnuId[normalizedOnuId] || {}),
    ...physicalStatus,
  };
}

async function collectOnuLive(
  onuId,
  fields = ["signal", "signal_tx", "signal_olt_rx", "temperature", "vlan", "status", "profile"]
) {
  requirePermission("onus_manage", "Sem permissao para coletar dados LIVE da ONU.");
  const normalizedOnuId = Number(onuId);
  if (!normalizedOnuId) {
    return null;
  }
  state.onuLiveStatus[normalizedOnuId] = { status: "running", updated_at: new Date().toISOString() };
  try {
    const result = await fetchJson(`/api/onus/${normalizedOnuId}/collect`, {
      method: "POST",
      body: JSON.stringify({ fields }),
    });
    if (result?.physical_status) {
      mergeOnuPhysicalStatusInState(normalizedOnuId, result.physical_status);
    }
    if (result?.onu) {
      mergeOnuInState(result.onu);
      resetOnuSignalAutoRefreshCountdown(normalizedOnuId);
      if (state.selectedOnuId === normalizedOnuId) {
        await refreshOnuHistory();
        renderOnuTable();
        renderOnuDetailsPanel();
        renderOnuHistory();
      }
    }
    state.onuLiveStatus[normalizedOnuId] = {
      status: "ok",
      updated_fields: result?.updated_fields || [],
      skipped_fields: result?.skipped_fields || {},
      updated_at: new Date().toISOString(),
    };
    return result;
  } catch (error) {
    const unsupportedOnDemand =
      String(error.message || "").toLowerCase().includes("rota nao encontrada") ||
      String(error.message || "").toLowerCase().includes("not found");
    if (unsupportedOnDemand) {
      state.onuLiveStatus[normalizedOnuId] = {
        status: "warning",
        message: "Backend sem suporte a coleta sob demanda. Reinicie o servidor atualizado.",
        updated_at: new Date().toISOString(),
      };
      if (state.selectedOnuId === normalizedOnuId) {
        renderOnuDetailsPanel();
      }
      return null;
    }
    state.onuLiveStatus[normalizedOnuId] = {
      status: "error",
      message: error.message,
      updated_at: new Date().toISOString(),
    };
    throw error;
  }
}

async function executeOnuQuickAction(onuId, action, options = {}) {
  requirePermission("onus_manage", "Sem permissao para executar acao na ONU.");
  const normalizedOnuId = Number(onuId);
  if (!normalizedOnuId) {
    return null;
  }
  const background = Boolean(options.background);
  if (!background) {
    state.onuActionResult[normalizedOnuId] = {
      status: "running",
      action,
      updated_at: new Date().toISOString(),
      output: "",
      command: "",
    };
    if (state.selectedOnuId === normalizedOnuId) {
      renderOnuDetailsPanel();
    }
  }
  try {
    const result = await fetchJson(`/api/onus/${normalizedOnuId}/actions/${action}`, {
      method: "POST",
      body: "{}",
    });
    if (result?.physical_status) {
      mergeOnuPhysicalStatusInState(normalizedOnuId, result.physical_status);
    }
    if (action === "live") {
      const parsedFromOutput = parseLiveTrafficFromOutput(result?.output);
      const downValue =
        result?.traffic?.down_mbps ??
        result?.onu?.traffic_down_mbps ??
        parsedFromOutput.down_mbps;
      const upValue =
        result?.traffic?.up_mbps ??
        result?.onu?.traffic_up_mbps ??
        parsedFromOutput.up_mbps;
      appendOnuLiveSample(
        normalizedOnuId,
        downValue,
        upValue,
        result.updated_at || new Date().toISOString()
      );
    }
    if (result?.onu) {
      mergeOnuInState(result.onu);
      if (state.selectedOnuId === normalizedOnuId) {
        await refreshOnuHistory();
        renderOnuTable();
        renderOnuHistory();
      }
    }
    state.onuActionResult[normalizedOnuId] = {
      status: "ok",
      action: result?.action || action,
      updated_at: result?.updated_at || new Date().toISOString(),
      output: result?.output || "",
      command: result?.command || "",
    };
    if (state.selectedOnuId === normalizedOnuId) {
      renderOnuDetailsPanel();
    }
    return result;
  } catch (error) {
    state.onuActionResult[normalizedOnuId] = {
      status: "error",
      action,
      updated_at: new Date().toISOString(),
      output: error.message || "",
      command: "",
    };
    if (state.selectedOnuId === normalizedOnuId) {
      renderOnuDetailsPanel();
    }
    throw error;
  }
}

function stopOnuLiveMonitor() {
  if (state.liveMonitorTimerId) {
    clearTimeout(state.liveMonitorTimerId);
    state.liveMonitorTimerId = null;
  }
  state.liveMonitorRunToken += 1;
  state.liveMonitorInFlight = false;
  state.liveMonitorNextRunAtMs = null;
  state.liveMonitorOnuId = null;
  updateOnuLiveMonitorUi();
}

function scheduleOnuLiveMonitorTick(onuId, runToken, delayMs = ONU_LIVE_MONITOR_INTERVAL_MS) {
  const normalizedOnuId = Number(onuId);
  const normalizedToken = Number(runToken);
  if (!normalizedOnuId || state.liveMonitorOnuId !== normalizedOnuId || state.liveMonitorRunToken !== normalizedToken) {
    return;
  }
  if (state.liveMonitorTimerId) {
    clearTimeout(state.liveMonitorTimerId);
    state.liveMonitorTimerId = null;
  }
  const nextDelay = Number.isFinite(Number(delayMs))
    ? Math.max(500, Number(delayMs))
    : ONU_LIVE_MONITOR_INTERVAL_MS;
  state.liveMonitorNextRunAtMs = Date.now() + nextDelay;
  updateOnuLiveMonitorUi();
  state.liveMonitorTimerId = setTimeout(() => {
    runOnuLiveMonitorCycle(normalizedOnuId, normalizedToken);
  }, nextDelay);
}

async function runOnuLiveMonitorCycle(onuId, runToken) {
  const normalizedOnuId = Number(onuId);
  const normalizedToken = Number(runToken);
  if (!normalizedOnuId) {
    return;
  }
  if (state.liveMonitorOnuId !== normalizedOnuId || state.liveMonitorRunToken !== normalizedToken) {
    return;
  }
  if (state.liveMonitorInFlight) {
    scheduleOnuLiveMonitorTick(normalizedOnuId, normalizedToken, 1000);
    return;
  }
  state.liveMonitorInFlight = true;
  state.liveMonitorNextRunAtMs = null;
  updateOnuLiveMonitorUi();
  try {
    const result = await executeOnuQuickAction(normalizedOnuId, "live", { background: true });
    if (result?.live_available === false) {
      stopOnuLiveMonitor();
      if (state.selectedOnuId === normalizedOnuId) {
        renderOnuDetailsPanel();
      }
      return;
    }
  } catch (_) {
    // Erros ficam visiveis no painel da ONU via state.onuActionResult.
  } finally {
    state.liveMonitorInFlight = false;
    updateOnuLiveMonitorUi();
  }
  if (state.liveMonitorOnuId === normalizedOnuId && state.liveMonitorRunToken === normalizedToken) {
    scheduleOnuLiveMonitorTick(normalizedOnuId, normalizedToken, ONU_LIVE_MONITOR_INTERVAL_MS);
  }
}

async function startOnuLiveMonitor(onuId) {
  const normalizedOnuId = Number(onuId);
  if (!normalizedOnuId) {
    return;
  }
  stopOnuLiveMonitor();
  state.liveMonitorOnuId = normalizedOnuId;
  state.liveMonitorRunToken += 1;
  const currentRunToken = state.liveMonitorRunToken;
  let firstResult = null;
  try {
    firstResult = await executeOnuQuickAction(normalizedOnuId, "live");
  } catch (error) {
    if (state.liveMonitorOnuId === normalizedOnuId && state.liveMonitorRunToken === currentRunToken) {
      stopOnuLiveMonitor();
      if (state.selectedOnuId === normalizedOnuId) {
        renderOnuDetailsPanel();
      }
    }
    throw error;
  }
  if (state.liveMonitorOnuId !== normalizedOnuId || state.liveMonitorRunToken !== currentRunToken) {
    return;
  }
  if (firstResult?.live_available === false) {
    stopOnuLiveMonitor();
    if (state.selectedOnuId === normalizedOnuId) {
      renderOnuDetailsPanel();
    }
    return;
  }
  scheduleOnuLiveMonitorTick(normalizedOnuId, currentRunToken, ONU_LIVE_MONITOR_INTERVAL_MS);
}

async function toggleOnuLiveMonitor(onuId) {
  const normalizedOnuId = Number(onuId);
  if (state.liveMonitorOnuId === normalizedOnuId) {
    stopOnuLiveMonitor();
    if (state.selectedOnuId === normalizedOnuId) {
      renderOnuDetailsPanel();
    }
    return;
  }
  await startOnuLiveMonitor(normalizedOnuId);
  if (state.selectedOnuId === normalizedOnuId) {
    renderOnuDetailsPanel();
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function monitorPollProgress(oltId, pollTriggerPromise) {
  state.pollProgress[oltId] = {
    status: "running",
    progress_pct: 0,
    stage: "Iniciando coleta...",
  };
  renderConnections();

  try {
    await pollTriggerPromise;
    for (;;) {
      let progress = null;
      try {
        progress = await fetchJson(`/api/olts/${oltId}/poll-progress`);
      } catch (_) {
        // Silencia falhas transitorias de consulta de progresso.
      }
      if (progress) {
        state.pollProgress[oltId] = progress;
        renderConnections();
        if (progress.status === "ok") {
          return progress;
        }
        if (progress.status === "error") {
          throw new Error(progress.details || progress.stage || "Falha na coleta");
        }
      }
      await sleep(1200);
    }
  } catch (error) {
    state.pollProgress[oltId] = {
      status: "error",
      progress_pct: 100,
      stage: error.message || "Falha na coleta",
    };
    renderConnections();
    throw error;
  }
}

async function syncData() {
  requirePermission("collection_manage", "Sem permissao para sincronizacao geral.");
  const result = await fetchJson("/api/sync", { method: "POST", body: "{}" });
  document.getElementById("lastSync").textContent = `Ultima coleta geral: ${formatDateTime(result.updated_at)}`;
  await loadData();
}

function signalPercent(signalDbm) {
  if (!signalDbm) {
    return 0;
  }
  return Math.max(4, Math.min(100, ((signalDbm + 30) / 12) * 100));
}

function formatTime(value) {
  return new Date(value).toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" });
}

function formatDateTime(value) {
  return new Date(value).toLocaleString("pt-BR");
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function parseLiveTrafficFromOutput(output) {
  const text = String(output || "");
  if (!text) {
    return { down_mbps: null, up_mbps: null };
  }
  const downMatch = text.match(/downstream:\s*(-?[\d.]+)/i);
  const upMatch = text.match(/upstream:\s*(-?[\d.]+)/i);
  const down = downMatch ? Number(downMatch[1]) : null;
  const up = upMatch ? Number(upMatch[1]) : null;
  return {
    down_mbps: Number.isFinite(down) ? down : null,
    up_mbps: Number.isFinite(up) ? up : null,
  };
}

function appendOnuLiveSample(onuId, downMbps, upMbps, collectedAt) {
  const normalizedOnuId = Number(onuId);
  if (!normalizedOnuId) {
    return;
  }
  const current = Array.isArray(state.onuLiveSeriesByOnuId[normalizedOnuId])
    ? [...state.onuLiveSeriesByOnuId[normalizedOnuId]]
    : [];
  const previous = current.length ? current[current.length - 1] : null;

  const rawDown = Number(downMbps);
  const rawUp = Number(upMbps);
  const down = Number.isFinite(rawDown)
    ? rawDown
    : previous && Number.isFinite(Number(previous.down_mbps))
      ? Number(previous.down_mbps)
      : 0;
  const up = Number.isFinite(rawUp)
    ? rawUp
    : previous && Number.isFinite(Number(previous.up_mbps))
      ? Number(previous.up_mbps)
      : 0;

  if (!Number.isFinite(down) && !Number.isFinite(up)) {
    return;
  }
  const ts = new Date(collectedAt || Date.now()).getTime();
  const sample = {
    ts: Number.isFinite(ts) ? ts : Date.now(),
    down_mbps: Math.max(0, down),
    up_mbps: Math.max(0, up),
  };
  current.push(sample);
  const windowStart = Date.now() - 60_000;
  const trimmed = current.filter((item) => Number(item.ts) >= windowStart).slice(-60);
  state.onuLiveSeriesByOnuId[normalizedOnuId] = trimmed;
}

function getOnuLiveSeries(onuId) {
  const normalizedOnuId = Number(onuId);
  if (!normalizedOnuId) {
    return [];
  }
  const series = Array.isArray(state.onuLiveSeriesByOnuId[normalizedOnuId])
    ? state.onuLiveSeriesByOnuId[normalizedOnuId]
    : [];
  const windowStart = Date.now() - 60_000;
  return series.filter((item) => Number(item.ts) >= windowStart);
}

function getOnuConnection(onu) {
  if (!onu) {
    return null;
  }
  return state.connections.find((connection) => Number(connection.olt_id) === Number(onu.olt_id)) || null;
}

function getPonAlertThresholdMbps(onu) {
  const connection = getOnuConnection(onu);
  const extra = connection?.extra_config || {};
  const candidate = Number(
    extra.live_pon_alert_mbps ||
      extra.live_alert_mbps ||
      extra.snmp_live_alert_mbps ||
      200
  );
  return Number.isFinite(candidate) && candidate > 0 ? candidate : 200;
}

function getTrendDirection(series, field) {
  if (!Array.isArray(series) || series.length < 4) {
    return "stable";
  }
  const values = series.map((item) => Number(item[field] || 0));
  const half = Math.floor(values.length / 2);
  const first = values.slice(0, half);
  const second = values.slice(half);
  const avg = (items) => (items.length ? items.reduce((sum, value) => sum + value, 0) / items.length : 0);
  const firstAvg = avg(first);
  const secondAvg = avg(second);
  const delta = secondAvg - firstAvg;
  if (Math.abs(delta) < 0.8) {
    return "stable";
  }
  return delta > 0 ? "up" : "down";
}

function trendLabel(direction) {
  if (direction === "up") {
    return "Subindo";
  }
  if (direction === "down") {
    return "Caindo";
  }
  return "Estavel";
}

function buildLiveSparkline(series) {
  const width = 420;
  const height = 90;
  if (!Array.isArray(series) || series.length < 2) {
    return '<div class="muted">Aguardando amostras LIVE para montar grafico (60s).</div>';
  }
  const maxValue = Math.max(
    1,
    ...series.flatMap((item) => [Number(item.down_mbps || 0), Number(item.up_mbps || 0)])
  );
  const stepX = series.length > 1 ? width / (series.length - 1) : width;
  const toY = (value) => Math.max(4, Math.min(height - 4, height - (Number(value || 0) / maxValue) * (height - 8)));
  const pointsDown = series.map((item, index) => `${(index * stepX).toFixed(2)},${toY(item.down_mbps).toFixed(2)}`).join(" ");
  const pointsUp = series.map((item, index) => `${(index * stepX).toFixed(2)},${toY(item.up_mbps).toFixed(2)}`).join(" ");
  return `
    <svg class="onu-live-sparkline" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" aria-label="Grafico LIVE 60 segundos">
      <polyline class="onu-live-line down" points="${pointsDown}"></polyline>
      <polyline class="onu-live-line up" points="${pointsUp}"></polyline>
    </svg>
  `;
}

function bindEvents() {
  document.querySelectorAll(".tab-button").forEach((button) => {
    button.addEventListener("click", () => {
      activateTab(button.dataset.tab);
    });
  });

  const loginForm = document.getElementById("loginForm");
  loginForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await performLogin();
    } catch (error) {
      setAuthStatus(error.message || "Falha no login.", true);
    }
  });

  const bootstrapForm = document.getElementById("bootstrapForm");
  bootstrapForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await performBootstrap();
    } catch (error) {
      setAuthStatus(error.message || "Falha ao criar administrador.", true);
    }
  });

  document.getElementById("logoutButton")?.addEventListener("click", async () => {
    try {
      await performLogout();
    } catch (error) {
      setAuthStatus(error.message || "Falha ao encerrar sessao.", true);
    }
  });

  document.getElementById("createUserButton")?.addEventListener("click", async () => {
    try {
      await createUser();
    } catch (error) {
      alert(error.message);
    }
  });

  document.getElementById("syncButton").addEventListener("click", async () => {
    try {
      await syncData();
    } catch (error) {
      alert(error.message);
    }
  });

  document.getElementById("runAutofindAllButton").addEventListener("click", async () => {
    try {
      await runAutofindAllRequests();
    } catch (error) {
      alert(error.message);
    }
  });

  document.getElementById("syncOltProfilesButton").addEventListener("click", async () => {
    try {
      await syncOltProfilesForRequests();
    } catch (error) {
      alert(error.message);
    }
  });

  document.getElementById("onuSearch").addEventListener("input", (event) => {
    state.onuFilter = event.target.value;
    state.onuPage = 1;
    renderOnuTable();
  });

  document.getElementById("onuHistorySelect").addEventListener("change", async (event) => {
    try {
      await selectOnuAndRender(event.target.value);
    } catch (error) {
      alert(error.message);
    }
  });

  document.getElementById("createOltButton").addEventListener("click", async () => {
    try {
      await createOlt();
    } catch (error) {
      alert(error.message);
    }
  });

  document.getElementById("updateOltButton").addEventListener("click", async () => {
    try {
      await updateOlt();
    } catch (error) {
      alert(error.message);
    }
  });

  document.getElementById("connectOltButton").addEventListener("click", async () => {
    try {
      await connectOlt();
    } catch (error) {
      setOltConnectStatus("critical", error.message);
      alert(error.message);
    }
  });

  document.getElementById("clearOltFormButton").addEventListener("click", () => {
    clearOltForm();
  });

  document.getElementById("addOltVlanButton").addEventListener("click", async () => {
    try {
      await addOltVlan();
    } catch (error) {
      alert(error.message);
    }
  });

  document.querySelector("#createOltForm select[name='transport_type']").addEventListener("change", (event) => {
    const form = document.getElementById("createOltForm");
    const previousTransport = event.target.dataset.lastTransport || "ssh";
    const currentPort = Number(form.port.value || 0);
    if (!currentPort || currentPort === defaultPortForTransport(previousTransport)) {
      form.port.value = defaultPortForTransport(event.target.value);
    }
    event.target.dataset.lastTransport = event.target.value;
  });

  document.querySelector("#createOltForm select[name='catalog_brand']").addEventListener("change", () => {
    applyOltTemplateCatalogSelection("brand");
  });

  document.querySelector("#createOltForm select[name='catalog_model']").addEventListener("change", () => {
    applyOltTemplateCatalogSelection("model");
  });

  document.querySelector("#createOltForm select[name='catalog_firmware']").addEventListener("change", () => {
    applyOltTemplateCatalogSelection("firmware");
  });

  ["brand", "model", "firmware"].forEach((fieldName) => {
    const field = document.querySelector(`#createOltForm [name='${fieldName}']`);
    if (!field) {
      return;
    }
    field.addEventListener("input", () => {
      refreshOltTemplateCatalog();
    });
  });

  document.body.addEventListener("change", (event) => {
    if (event.target && event.target.matches("#createUserForm [name='is_admin']")) {
      syncUserFormAdminState(document.getElementById("createUserForm"));
      return;
    }
    if (event.target && event.target.matches("form[data-user-id] [name='is_admin']")) {
      syncUserFormAdminState(event.target.closest("form[data-user-id]"));
      return;
    }
    if (event.target && event.target.id === "oltVlanSelect") {
      state.selectedOltVlanId = Number(event.target.value || 0) || null;
      renderOltVlans();
      return;
    }
    const requestForm = event.target?.closest ? event.target.closest("form[data-request-id]") : null;
    if (requestForm && event.target?.name === "onu_mode") {
      storeRequestDraft(requestForm);
      renderRequests();
      return;
    }
    if (event.target && event.target.matches("[data-request-profile-select]")) {
      syncRequestProvisioningForm(requestForm, { source: "profile" });
      return;
    }
    if (requestForm && event.target?.name === "vlan_id") {
      syncRequestProvisioningForm(requestForm, { source: "vlan" });
      return;
    }
    if (requestForm) {
      storeRequestDraft(requestForm);
    }
  });

  document.body.addEventListener("input", (event) => {
    if (event.target && event.target.id === "oltVlanFilter") {
      state.oltVlanFilter = event.target.value || "";
      renderOltVlans();
      return;
    }
    const requestForm = event.target?.closest ? event.target.closest("form[data-request-id]") : null;
    if (requestForm) {
      if (event.target?.name === "vlan_id") {
        syncRequestProvisioningForm(requestForm, { source: "vlan" });
      } else {
        storeRequestDraft(requestForm);
      }
    }
  });

  document.body.addEventListener("click", async (event) => {
    const pagerButton = event.target.closest("[data-onu-page]");
    if (pagerButton) {
      state.onuPage = Number(pagerButton.dataset.onuPage);
      renderOnuTable();
      return;
    }

    const viewButton = event.target.closest("[data-onu-view-id]");
    if (viewButton) {
      try {
        await selectOnuAndRender(viewButton.dataset.onuViewId);
        openOnuModal();
      } catch (error) {
        alert(error.message);
      }
      return;
    }

    if (event.target.closest("[data-onu-modal-close]")) {
      closeOnuModal();
      return;
    }

    const oltTab = event.target.closest("[data-olt-id]");
    if (oltTab) {
      state.activeOltId = Number(oltTab.dataset.oltId);
      populateOltFormFromActive();
      try {
        await refreshOltVlans();
      } catch (_) {
        state.oltVlansByOltId[state.activeOltId] = [];
      }
      renderOltTabs();
      renderOltPanelTabs();
      renderOltPanels();
      renderOltDetails();
      renderOltVlans();
      return;
    }

    const oltPanelTab = event.target.closest("[data-olt-panel-tab]");
    if (oltPanelTab) {
      state.activeOltPanelTab = oltPanelTab.dataset.oltPanelTab || "infra";
      renderOltPanelTabs();
      renderOltPanels();
      return;
    }

    const onuRow = event.target.closest("[data-onu-id]");
    if (onuRow) {
      try {
        await selectOnuAndRender(onuRow.dataset.onuId);
      } catch (error) {
        alert(error.message);
      }
      return;
    }

    const onuQuickAction = event.target.closest("[data-onu-quick-action]");
    if (onuQuickAction) {
      const action = onuQuickAction.dataset.onuQuickAction;
      try {
        const onuId = Number(state.selectedOnuId);
        if (!onuId) {
          throw new Error("Selecione uma ONU para executar a acao.");
        }
        if (action === "refresh-all") {
          await collectOnuLive(onuId, ONU_FULL_REFRESH_FIELDS);
        } else if (action === "live") {
          await toggleOnuLiveMonitor(onuId);
        } else {
          await executeOnuQuickAction(onuId, action);
        }
      } catch (error) {
        alert(error.message);
      }
      return;
    }

    const deleteOnuButton = event.target.closest("[data-onu-delete-id]");
    if (deleteOnuButton) {
      try {
        const onuId = Number(deleteOnuButton.dataset.onuDeleteId);
        const onu = state.onus.find((item) => item.id === onuId);
        const label = onu ? `${onu.client_name || "ONU"} (${onu.serial})` : `ONU ${onuId}`;
        const confirmed = window.confirm(`Excluir ${label} da OLT e do sistema local?`);
        if (!confirmed) {
          return;
        }
        await deleteOnu(onuId);
      } catch (error) {
        alert(error.message);
      }
      return;
    }

    const previewButton = event.target.closest("[data-preview-request-id]");
    if (previewButton) {
      try {
        await previewRequestProvisioning(previewButton.dataset.previewRequestId);
      } catch (error) {
        alert(error.message);
      }
      return;
    }

    const actionButton = event.target.closest("[data-action]");
    if (actionButton) {
      try {
        await processRequest(actionButton.dataset.requestId, actionButton.dataset.action);
      } catch (error) {
        alert(error.message);
      }
      return;
    }

    const connectionButton = event.target.closest("[data-connection-action]");
    if (connectionButton) {
      try {
        const oltId = Number(connectionButton.dataset.connectionOltId);
        if (connectionButton.dataset.connectionAction === "save") {
          await saveConnection(oltId);
        } else if (connectionButton.dataset.connectionAction === "apply-template") {
          await applyConnectionTemplateNow(oltId);
        } else if (connectionButton.dataset.connectionAction === "apply-template-merge") {
          await applyConnectionTemplateMerge(oltId);
        } else if (connectionButton.dataset.connectionAction === "poll") {
          await pollOlt(oltId);
        }
      } catch (error) {
        alert(error.message);
      }
      return;
    }

    const templateButton = event.target.closest("[data-template-action]");
    if (templateButton) {
      try {
        const templateId = templateButton.dataset.templateId;
        if (templateButton.dataset.templateAction === "save") {
          await saveConnectionTemplate(templateId);
        } else if (templateButton.dataset.templateAction === "delete") {
          await deleteConnectionTemplate(templateId);
        }
      } catch (error) {
        alert(error.message);
      }
      return;
    }

    const userPresetButton = event.target.closest("[data-user-preset-key]");
    if (userPresetButton) {
      try {
        requirePermission("users_manage", "Sem permissao para aplicar perfil rapido.");
        applyUserPresetToForm(
          document.getElementById("createUserForm"),
          userPresetButton.dataset.userPresetKey
        );
      } catch (error) {
        alert(error.message);
      }
      return;
    }

    const userButton = event.target.closest("[data-user-action]");
    if (userButton) {
      try {
        const userId = Number(userButton.dataset.userId);
        if (userButton.dataset.userAction === "save") {
          await updateUser(userId);
        } else if (userButton.dataset.userAction === "delete") {
          await deleteUser(userId);
        }
      } catch (error) {
        alert(error.message);
      }
      return;
    }

    const deleteButton = event.target.closest("[data-delete-olt-id]");
    if (deleteButton) {
      try {
        const oltId = Number(deleteButton.dataset.deleteOltId);
        const confirmed = window.confirm("Excluir esta OLT e todos os dados vinculados?");
        if (!confirmed) {
          return;
        }
        await deleteOlt(oltId);
      } catch (error) {
        alert(error.message);
      }
      return;
    }

    const vlanActionButton = event.target.closest("[data-olt-vlan-action]");
    if (vlanActionButton) {
      try {
        const vlanId = Number(state.selectedOltVlanId);
        if (!vlanId) {
          throw new Error("Selecione uma VLAN.");
        }
        if (vlanActionButton.dataset.oltVlanAction === "save") {
          const nameInput = document.getElementById("selectedVlanName");
          const descriptionInput = document.getElementById("selectedVlanDescription");
          await saveOltVlan(vlanId, nameInput?.value || "", descriptionInput?.value || "");
        } else if (vlanActionButton.dataset.oltVlanAction === "delete") {
          const confirmed = window.confirm(`Excluir VLAN ${vlanId} desta OLT?`);
          if (!confirmed) {
            return;
          }
          await deleteOltVlan(vlanId);
        }
      } catch (error) {
        alert(error.message);
      }
      return;
    }

    const togglePasswordButton = event.target.closest("[data-password-target]");
    if (togglePasswordButton) {
      const formId = togglePasswordButton.dataset.passwordTarget;
      let passwordInput = null;
      if (formId === "createOltForm") {
        passwordInput = document.querySelector("#createOltForm input[name='password']");
      } else if (formId.startsWith("connection-")) {
        const oltId = formId.replace("connection-", "");
        passwordInput = document.querySelector(`form[data-connection-olt-id="${oltId}"] input[name='password']`);
      } else if (formId.startsWith("template-")) {
        const templateId = formId.replace("template-", "");
        passwordInput = document.querySelector(`form[data-template-id="${templateId}"] input[name='password']`);
      }
      if (passwordInput) {
        const nextType = passwordInput.type === "password" ? "text" : "password";
        passwordInput.type = nextType;
        togglePasswordButton.textContent = nextType === "password" ? "Mostrar" : "Ocultar";
      }
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      closeOnuModal();
    }
  });

  document.addEventListener("visibilitychange", handleDocumentVisibilityChange);
}

document.addEventListener("DOMContentLoaded", async () => {
  bindEvents();
  try {
    await ensureAuthenticatedAndLoad();
  } catch (error) {
    document.body.innerHTML = `<main class="page-shell"><article class="panel"><h1>Falha ao carregar</h1><p>${error.message}</p></article></main>`;
  }
});

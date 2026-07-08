const state = {
  authMode: 'api_key',
  apiKey: 'test_key',
  tenantId: 'demo-tenant',
  accessToken: null,
  principal: null,
  cases: [],
  selectedId: null,
  selectedCase: null,
  autoRefresh: null,
};

const els = {
  authMode: document.getElementById('authMode'),
  apiKeyFields: document.getElementById('apiKeyFields'),
  analystFields: document.getElementById('analystFields'),
  apiKey: document.getElementById('apiKey'),
  tenantId: document.getElementById('tenantId'),
  analystEmail: document.getElementById('analystEmail'),
  analystPassword: document.getElementById('analystPassword'),
  connectBtn: document.getElementById('connectBtn'),
  bootstrapBtn: document.getElementById('bootstrapBtn'),
  seedBtn: document.getElementById('seedBtn'),
  dispatchBtn: document.getElementById('dispatchBtn'),
  refreshBtn: document.getElementById('refreshBtn'),
  autoRefreshBtn: document.getElementById('autoRefreshBtn'),
  enqueueRetrainingBtn: document.getElementById('enqueueRetrainingBtn'),
  newKeyBtn: document.getElementById('newKeyBtn'),
  metrics: document.getElementById('metrics'),
  monitoring: document.getElementById('monitoring'),
  datasets: document.getElementById('datasets'),
  cases: document.getElementById('cases'),
  signals: document.getElementById('signals'),
  jobs: document.getElementById('jobs'),
  models: document.getElementById('models'),
  modelSummary: document.getElementById('modelSummary'),
  webhooks: document.getElementById('webhooks'),
  connectors: document.getElementById('connectors'),
  analysts: document.getElementById('analysts'),
  apiKeys: document.getElementById('apiKeys'),
  statusChip: document.getElementById('statusChip'),
  lastRefresh: document.getElementById('lastRefresh'),
  tenantName: document.getElementById('tenantName'),
  tenantMeta: document.getElementById('tenantMeta'),
  authState: document.getElementById('authState'),
  roleState: document.getElementById('roleState'),
  healthState: document.getElementById('healthState'),
  detail: document.getElementById('detail'),
  detailEmpty: document.getElementById('detailEmpty'),
  detailId: document.getElementById('detailId'),
  detailAction: document.getElementById('detailAction'),
  detailReasons: document.getElementById('detailReasons'),
  detailFactors: document.getElementById('detailFactors'),
  detailPayload: document.getElementById('detailPayload'),
  caseStatus: document.getElementById('caseStatus'),
  caseAssignee: document.getElementById('caseAssignee'),
  saveStatusBtn: document.getElementById('saveStatusBtn'),
  feedbackForm: document.getElementById('feedbackForm'),
  feedbackLabel: document.getElementById('feedbackLabel'),
  feedbackNotes: document.getElementById('feedbackNotes'),
  phishingForm: document.getElementById('phishingForm'),
  phishingUrl: document.getElementById('phishingUrl'),
  havingIpAddress: document.getElementById('havingIpAddress'),
  urlLength: document.getElementById('urlLength'),
  prefixSuffix: document.getElementById('prefixSuffix'),
  sslState: document.getElementById('sslState'),
  domainRegistrationLength: document.getElementById('domainRegistrationLength'),
  webTraffic: document.getElementById('webTraffic'),
  googleIndex: document.getElementById('googleIndex'),
  phishingResult: document.getElementById('phishingResult'),
  graphForm: document.getElementById('graphForm'),
  graphEntityType: document.getElementById('graphEntityType'),
  graphEntityId: document.getElementById('graphEntityId'),
  graphResult: document.getElementById('graphResult'),
  graphLinks: document.getElementById('graphLinks'),
  caseActionFilter: document.getElementById('caseActionFilter'),
  caseStatusFilter: document.getElementById('caseStatusFilter'),
  connectorForm: document.getElementById('connectorForm'),
  connectorRoute: document.getElementById('connectorRoute'),
  connectorSourcePath: document.getElementById('connectorSourcePath'),
  securityAudit: document.getElementById('securityAudit'),
  securityAuditPanel: document.getElementById('securityAuditPanel'),
};

function setStatus(message, tone = 'neutral') {
  els.statusChip.textContent = message;
  els.statusChip.className = `hero-chip ${tone === 'neutral' ? 'neutral' : ''}`.trim();
}

function formatDate(value) {
  if (!value) return 'n/a';
  return new Date(value).toLocaleString();
}

function isAdminLike() {
  return ['admin', 'service'].includes(state.principal?.role || '');
}

function authHeaders(contentType = true) {
  const headers = {};
  if (state.accessToken) {
    headers.Authorization = `Bearer ${state.accessToken}`;
  } else if (state.apiKey) {
    headers.Authorization = `Bearer ${state.apiKey}`;
  }
  if (contentType) {
    headers['Content-Type'] = 'application/json';
  }
  return headers;
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      ...authHeaders(options.body !== undefined),
      ...(options.headers || {}),
    },
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `Request failed: ${response.status}`);
  }
  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    return response.json();
  }
  return response.text();
}

async function safeApi(path, options = {}) {
  try {
    return await api(path, options);
  } catch (error) {
    if (String(error.message).includes('403')) {
      return null;
    }
    throw error;
  }
}

function renderMetrics(metrics, monitoring) {
  const cards = [...metrics];
  if (monitoring) {
    cards.push({ label: 'Queued jobs', value: String(monitoring.queued_jobs), tone: monitoring.queued_jobs ? 'warn' : 'good' });
    cards.push({ label: 'Failed jobs', value: String(monitoring.failed_jobs), tone: monitoring.failed_jobs ? 'danger' : 'good' });
    cards.push({ label: 'Dead-letter webhooks', value: String(monitoring.dead_letter_webhooks), tone: monitoring.dead_letter_webhooks ? 'danger' : 'good' });
  }
  els.metrics.innerHTML = cards.map(metric => `
    <article class="metric-card ${metric.tone || 'neutral'}">
      <div class="muted">${metric.label}</div>
      <div class="value">${metric.value}</div>
    </article>
  `).join('');
}

function renderDatasets(items) {
  if (!items) {
    els.datasets.innerHTML = '<div class="empty-state">Dataset inventory requires ops access.</div>';
    return;
  }
  els.datasets.innerHTML = items.map(item => `
    <div class="signal-item">
      <div>
        <strong>${item.dataset_name}</strong>
        <div class="case-meta">${item.kind} · ${item.record_count ?? 0} rows</div>
        <div class="case-meta dataset-path">${item.path}</div>
      </div>
      <div>${item.present ? 'ready' : 'missing'}</div>
    </div>
  `).join('') || '<div class="empty-state">No dataset inventory available.</div>';
}
function renderMonitoring(snapshot) {
  if (!snapshot) {
    els.monitoring.innerHTML = '<div class="empty-state">Monitoring requires ops access.</div>';
    return;
  }
  const items = [
    ['Queued jobs', snapshot.queued_jobs],
    ['Running jobs', snapshot.running_jobs],
    ['Failed jobs', snapshot.failed_jobs],
    ['Queued webhooks', snapshot.queued_webhooks],
    ['Dead-letter webhooks', snapshot.dead_letter_webhooks],
    ['Active analysts', snapshot.analysts_active],
    ['Active API keys', snapshot.api_keys_active],
    ['Model versions', snapshot.model_versions],
  ];
  els.monitoring.innerHTML = items.map(([label, value]) => `
    <div class="signal-item">
      <div>
        <strong>${label}</strong>
        <div class="case-meta">Operational snapshot</div>
      </div>
      <div>${value}</div>
    </div>
  `).join('');
}

function renderCases(items) {
  state.cases = items;
  if (!items.length) {
    els.cases.innerHTML = '<div class="empty-state">No cases match the current filters.</div>';
    return;
  }
  els.cases.innerHTML = items.map(item => `
    <button class="case-item ${state.selectedId === item.request_id ? 'active' : ''}" data-id="${item.request_id}">
      <div class="case-top">
        <strong>${item.route.toUpperCase()} · ${item.fraud_score}</strong>
        <span class="badge ${item.action}">${item.action}</span>
      </div>
      <div class="case-meta">${item.user_id || 'unknown user'} · ${formatDate(item.created_at)}</div>
      <div class="case-meta">${item.case_status}${item.assigned_to ? ` · ${item.assigned_to}` : ''}</div>
      <div class="case-meta">${item.reasons.join(' · ')}</div>
    </button>
  `).join('');
  document.querySelectorAll('.case-item').forEach(node => node.addEventListener('click', () => loadCase(node.dataset.id)));
}

function renderSignals(signals) {
  if (!signals.length) {
    els.signals.innerHTML = '<div class="empty-state">No signal data yet.</div>';
    return;
  }
  els.signals.innerHTML = signals.map(item => `
    <div class="signal-item">
      <div>
        <strong>${item.signal}</strong>
        <div class="case-meta">Seen ${item.count} times recently</div>
      </div>
      <div>${item.impact}</div>
    </div>
  `).join('');
}

function renderApiKeys(keys) {
  if (!keys) {
    els.apiKeys.innerHTML = '<div class="empty-state">Admin or service access required.</div>';
    return;
  }
  els.apiKeys.innerHTML = keys.map(item => `
    <div class="signal-item">
      <div>
        <strong>${item.key_name}</strong>
        <div class="case-meta">${item.key_prefix} · ${item.is_active ? 'active' : 'inactive'}</div>
      </div>
      <div>${item.last_used_at ? formatDate(item.last_used_at) : 'unused'}</div>
    </div>
  `).join('') || '<div class="empty-state">No API keys yet.</div>';
}

function renderAnalysts(items) {
  if (!items) {
    els.analysts.innerHTML = '<div class="empty-state">Admin or service access required.</div>';
    return;
  }
  els.analysts.innerHTML = items.map(item => `
    <div class="signal-item">
      <div>
        <strong>${item.full_name}</strong>
        <div class="case-meta">${item.email} · ${item.role}</div>
      </div>
      <div>${item.is_active ? 'active' : 'inactive'}</div>
    </div>
  `).join('') || '<div class="empty-state">No analysts created yet.</div>';
}

function renderModels(items) {
  if (!items) {
    els.models.innerHTML = '<div class="empty-state">Model registry requires ops access.</div>';
    return;
  }
  els.models.innerHTML = items.map(item => `
    <div class="signal-item">
      <div>
        <strong>${item.model_name}</strong>
        <div class="case-meta">${item.version_id} · ${item.stage}${item.is_active ? ' · active' : ''}</div>
        <div class="case-meta">f1 ${item.metrics.f1 ?? 'n/a'} · auc ${item.metrics.auc ?? 'n/a'}</div>
      </div>
      <div class="actions">
        <span class="badge ${item.is_active ? 'SUCCEEDED' : 'QUEUED'}">${item.is_active ? 'ACTIVE' : 'CANDIDATE'}</span>
        ${isAdminLike() && !item.is_active ? `<button class="ghost small activate-model-btn" data-model-name="${item.model_name}" data-version-id="${item.version_id}">Promote</button>` : ''}
      </div>
    </div>
  `).join('') || '<div class="empty-state">No model versions recorded yet.</div>';
  document.querySelectorAll('.activate-model-btn').forEach(node => node.addEventListener('click', async () => activateModel(node.dataset.modelName, node.dataset.versionId)));
}

function renderModelSummary(summary) {
  if (!summary) {
    els.modelSummary.innerHTML = '<div class="empty-state">Model evaluation summary is not available yet.</div>';
    return;
  }
  const items = Object.entries(summary.models || {});
  els.modelSummary.innerHTML = items.map(([modelName, info]) => {
    const metrics = info.metrics || {};
    return `
      <div class="signal-item model-summary-item">
        <div>
          <strong>${modelName}</strong>
          <div class="case-meta">${info.version_id}</div>
          <div class="case-meta dataset-path">${info.artifact_path}</div>
        </div>
        <div class="model-metrics-grid">
          <span>AUC <strong>${(metrics.auc ?? 0).toFixed ? metrics.auc.toFixed(4) : metrics.auc ?? 'n/a'}</strong></span>
          <span>F1 <strong>${(metrics.f1 ?? 0).toFixed ? metrics.f1.toFixed(4) : metrics.f1 ?? 'n/a'}</strong></span>
          <span>P <strong>${(metrics.precision ?? 0).toFixed ? metrics.precision.toFixed(4) : metrics.precision ?? 'n/a'}</strong></span>
          <span>R <strong>${(metrics.recall ?? 0).toFixed ? metrics.recall.toFixed(4) : metrics.recall ?? 'n/a'}</strong></span>
        </div>
      </div>
    `;
  }).join('') || '<div class="empty-state">No model evaluation data found.</div>';
}
function renderJobs(items) {
  if (!items) {
    els.jobs.innerHTML = '<div class="empty-state">Jobs require ops access.</div>';
    return;
  }
  els.jobs.innerHTML = items.map(item => `
    <div class="signal-item">
      <div>
        <strong>${item.job_type}</strong>
        <div class="case-meta">${item.job_id}</div>
        <div class="case-meta">Attempts ${item.attempts}/${item.max_attempts} · run after ${formatDate(item.run_after)}</div>
      </div>
      <div class="actions">
        <span class="badge ${item.status}">${item.status}</span>
      </div>
    </div>
  `).join('') || '<div class="empty-state">No jobs queued yet.</div>';
}

function renderWebhookDeliveries(items) {
  if (!items) {
    els.webhooks.innerHTML = '<div class="empty-state">Webhook visibility requires ops access.</div>';
    return;
  }
  els.webhooks.innerHTML = items.map(item => `
    <div class="signal-item">
      <div>
        <strong>${item.event_type}</strong>
        <div class="case-meta">${item.request_id}</div>
        <div class="case-meta">retry ${item.retry_count}/${item.max_attempts}${item.last_http_status ? ` · http ${item.last_http_status}` : ''}</div>
      </div>
      <div class="actions">
        <span class="badge ${item.status}">${item.status}</span>
      </div>
    </div>
  `).join('') || '<div class="empty-state">No webhook deliveries yet.</div>';
}

function renderConnectors(items) {
  if (!items) {
    els.connectors.innerHTML = '<div class="empty-state">Admin or service access required.</div>';
    return;
  }
  els.connectors.innerHTML = items.map(item => `
    <div class="signal-item">
      <div>
        <strong>${item.route}</strong>
        <div class="case-meta">${item.connector_type} · ${item.source_path}</div>
        <div class="case-meta">Last run ${item.last_run_at ? formatDate(item.last_run_at) : 'never'}</div>
      </div>
      <div class="actions">
        <button class="ghost small run-connector-btn" data-connector-id="${item.connector_id}">Run</button>
      </div>
    </div>
  `).join('') || '<div class="empty-state">No connectors configured yet.</div>';
  document.querySelectorAll('.run-connector-btn').forEach(node => node.addEventListener('click', async () => runConnector(node.dataset.connectorId)));
}

function renderSecurityAudit(items) {
  if (!items) {
    els.securityAuditPanel.classList.add('hidden-panel');
    els.securityAudit.innerHTML = '';
    return;
  }
  els.securityAuditPanel.classList.remove('hidden-panel');
  els.securityAudit.innerHTML = items.map(item => `
    <div class="signal-item">
      <div>
        <strong>${item.event_type}</strong>
        <div class="case-meta">${item.actor_id || 'system'} · ${item.actor_role || 'n/a'}</div>
        <div class="case-meta">${JSON.stringify(item.details)}</div>
      </div>
      <div>${formatDate(item.created_at)}</div>
    </div>
  `).join('') || '<div class="empty-state">No security audit events yet.</div>';
}

function formatStatLabel(key) {
  return key.replaceAll('_', ' ');
}

function formatRiskFlags(flags) {
  if (!flags.length) return '<span class="graph-pill good">No active graph flags</span>';
  return flags.map(flag => `<span class="graph-pill warn">${formatStatLabel(flag)}</span>`).join('');
}

function renderGraphResult(entity) {
  const stats = Object.entries(entity.stats).map(([key, value]) => `
    <div class="graph-stat">
      <span class="muted">${formatStatLabel(key)}</span>
      <strong>${value}</strong>
    </div>
  `).join('');
  els.graphResult.innerHTML = `
    <div class="graph-card">
      <div class="graph-card-top">
        <div>
          <div class="muted">${formatStatLabel(entity.entity_type)}</div>
          <strong>${entity.entity_id}</strong>
        </div>
        <div class="badge ${entity.risk_flags.length ? 'CHALLENGE' : 'ALLOW'}">${entity.risk_flags.length ? 'Linked risk' : 'Clean graph'}</div>
      </div>
      <div class="graph-pill-row">${formatRiskFlags(entity.risk_flags)}</div>
      <div class="graph-stats">${stats}</div>
    </div>
  `;
}

function buildGraphLinks(payload) {
  const links = [];
  if (payload.user_id) links.push({ entityType: 'user', entityId: payload.user_id, label: 'User', value: payload.user_id });
  if (payload.device_id) links.push({ entityType: 'device', entityId: payload.device_id, label: 'Device', value: payload.device_id });
  if (payload.device?.device_id) links.push({ entityType: 'device', entityId: payload.device.device_id, label: 'Device', value: payload.device.device_id });
  if (payload.payee_vpa) links.push({ entityType: 'payee', entityId: payload.payee_vpa, label: 'Payee', value: payload.payee_vpa });
  if (payload.phone_hash) links.push({ entityType: 'phone_hash', entityId: payload.phone_hash, label: 'Phone Hash', value: payload.phone_hash });
  if (payload.pan_hash) links.push({ entityType: 'pan_hash', entityId: payload.pan_hash, label: 'PAN Hash', value: payload.pan_hash });
  return links.filter((link, index, array) => array.findIndex(item => item.entityType === link.entityType && item.entityId === link.entityId) === index);
}

function renderGraphLinks(payload) {
  const links = buildGraphLinks(payload);
  if (!links.length) {
    els.graphLinks.innerHTML = '<div class="empty-state">This case does not expose graph-linked identifiers yet.</div>';
    return;
  }
  els.graphLinks.innerHTML = links.map(link => `
    <button class="signal-item graph-link-button" data-entity-type="${link.entityType}" data-entity-id="${link.entityId}">
      <div>
        <strong>${link.label}</strong>
        <div class="case-meta graph-link-value">${link.value}</div>
      </div>
      <div>Inspect</div>
    </button>
  `).join('');
  document.querySelectorAll('.graph-link-button').forEach(node => {
    node.addEventListener('click', async () => {
      els.graphEntityType.value = node.dataset.entityType;
      els.graphEntityId.value = node.dataset.entityId;
      await loadGraphEntity(node.dataset.entityType, node.dataset.entityId);
    });
  });
}

async function loadHealth() {
  const health = await api('/health', { headers: {}, body: undefined });
  els.healthState.textContent = `${health.status} · db ${health.database}`;
  return health;
}

async function loadPrincipal() {
  state.principal = await api('/v1/auth/me');
  els.authState.textContent = state.principal.auth_method;
  els.roleState.textContent = state.principal.role;
  return state.principal;
}

async function loadTenant() {
  const tenant = await api('/v1/tenant');
  els.tenantName.textContent = tenant.name;
  els.tenantMeta.textContent = `${tenant.tenant_id} · ${tenant.role || 'unknown role'} · via ${tenant.key_name}`;
}

async function loadCase(requestId) {
  state.selectedId = requestId;
  const detail = await api(`/v1/ops/cases/${requestId}`);
  state.selectedCase = detail;
  renderCases(state.cases);
  els.detailEmpty.classList.add('hidden');
  els.detail.classList.remove('hidden');
  els.detailId.textContent = detail.request_id;
  els.detailAction.textContent = `${detail.action} · ${detail.fraud_score}`;
  els.detailReasons.innerHTML = detail.reasons.map(reason => `<li>${reason}</li>`).join('');
  els.detailFactors.innerHTML = detail.factors.map(factor => `
    <div class="signal-item">
      <div>
        <strong>${factor.signal}</strong>
        <div class="case-meta">${factor.summary}</div>
      </div>
      <div>${factor.impact}</div>
    </div>
  `).join('');
  els.caseStatus.value = detail.case_status;
  els.caseAssignee.value = detail.assigned_to || '';
  els.detailPayload.textContent = JSON.stringify(detail.request_payload, null, 2);
  renderGraphLinks(detail.request_payload);
}

async function loadGraphEntity(entityType, entityId) {
  const trimmed = entityId.trim();
  if (!trimmed) {
    els.graphResult.innerHTML = '<div class="empty-state">Enter an entity ID or pick one from the selected case.</div>';
    return;
  }
  try {
    const entity = await api(`/v1/ops/graph/${encodeURIComponent(entityType)}/${encodeURIComponent(trimmed)}`);
    renderGraphResult(entity);
    setStatus(`Loaded graph view for ${entityType} ${trimmed}`);
  } catch {
    els.graphResult.innerHTML = `
      <div class="graph-card">
        <strong>Graph entity not found</strong>
        <div class="case-meta">No stored links for ${entityType} ${trimmed} yet.</div>
      </div>
    `;
  }
}

async function loadSummary() {
  const action = els.caseActionFilter.value;
  const caseStatus = els.caseStatusFilter.value;
  await Promise.all([loadHealth(), loadPrincipal(), loadTenant()]);
  const summary = await api('/v1/ops/summary');
  const [cases, monitoring, jobs, models, webhooks, connectors, analysts, apiKeys, securityAudit, datasets, modelSummary] = await Promise.all([
    api(`/v1/ops/cases?limit=30${action ? `&action=${encodeURIComponent(action)}` : ''}${caseStatus ? `&case_status=${encodeURIComponent(caseStatus)}` : ''}`),
    safeApi('/v1/ops/monitoring'),
    safeApi('/v1/ops/jobs?limit=10'),
    safeApi('/v1/ops/models?limit=10'),
    safeApi('/v1/ops/webhook-deliveries?limit=10'),
    safeApi('/v1/ops/connectors'),
    safeApi('/v1/ops/analysts'),
    safeApi('/v1/ops/api-keys'),
    safeApi('/v1/ops/security-audit?limit=10'),
  ]);

  renderMetrics(summary.metrics, monitoring);
  renderSignals(summary.top_signals);
  renderCases(cases?.items || []);
  renderMonitoring(monitoring);
  renderDatasets(datasets);
  renderJobs(jobs);
  renderModelSummary(modelSummary);
  renderModels(models);
  renderWebhookDeliveries(webhooks);
  renderConnectors(connectors);
  renderAnalysts(analysts);
  renderApiKeys(apiKeys);
  renderSecurityAudit(securityAudit);

  els.lastRefresh.textContent = `Refreshed ${new Date().toLocaleTimeString()}`;
  setStatus(`Loaded ${cases?.items?.length || 0} cases`);
}

async function connect() {
  state.authMode = els.authMode.value;
  state.apiKey = els.apiKey.value.trim();
  state.tenantId = els.tenantId.value.trim() || 'demo-tenant';
  if (state.authMode === 'analyst') {
    const login = await fetch('/v1/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Tenant-Id': state.tenantId,
      },
      body: JSON.stringify({
        email: els.analystEmail.value.trim(),
        password: els.analystPassword.value,
      }),
    });
    if (!login.ok) {
      throw new Error(await login.text());
    }
    const payload = await login.json();
    state.accessToken = payload.access_token;
  } else {
    state.accessToken = null;
  }
  await loadSummary();
}

async function bootstrapAdmin() {
  const email = window.prompt('Bootstrap admin email', 'admin@fraudguard.local');
  if (!email) return;
  const password = window.prompt('Bootstrap admin password', 'StrongPass!234');
  if (!password) return;
  const fullName = window.prompt('Bootstrap admin full name', 'FraudGuard Admin');
  if (!fullName) return;
  await api('/v1/auth/bootstrap', {
    method: 'POST',
    body: JSON.stringify({ email, password, full_name: fullName }),
  });
  setStatus(`Bootstrapped admin ${email}`);
}

async function seedDemo() {
  const result = await api('/v1/dev/seed', { method: 'POST' });
  setStatus(`Generated ${result.generated_cases} demo events`);
  await loadSummary();
}

async function dispatchWebhooks() {
  const result = await api('/v1/ops/webhook-deliveries/dispatch', { method: 'POST' });
  setStatus(`Webhooks: ${result.dispatched} delivered, ${result.failed} failed`);
  await loadSummary();
}

async function activateModel(modelName, versionId) {
  await api(`/v1/ops/models/${encodeURIComponent(modelName)}/${encodeURIComponent(versionId)}/activate`, {
    method: 'POST',
    body: JSON.stringify({ stage: 'production' }),
  });
  setStatus(`Promoted ${modelName} ${versionId}`);
  await loadSummary();
}

async function enqueueRetraining() {
  const job = await api('/v1/dev/retraining-jobs', {
    method: 'POST',
    body: JSON.stringify({ promote_stage: 'candidate', activate_after_training: false }),
  });
  setStatus(`Queued retraining job ${job.job_id}`);
  await loadSummary();
}

async function createApiKey() {
  const keyName = window.prompt('New API key name');
  if (!keyName) return;
  const result = await api('/v1/ops/api-keys', {
    method: 'POST',
    body: JSON.stringify({ key_name: keyName }),
  });
  window.alert(`New key created once. Save it now:\n\n${result.raw_key}`);
  await loadSummary();
}

async function saveCaseStatus() {
  if (!state.selectedId) return;
  await api(`/v1/ops/cases/${state.selectedId}/status`, {
    method: 'PATCH',
    body: JSON.stringify({ case_status: els.caseStatus.value, assigned_to: els.caseAssignee.value || null }),
  });
  setStatus(`Case ${state.selectedId} updated`);
  await loadSummary();
  await loadCase(state.selectedId);
}

async function saveFeedback(event) {
  event.preventDefault();
  if (!state.selectedId) return;
  await api(`/v1/ops/cases/${state.selectedId}/feedback`, {
    method: 'POST',
    body: JSON.stringify({ label: els.feedbackLabel.value, notes: els.feedbackNotes.value, reported_by: state.principal?.email || 'dashboard-analyst' }),
  });
  setStatus(`Feedback saved for ${state.selectedId}`);
  await loadSummary();
  await loadCase(state.selectedId);
}

function buildPhishingPayload() {
  return {
    url: els.phishingUrl.value.trim() || null,
    source: 'dashboard',
    having_ip_address: Number(els.havingIpAddress.value),
    url_length: Number(els.urlLength.value),
    shortening_service: 0,
    having_at_symbol: 0,
    double_slash_redirecting: 0,
    prefix_suffix: Number(els.prefixSuffix.value),
    having_sub_domain: 0,
    sslfinal_state: Number(els.sslState.value),
    domain_registration_length: Number(els.domainRegistrationLength.value),
    favicon: 0,
    port: 0,
    https_token: 0,
    request_url: 0,
    url_of_anchor: 0,
    links_in_tags: 0,
    sfh: 0,
    submitting_to_email: 0,
    abnormal_url: 0,
    redirect: 0,
    on_mouseover: 0,
    rightclick: 0,
    popup_window: 0,
    iframe: 0,
    age_of_domain: 0,
    dnsrecord: 0,
    web_traffic: Number(els.webTraffic.value),
    page_rank: 0,
    google_index: Number(els.googleIndex.value),
    links_pointing_to_page: 0,
    statistical_report: 0,
  };
}

async function submitPhishing(event) {
  event.preventDefault();
  const result = await api('/v1/score/phishing', {
    method: 'POST',
    body: JSON.stringify(buildPhishingPayload()),
  });
  els.phishingResult.innerHTML = `
    <div class="phishing-result-card ${result.action}">
      <strong>${result.action} · ${result.fraud_score}</strong>
      <div class="case-meta">${result.reasons.join(' · ')}</div>
      <div class="case-meta">Request ${result.request_id}</div>
    </div>
  `;
  setStatus(`Phishing screen completed with ${result.action}`);
  await loadSummary();
  await loadCase(result.request_id);
}

async function submitGraphLookup(event) {
  event.preventDefault();
  await loadGraphEntity(els.graphEntityType.value, els.graphEntityId.value);
}

async function createConnector(event) {
  event.preventDefault();
  await api('/v1/ops/connectors', {
    method: 'POST',
    body: JSON.stringify({ connector_type: 'file_drop', route: els.connectorRoute.value, source_path: els.connectorSourcePath.value.trim(), config: {} }),
  });
  setStatus(`Connector created for ${els.connectorRoute.value}`);
  els.connectorSourcePath.value = '';
  await loadSummary();
}

async function runConnector(connectorId) {
  const payload = await api(`/v1/ops/connectors/${connectorId}/run`, { method: 'POST' });
  setStatus(`Connector queued as job ${payload.job_id}`);
  await loadSummary();
}

function syncAuthMode() {
  const analystMode = els.authMode.value === 'analyst';
  els.apiKeyFields.classList.toggle('hidden', analystMode);
  els.analystFields.classList.toggle('hidden', !analystMode);
}

function toggleAutoRefresh() {
  if (state.autoRefresh) {
    clearInterval(state.autoRefresh);
    state.autoRefresh = null;
    els.autoRefreshBtn.textContent = 'Auto Refresh: Off';
    return;
  }
  state.autoRefresh = setInterval(() => {
    loadSummary().catch(error => console.error(error));
  }, 15000);
  els.autoRefreshBtn.textContent = 'Auto Refresh: On';
}

els.authMode.addEventListener('change', syncAuthMode);
els.connectBtn.addEventListener('click', () => connect().catch(handleError));
els.bootstrapBtn.addEventListener('click', () => bootstrapAdmin().catch(handleError));
els.seedBtn.addEventListener('click', () => seedDemo().catch(handleError));
els.dispatchBtn.addEventListener('click', () => dispatchWebhooks().catch(handleError));
els.refreshBtn.addEventListener('click', () => loadSummary().catch(handleError));
els.autoRefreshBtn.addEventListener('click', toggleAutoRefresh);
els.enqueueRetrainingBtn.addEventListener('click', () => enqueueRetraining().catch(handleError));
els.newKeyBtn.addEventListener('click', () => createApiKey().catch(handleError));
els.saveStatusBtn.addEventListener('click', () => saveCaseStatus().catch(handleError));
els.feedbackForm.addEventListener('submit', event => saveFeedback(event).catch(handleError));
els.phishingForm.addEventListener('submit', event => submitPhishing(event).catch(handleError));
els.graphForm.addEventListener('submit', event => submitGraphLookup(event).catch(handleError));
els.connectorForm.addEventListener('submit', event => createConnector(event).catch(handleError));
els.caseActionFilter.addEventListener('change', () => loadSummary().catch(handleError));
els.caseStatusFilter.addEventListener('change', () => loadSummary().catch(handleError));

function handleError(error) {
  console.error(error);
  setStatus(String(error.message || error).slice(0, 160), 'neutral');
}

syncAuthMode();
loadSummary().catch(error => {
  console.error(error);
  setStatus('Connect with a valid API key or analyst login', 'neutral');
});



const state = {
  apiKey: 'test_key',
  cases: [],
  selectedId: null,
  selectedCase: null,
};

const els = {
  apiKey: document.getElementById('apiKey'),
  connectBtn: document.getElementById('connectBtn'),
  seedBtn: document.getElementById('seedBtn'),
  dispatchBtn: document.getElementById('dispatchBtn'),
  refreshBtn: document.getElementById('refreshBtn'),
  newKeyBtn: document.getElementById('newKeyBtn'),
  metrics: document.getElementById('metrics'),
  cases: document.getElementById('cases'),
  signals: document.getElementById('signals'),
  apiKeys: document.getElementById('apiKeys'),
  datasets: document.getElementById('datasets'),
  statusChip: document.getElementById('statusChip'),
  tenantName: document.getElementById('tenantName'),
  tenantMeta: document.getElementById('tenantMeta'),
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
};

function authHeaders() {
  return {
    Authorization: `Bearer ${state.apiKey}`,
    'Content-Type': 'application/json',
  };
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      ...authHeaders(),
      ...(options.headers || {}),
    },
  });
  if (!response.ok) {
    throw new Error(await response.text());
  }
  return response.json();
}

function renderMetrics(metrics) {
  els.metrics.innerHTML = metrics.map(metric => `
    <article class="metric-card ${metric.tone}">
      <div class="muted">${metric.label}</div>
      <div class="value">${metric.value}</div>
    </article>
  `).join('');
}

function renderCases(items) {
  state.cases = items;
  els.cases.innerHTML = items.map(item => `
    <button class="case-item ${state.selectedId === item.request_id ? 'active' : ''}" data-id="${item.request_id}">
      <div class="case-top">
        <strong>${item.route.toUpperCase()} · ${item.fraud_score}</strong>
        <span class="badge ${item.action}">${item.action}</span>
      </div>
      <div class="case-meta">${item.user_id || 'unknown user'} · ${new Date(item.created_at).toLocaleString()}</div>
      <div class="case-meta">${item.case_status}${item.assigned_to ? ` · ${item.assigned_to}` : ''}</div>
      <div class="case-meta">${item.reasons.join(' · ')}</div>
    </button>
  `).join('');

  document.querySelectorAll('.case-item').forEach((node) => {
    node.addEventListener('click', () => loadCase(node.dataset.id));
  });
}

function renderSignals(signals) {
  els.signals.innerHTML = signals.map(item => `
    <div class="signal-item">
      <div>
        <strong>${item.signal}</strong>
        <div class="case-meta">Seen ${item.count} times</div>
      </div>
      <div>${item.impact}</div>
    </div>
  `).join('');
}

function renderApiKeys(keys) {
  els.apiKeys.innerHTML = keys.map(item => `
    <div class="signal-item">
      <div>
        <strong>${item.key_name}</strong>
        <div class="case-meta">${item.key_prefix} · ${item.is_active ? 'active' : 'inactive'}</div>
      </div>
      <div>${item.last_used_at ? new Date(item.last_used_at).toLocaleDateString() : 'unused'}</div>
    </div>
  `).join('');
}

function renderDatasets(items) {
  els.datasets.innerHTML = items.map(item => `
    <div class="signal-item dataset-item ${item.present ? 'dataset-ready' : 'dataset-missing'}">
      <div>
        <strong>${item.dataset_name}</strong>
        <div class="case-meta">${item.kind} · ${item.record_count ?? 0} rows · ${item.linked_models.join(', ')}</div>
        <div class="case-meta dataset-path">${item.path}</div>
      </div>
      <div>${item.present ? 'ready' : 'missing'}</div>
    </div>
  `).join('');
}

function formatStatLabel(key) {
  return key.replaceAll('_', ' ');
}

function formatRiskFlags(flags) {
  if (!flags.length) {
    return '<span class="graph-pill good">No active graph flags</span>';
  }
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
        <div class="badge ${entity.risk_flags.length ? 'CHALLENGE' : 'ALLOW'}">${entity.risk_flags.length ? 'Linked Risk' : 'Clean Graph'}</div>
      </div>
      <div class="graph-pill-row">${formatRiskFlags(entity.risk_flags)}</div>
      <div class="graph-stats">${stats}</div>
    </div>
  `;
}

function buildGraphLinks(payload) {
  const links = [];
  if (payload.user_id) {
    links.push({ entityType: 'user', entityId: payload.user_id, label: 'User', value: payload.user_id });
  }
  if (payload.device_id) {
    links.push({ entityType: 'device', entityId: payload.device_id, label: 'Device', value: payload.device_id });
  }
  if (payload.device?.device_id) {
    links.push({ entityType: 'device', entityId: payload.device.device_id, label: 'Device', value: payload.device.device_id });
  }
  if (payload.payee_vpa) {
    links.push({ entityType: 'payee', entityId: payload.payee_vpa, label: 'Payee', value: payload.payee_vpa });
  }
  if (payload.phone_hash) {
    links.push({ entityType: 'phone_hash', entityId: payload.phone_hash, label: 'Phone Hash', value: payload.phone_hash });
  }
  if (payload.pan_hash) {
    links.push({ entityType: 'pan_hash', entityId: payload.pan_hash, label: 'PAN Hash', value: payload.pan_hash });
  }
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

  document.querySelectorAll('.graph-link-button').forEach((node) => {
    node.addEventListener('click', async () => {
      els.graphEntityType.value = node.dataset.entityType;
      els.graphEntityId.value = node.dataset.entityId;
      await loadGraphEntity(node.dataset.entityType, node.dataset.entityId);
    });
  });
}

async function loadTenant() {
  const tenant = await api('/v1/tenant');
  els.tenantName.textContent = tenant.name;
  els.tenantMeta.textContent = `${tenant.tenant_id} · via ${tenant.key_name}`;
}

async function loadApiKeys() {
  const keys = await api('/v1/ops/api-keys');
  renderApiKeys(keys);
}

async function loadDatasets() {
  const items = await api('/v1/ops/datasets');
  renderDatasets(items);
}

async function loadSummary() {
  await loadTenant();
  const summary = await api('/v1/ops/summary');
  renderMetrics(summary.metrics);
  renderCases(summary.recent_cases);
  renderSignals(summary.top_signals);
  await Promise.all([loadApiKeys(), loadDatasets()]);
  els.statusChip.textContent = `Loaded ${summary.recent_cases.length} recent cases`;
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
  const trimmedId = entityId.trim();
  if (!trimmedId) {
    els.graphResult.innerHTML = '<div class="empty-state">Enter an entity ID or pick one from the selected case.</div>';
    return;
  }

  try {
    const entity = await api(`/v1/ops/graph/${encodeURIComponent(entityType)}/${encodeURIComponent(trimmedId)}`);
    renderGraphResult(entity);
    els.statusChip.textContent = `Loaded graph view for ${entityType} ${trimmedId}`;
  } catch (error) {
    els.graphResult.innerHTML = `
      <div class="graph-card graph-card-error">
        <strong>Graph entity not found</strong>
        <div class="case-meta">No stored links for ${entityType} ${trimmedId} yet.</div>
      </div>
    `;
  }
}

async function seedDemo() {
  const result = await api('/v1/dev/seed', { method: 'POST' });
  els.statusChip.textContent = `Generated ${result.generated_cases} demo events`;
  await loadSummary();
}

async function dispatchWebhooks() {
  const result = await api('/v1/ops/webhook-deliveries/dispatch', { method: 'POST' });
  els.statusChip.textContent = `Webhooks: ${result.dispatched} delivered, ${result.failed} failed`;
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
  await loadApiKeys();
}

async function saveCaseStatus() {
  if (!state.selectedId) return;
  await api(`/v1/ops/cases/${state.selectedId}/status`, {
    method: 'PATCH',
    body: JSON.stringify({
      case_status: els.caseStatus.value,
      assigned_to: els.caseAssignee.value || null,
    }),
  });
  els.statusChip.textContent = `Case ${state.selectedId} updated`;
  await loadSummary();
  await loadCase(state.selectedId);
}

async function saveFeedback(event) {
  event.preventDefault();
  if (!state.selectedId) return;
  await api(`/v1/ops/cases/${state.selectedId}/feedback`, {
    method: 'POST',
    body: JSON.stringify({
      label: els.feedbackLabel.value,
      notes: els.feedbackNotes.value,
      reported_by: 'dashboard-analyst',
    }),
  });
  els.statusChip.textContent = `Feedback saved for ${state.selectedId}`;
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
  els.statusChip.textContent = `Phishing screen completed with ${result.action}`;
  await loadSummary();
  await loadCase(result.request_id);
}

async function submitGraphLookup(event) {
  event.preventDefault();
  await loadGraphEntity(els.graphEntityType.value, els.graphEntityId.value);
}

els.connectBtn.addEventListener('click', async () => {
  state.apiKey = els.apiKey.value.trim();
  await loadSummary();
});

els.refreshBtn.addEventListener('click', loadSummary);
els.seedBtn.addEventListener('click', seedDemo);
els.dispatchBtn.addEventListener('click', dispatchWebhooks);
els.newKeyBtn.addEventListener('click', createApiKey);
els.saveStatusBtn.addEventListener('click', saveCaseStatus);
els.feedbackForm.addEventListener('submit', saveFeedback);
els.phishingForm.addEventListener('submit', submitPhishing);
els.graphForm.addEventListener('submit', submitGraphLookup);

loadSummary().catch((error) => {
  els.statusChip.textContent = 'Enter a valid API key to load data';
  console.error(error);
});

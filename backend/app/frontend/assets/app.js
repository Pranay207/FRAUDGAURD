const state = {
  authMode: 'api_key',
  apiKey: 'test_key',
  tenantId: 'demo-tenant',
  accessToken: null,
  principal: null,
  cases: [],
  selectedCaseIds: new Set(),
  selectedId: null,
  selectedCase: null,
  modelEvaluationSummary: null,
  autoRefresh: null,
  analysts: [],
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
  shadowSummary: document.getElementById('shadowSummary'),
  exportShadowBtn: document.getElementById('exportShadowBtn'),
  shadowDecisions: document.getElementById('shadowDecisions'),
  pilotReport: document.getElementById('pilotReport'),
  exportPilotReportBtn: document.getElementById('exportPilotReportBtn'),
  webhooks: document.getElementById('webhooks'),
  connectors: document.getElementById('connectors'),
  analysts: document.getElementById('analysts'),
  analystDirectory: document.getElementById('analystDirectory'),
  analystCreateForm: document.getElementById('analystCreateForm'),
  analystFullName: document.getElementById('analystFullName'),
  analystCreateEmail: document.getElementById('analystCreateEmail'),
  analystCreatePassword: document.getElementById('analystCreatePassword'),
  analystCreateRole: document.getElementById('analystCreateRole'),
  createAnalystBtn: document.getElementById('createAnalystBtn'),
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
  detailShadow: document.getElementById('detailShadow'),
  detailModelEvidence: document.getElementById('detailModelEvidence'),
  detailPayload: document.getElementById('detailPayload'),
  detailActivity: document.getElementById('detailActivity'),
  detailLinkedCases: document.getElementById('detailLinkedCases'),
  exportActivityBtn: document.getElementById('exportActivityBtn'),
  caseStatus: document.getElementById('caseStatus'),
  caseAssignee: document.getElementById('caseAssignee'),
  saveStatusBtn: document.getElementById('saveStatusBtn'),
  exportCaseBtn: document.getElementById('exportCaseBtn'),
  exportCasesBtn: document.getElementById('exportCasesBtn'),
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
  caseSearch: document.getElementById('caseSearch'),
  caseQueueStats: document.getElementById('caseQueueStats'),
  bulkAssignee: document.getElementById('bulkAssignee'),
  bulkCaseStatus: document.getElementById('bulkCaseStatus'),
  applyBulkCasesBtn: document.getElementById('applyBulkCasesBtn'),
  clearCaseSelectionBtn: document.getElementById('clearCaseSelectionBtn'),
  assignMeBtn: document.getElementById('assignMeBtn'),
  clearAssigneeBtn: document.getElementById('clearAssigneeBtn'),
  connectorForm: document.getElementById('connectorForm'),
  connectorRoute: document.getElementById('connectorRoute'),
  connectorSourcePath: document.getElementById('connectorSourcePath'),
  securityAudit: document.getElementById('securityAudit'),
  securityAuditPanel: document.getElementById('securityAuditPanel'),
};

const customSelectState = {
  active: null,
};

function closeCustomSelect(wrapper = customSelectState.active) {
  if (!wrapper) return;
  wrapper.classList.remove('open');
  const button = wrapper.querySelector('.custom-select-trigger');
  if (button) {
    button.setAttribute('aria-expanded', 'false');
  }
  if (customSelectState.active === wrapper) {
    customSelectState.active = null;
  }
}

function refreshCustomSelect(select) {
  const wrapper = select?.nextElementSibling;
  if (!wrapper || !wrapper.classList.contains('custom-select')) return;
  const button = wrapper.querySelector('.custom-select-trigger');
  const selected = select.options[select.selectedIndex];
  if (button) {
    button.textContent = selected ? selected.textContent : '';
  }
  wrapper.querySelectorAll('.custom-select-option').forEach(option => {
    const active = option.dataset.value === select.value;
    option.classList.toggle('active', active);
    option.setAttribute('aria-selected', active ? 'true' : 'false');
  });
}

function buildCustomSelect(select) {
  if (!select || select.dataset.customized === 'true') return;

  select.dataset.customized = 'true';
  select.classList.add('native-select-hidden');

  const wrapper = document.createElement('div');
  wrapper.className = 'custom-select';

  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'custom-select-trigger';
  button.setAttribute('aria-haspopup', 'listbox');
  button.setAttribute('aria-expanded', 'false');

  const menu = document.createElement('div');
  menu.className = 'custom-select-menu';
  menu.setAttribute('role', 'listbox');

  Array.from(select.options).forEach((nativeOption, index) => {
    const option = document.createElement('button');
    option.type = 'button';
    option.className = 'custom-select-option';
    option.dataset.value = nativeOption.value;
    option.dataset.index = String(index);
    option.textContent = nativeOption.textContent || '';
    option.setAttribute('role', 'option');
    option.setAttribute('aria-selected', 'false');
    option.addEventListener('click', () => {
      select.value = nativeOption.value;
      refreshCustomSelect(select);
      closeCustomSelect(wrapper);
      select.dispatchEvent(new Event('change', { bubbles: true }));
    });
    menu.appendChild(option);
  });

  button.addEventListener('click', () => {
    const isOpen = wrapper.classList.contains('open');
    if (customSelectState.active && customSelectState.active !== wrapper) {
      closeCustomSelect(customSelectState.active);
    }
    if (isOpen) {
      closeCustomSelect(wrapper);
      return;
    }
    wrapper.classList.add('open');
    button.setAttribute('aria-expanded', 'true');
    customSelectState.active = wrapper;
  });

  wrapper.appendChild(button);
  wrapper.appendChild(menu);
  select.insertAdjacentElement('afterend', wrapper);
  refreshCustomSelect(select);
}

function initCustomSelects() {
  document.querySelectorAll('select').forEach(buildCustomSelect);
  document.addEventListener('click', event => {
    if (!customSelectState.active) return;
    if (customSelectState.active.contains(event.target)) return;
    closeCustomSelect(customSelectState.active);
  });
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape') {
      closeCustomSelect(customSelectState.active);
    }
  });
}

function setStatus(message, tone = 'neutral') {
  els.statusChip.textContent = message;
  els.statusChip.className = `hero-chip ${tone === 'neutral' ? 'neutral' : ''}`.trim();
}

function formatDate(value) {
  if (!value) return 'n/a';
  return new Date(value).toLocaleString();
}

function formatMetricValue(value, digits = 4) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) {
    return 'n/a';
  }
  return Number(value).toFixed(digits);
}

function basename(path) {
  if (!path) return 'n/a';
  return String(path).split(/[\/]/).pop();
}

function isAdminLike() {
  return ['admin', 'service'].includes(state.principal?.role || '');
}

function analystIdentity(item) {
  return item.email || item.full_name || item.analyst_id;
}

function renderAnalystDirectory(items) {
  if (!els.analystDirectory) return;
  els.analystDirectory.innerHTML = (items || []).filter(item => item.is_active).map(item => `<option value="${analystIdentity(item)}"></option>`).join('');
}

function syncAdminControls() {
  const adminLike = isAdminLike();
  els.analystCreateForm?.classList.toggle('hidden', !adminLike);
  els.newKeyBtn?.classList.toggle('hidden', !adminLike);
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
        <div class="case-meta">${item.kind} | ${item.record_count ?? 0} rows</div>
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
  renderCaseQueueStats(items);
  if (!items.length) {
    els.cases.innerHTML = '<div class="empty-state">No cases match the current filters.</div>';
    return;
  }
  els.cases.innerHTML = items.map(item => `
    <div class="case-item ${state.selectedId === item.request_id ? 'active' : ''}" data-id="${item.request_id}">
      <label class="case-select-row">
        <input type="checkbox" class="case-selector" data-id="${item.request_id}" ${state.selectedCaseIds.has(item.request_id) ? 'checked' : ''} />
        <span>Select</span>
      </label>
      <button type="button" class="case-open" data-id="${item.request_id}">
        <div class="case-top">
          <strong>${item.route.toUpperCase()} | ${item.fraud_score}</strong>
          <span class="badge ${item.action}">${item.action}</span>
        </div>
        <div class="case-meta">${item.user_id || 'unknown user'} | ${item.case_status}${item.assigned_to ? ` | ${item.assigned_to}` : ''}</div>
        <div class="case-meta">${item.reasons.join(' | ')}</div>
      </button>
      <div class="button-row">
        <button type="button" class="ghost small queue-action-btn" data-id="${item.request_id}" data-status="INVESTIGATING">Investigate</button>
        <button type="button" class="ghost small queue-action-btn" data-id="${item.request_id}" data-status="RESOLVED">Resolve</button>
      </div>
    </div>
  `).join('');
  document.querySelectorAll('.case-open').forEach(node => node.addEventListener('click', () => loadCase(node.dataset.id)));
  document.querySelectorAll('.case-selector').forEach(node => node.addEventListener('change', event => toggleCaseSelection(event)));
  document.querySelectorAll('.queue-action-btn').forEach(node => node.addEventListener('click', event => quickUpdateCaseStatus(event)));
}

function renderCaseQueueStats(items) {
  const counts = { OPEN: 0, INVESTIGATING: 0, RESOLVED: 0 };
  for (const item of items) {
    if (counts[item.case_status] !== undefined) {
      counts[item.case_status] += 1;
    }
  }
  els.caseQueueStats.innerHTML = `
    <div class="signal-item">
      <div>
        <strong>Queue snapshot</strong>
        <div class="case-meta">${items.length} visible cases | ${state.selectedCaseIds.size} selected</div>
      </div>
      <div>Open ${counts.OPEN}</div>
    </div>
    <div class="signal-item">
      <div>
        <strong>Investigating</strong>
        <div class="case-meta">In-progress analyst work</div>
      </div>
      <div>${counts.INVESTIGATING}</div>
    </div>
    <div class="signal-item">
      <div>
        <strong>Resolved</strong>
        <div class="case-meta">Closed queue items</div>
      </div>
      <div>${counts.RESOLVED}</div>
    </div>
  `;
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
        <div class="case-meta">${item.key_prefix} | ${item.is_active ? 'active' : 'inactive'}</div>
      </div>
      <div>${item.last_used_at ? formatDate(item.last_used_at) : 'unused'}</div>
    </div>
  `).join('') || '<div class="empty-state">No API keys yet.</div>';
}

function renderAnalysts(items) {
  if (!items) {
    els.analysts.innerHTML = '<div class="empty-state">Admin or service access required.</div>';
    renderAnalystDirectory([]);
    syncAdminControls();
    return;
  }
  state.analysts = items;
  renderAnalystDirectory(items);
  syncAdminControls();
  els.analysts.innerHTML = items.map(item => `
    <div class="signal-item analyst-card">
      <div class="signal-stack">
        <div class="shadow-route-top">
          <strong>${item.full_name}</strong>
          <span class="badge ${item.is_active ? 'SUCCEEDED' : 'FAILED'}">${item.is_active ? 'active' : 'inactive'}</span>
        </div>
        <div class="case-meta">${item.email} | ${item.role}</div>
        <div class="case-meta">Created ${formatDate(item.created_at)}${item.last_login_at ? ` | last login ${formatDate(item.last_login_at)}` : ' | never logged in'}</div>
      </div>
      <div class="actions">
        <button class="ghost small analyst-assign-btn" data-identity="${analystIdentity(item)}">Assign</button>
        ${isAdminLike() ? `<button class="ghost small analyst-status-btn" data-analyst-id="${item.analyst_id}" data-is-active="${item.is_active ? '1' : '0'}">${item.is_active ? 'Deactivate' : 'Reactivate'}</button>` : ''}
      </div>
    </div>
  `).join('') || '<div class="empty-state">No analysts created yet.</div>';
  document.querySelectorAll('.analyst-status-btn').forEach(node => node.addEventListener('click', () => toggleAnalystStatus(node.dataset.analystId, node.dataset.isActive === '1')));
  document.querySelectorAll('.analyst-assign-btn').forEach(node => node.addEventListener('click', () => assignAnalystIdentity(node.dataset.identity)));
}

function renderModels(items, summary = null) {
  if (!items) {
    els.models.innerHTML = '<div class="empty-state">Model registry requires ops access.</div>';
    return;
  }
  const evalMap = summary?.models || {};
  els.models.innerHTML = items.map(item => {
    const evalInfo = evalMap[item.model_name] || null;
    return `
      <div class="signal-item">
        <div>
          <strong>${item.model_name}</strong>
          <div class="case-meta">${item.version_id} | ${item.stage}${item.is_active ? ' | active' : ''}</div>
          <div class="case-meta">f1 ${formatMetricValue(item.metrics.f1)} | auc ${formatMetricValue(item.metrics.auc)} | acc ${formatMetricValue(item.metrics.accuracy)}</div>
          <div class="case-meta">Training job ${item.training_job_id || 'manual'} | created ${formatDate(item.created_at)}</div>
          <div class="case-meta dataset-path">artifact ${basename(item.artifact_path)}</div>
        </div>
        <div class="actions">
          <span class="badge ${item.is_active ? 'SUCCEEDED' : 'QUEUED'}">${item.is_active ? 'ACTIVE' : item.stage.toUpperCase()}</span>
          ${evalInfo ? `<span class="graph-pill ${evalInfo.version_id === item.version_id ? 'good' : 'warn'}">eval ${evalInfo.version_id === item.version_id ? 'matches' : 'differs'}</span>` : '<span class="graph-pill">no eval</span>'}
          ${isAdminLike() && !item.is_active ? `<button class="ghost small activate-model-btn" data-model-name="${item.model_name}" data-version-id="${item.version_id}">Promote</button>` : ''}
        </div>
      </div>
    `;
  }).join('') || '<div class="empty-state">No model versions recorded yet.</div>';
  document.querySelectorAll('.activate-model-btn').forEach(node => node.addEventListener('click', async () => activateModel(node.dataset.modelName, node.dataset.versionId)));
}

function renderModelSummary(summary, models = []) {
  state.modelEvaluationSummary = summary || null;
  if (!summary) {
    els.modelSummary.innerHTML = '<div class="empty-state">Model evaluation summary is not available yet.</div>';
    return;
  }
  const items = Object.entries(summary.models || {});
  const activeByName = Object.fromEntries((models || []).filter(item => item.is_active).map(item => [item.model_name, item]));
  const headline = `
    <div class="signal-item model-summary-item detail-callout">
      <div>
        <strong>Evaluation snapshot</strong>
        <div class="case-meta">Generated ${formatDate(summary.generated_at)}</div>
      </div>
      <div>${items.length} models</div>
    </div>
  `;
  const cards = items.map(([modelName, info]) => {
    const metrics = info.metrics || {};
    const active = activeByName[modelName];
    const versionAligned = active ? active.version_id === info.version_id : false;
    const falsePositiveRate = computeFalsePositiveRate(metrics);
    return `
      <div class="signal-item model-summary-item detail-callout">
        <div>
          <strong>${modelName}</strong>
          <div class="case-meta">eval ${info.version_id}</div>
          <div class="case-meta dataset-path">${info.artifact_path}</div>
          <div class="case-meta">${active ? `active ${active.version_id}` : 'not promoted'}${active ? ` | ${versionAligned ? 'aligned with eval' : 'eval differs from active'}` : ''}</div>
          <div class="case-meta">samples ${metrics.total_test_samples ?? 'n/a'} | fraud positives ${metrics.positive_support ?? 'n/a'} | clean negatives ${metrics.negative_support ?? 'n/a'}</div>
          <div class="case-meta">TP ${metrics.true_positives ?? 'n/a'} | FP ${metrics.false_positives ?? 'n/a'} | TN ${metrics.true_negatives ?? 'n/a'} | FN ${metrics.false_negatives ?? 'n/a'}</div>
        </div>
        <div class="model-metrics-grid">
          <span>AUC <strong>${formatMetricValue(metrics.auc)}</strong></span>
          <span>F1 <strong>${formatMetricValue(metrics.f1)}</strong></span>
          <span>Precision <strong>${formatMetricValue(metrics.precision)}</strong></span>
          <span>Recall / TPR <strong>${formatRate(metrics.recall)}</strong></span>
          <span>Accuracy <strong>${formatRate(metrics.accuracy)}</strong></span>
          <span>FPR <strong>${formatRate(falsePositiveRate)}</strong></span>
        </div>
      </div>
    `;
  }).join('');
  els.modelSummary.innerHTML = headline + (cards || '<div class="empty-state">No model evaluation data found.</div>');
}

function renderShadowSummary(summary) {
  if (!summary) {
    els.shadowSummary.innerHTML = '<div class="empty-state">Shadow comparison data requires ops access.</div>';
    return;
  }
  const routeRows = (summary.route_breakdown || []).map(item => `
    <div class="shadow-route-card">
      <div class="shadow-route-top">
        <strong>${item.route}</strong>
        <span class="badge ${item.diverged ? 'CHALLENGE' : 'ALLOW'}">${(item.divergence_rate * 100).toFixed(1)}% drift</span>
      </div>
      <div class="case-meta">${item.diverged}/${item.total} diverged</div>
      <div class="case-meta">Average delta ${formatSignedMetricValue(item.avg_score_delta, 2)}</div>
    </div>
  `).join('');
  els.shadowSummary.innerHTML = `
    <div class="kpi-strip">
      <div class="kpi-chip">
        <span>Challenger</span>
        <strong>${summary.challenger_version}</strong>
      </div>
      <div class="kpi-chip">
        <span>Compared</span>
        <strong>${summary.total}</strong>
      </div>
      <div class="kpi-chip ${summary.diverged ? 'warn' : 'good'}">
        <span>Decision drifts</span>
        <strong>${summary.diverged}</strong>
      </div>
      <div class="kpi-chip">
        <span>Divergence rate</span>
        <strong>${(summary.divergence_rate * 100).toFixed(1)}%</strong>
      </div>
    </div>
    <div class="shadow-route-grid">${routeRows || '<div class="empty-state">No shadow route data yet.</div>'}</div>
  `;
}

function renderShadowDecisions(items) {
  if (!items) {
    els.shadowDecisions.innerHTML = '<div class="empty-state">Shadow drift data requires ops access.</div>';
    return;
  }
  els.shadowDecisions.innerHTML = items.map(item => `
    <div class="signal-item shadow-drift-card">
      <div class="signal-stack">
        <div class="shadow-route-top">
          <strong>${item.route} | ${item.request_id}</strong>
          <span class="badge ${item.diverged ? 'CHALLENGE' : 'ALLOW'}">${item.diverged ? 'drift' : 'match'}</span>
        </div>
        <div class="detail-badges">
          <span class="graph-pill warn">Prod ${item.production_action} ${item.production_score}</span>
          <span class="graph-pill good">Challenger ${item.shadow_action} ${item.shadow_score}</span>
          <span class="graph-pill ${item.delta_score > 0 ? 'warn' : 'good'}">Delta ${formatSignedMetricValue(item.delta_score, 0)}</span>
        </div>
        <div class="case-meta">${(item.shadow_reasons || []).join(' | ') || 'No challenger reasons recorded'}</div>
      </div>
      <div class="actions">
        <button class="ghost small shadow-case-open" data-request-id="${item.request_id}">Open Case</button>
      </div>
    </div>
  `).join('') || '<div class="empty-state">No shadow decisions recorded yet.</div>';
  document.querySelectorAll('.shadow-case-open').forEach(node => node.addEventListener('click', () => loadCase(node.dataset.requestId)));
}

function renderPilotReport(report) {
  if (!report) {
    els.pilotReport.innerHTML = '<div class="empty-state">Pilot report requires ops access.</div>';
    return;
  }
  const stats = [
    ['Compared events', report.compared_events],
    ['Production blocks', report.production_blocks],
    ['Challenger blocks', report.challenger_blocks],
    ['Incremental blocks', report.incremental_blocks],
    ['Open cases', report.open_cases],
    ['Labeled cases', report.labeled_cases],
  ].map(([label, value]) => `
    <div class="pilot-stat-card">
      <span>${label}</span>
      <strong>${value}</strong>
      <div class="case-meta">${report.challenger_version}</div>
    </div>
  `).join('');
  const notes = (report.notes || []).map(note => `
    <div class="signal-item pilot-note">
      <div>
        <strong>Pilot note</strong>
        <div class="case-meta">${note}</div>
      </div>
    </div>
  `).join('');
  els.pilotReport.innerHTML = `
    <div class="kpi-strip">
      <div class="kpi-chip">
        <span>Challenger</span>
        <strong>${report.challenger_version}</strong>
      </div>
      <div class="kpi-chip ${report.incremental_blocks > 0 ? 'warn' : 'good'}">
        <span>Incremental blocks</span>
        <strong>${report.incremental_blocks}</strong>
      </div>
      <div class="kpi-chip">
        <span>Divergence rate</span>
        <strong>${formatRate(report.divergence_rate, 1)}</strong>
      </div>
    </div>
    <div class="pilot-stat-grid">${stats}</div>
    ${notes}
  `;
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
        <div class="case-meta">Attempts ${item.attempts}/${item.max_attempts} | run after ${formatDate(item.run_after)}</div>
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
        <div class="case-meta">retry ${item.retry_count}/${item.max_attempts}${item.last_http_status ? ` | http ${item.last_http_status}` : ''}</div>
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
        <div class="case-meta">${item.connector_type} | ${item.source_path}</div>
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
        <div class="case-meta">${item.actor_id || 'system'} | ${item.actor_role || 'n/a'}</div>
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
      refreshCustomSelect(els.graphEntityType);
      els.graphEntityId.value = node.dataset.entityId;
      await loadGraphEntity(node.dataset.entityType, node.dataset.entityId);
    });
  });
}

function formatActivityDetails(details) {
  const entries = Object.entries(details || {});
  if (!entries.length) {
    return 'No structured details';
  }
  return entries.map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(', ') : value}`).join(' | ');
}

function formatLinkedSignal(signal) {
  return signal.replace('shared_', 'Shared ').replaceAll('_', ' ');
}

function formatModelSource(source) {
  return (source || 'unknown').replaceAll('_', ' ');
}

function formatSignedMetricValue(value, digits = 4) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) {
    return 'n/a';
  }
  const numeric = Number(value);
  const sign = numeric > 0 ? '+' : '';
  return `${sign}${numeric.toFixed(digits)}`;
}

function formatRate(value, digits = 3) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) {
    return 'n/a';
  }
  return `${(Number(value) * 100).toFixed(digits)}%`;
}

function computeFalsePositiveRate(metrics = {}) {
  if (metrics.false_positives !== undefined && metrics.true_negatives !== undefined) {
    const denominator = Number(metrics.false_positives) + Number(metrics.true_negatives);
    if (denominator > 0) {
      return Number(metrics.false_positives) / denominator;
    }
  }
  return metrics.false_positive_rate ?? null;
}

function describeShadowDecision(shadow) {
  const delta = Number(shadow?.delta_score || 0);
  const prodAction = shadow?.production_action || 'REVIEW';
  const challengerAction = shadow?.shadow_action || 'REVIEW';

  if (prodAction !== challengerAction) {
    if (challengerAction === 'BLOCK') {
      return 'Challenger interpretation: stricter policy, would escalate this case to block.';
    }
    if (challengerAction === 'CHALLENGE') {
      return 'Challenger interpretation: stricter policy, would step this case up for analyst challenge.';
    }
    return 'Challenger interpretation: less severe policy, would de-escalate this case versus production.';
  }

  if (Math.abs(delta) >= 0.15) {
    return `Challenger interpretation: same action, but material score drift (${formatSignedMetricValue(delta, 3)}) suggests threshold sensitivity.`;
  }
  if (Math.abs(delta) >= 0.05) {
    return `Challenger interpretation: same action with moderate score drift (${formatSignedMetricValue(delta, 3)}). Watch threshold tuning.`;
  }
  return 'Challenger interpretation: stable match with production. No meaningful decision drift.';
}

function graphLinkForSignal(payload, signal) {
  const links = buildGraphLinks(payload || {});
  const signalMap = {
    shared_user: 'user',
    shared_device: 'device',
    shared_payee: 'payee',
    shared_phone: 'phone_hash',
    shared_pan: 'pan_hash',
  };
  const entityType = signalMap[signal];
  if (!entityType) {
    return null;
  }
  return links.find(link => link.entityType === entityType) || null;
}

function bindLinkedCaseActions() {
  document.querySelectorAll('.linked-case-open').forEach(node => {
    node.addEventListener('click', () => loadCase(node.dataset.id));
  });
  document.querySelectorAll('.linked-case-graph-jump').forEach(node => {
    node.addEventListener('click', async () => {
      els.graphEntityType.value = node.dataset.entityType;
      refreshCustomSelect(els.graphEntityType);
      els.graphEntityId.value = node.dataset.entityId;
      await loadGraphEntity(node.dataset.entityType, node.dataset.entityId);
    });
  });
}

async function loadHealth() {
  const health = await api('/health', { headers: {}, body: undefined });
  els.healthState.textContent = `${health.status} | db ${health.database}`;
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
  els.tenantMeta.textContent = `${tenant.tenant_id} | ${tenant.role || 'unknown role'} | via ${tenant.key_name}`;
}

async function loadCase(requestId) {
  state.selectedId = requestId;
  const detail = await api(`/v1/ops/cases/${requestId}`);
  state.selectedCase = detail;
  renderCases(state.cases);
  els.detailEmpty.classList.add('hidden');
  els.detail.classList.remove('hidden');
  els.detailId.textContent = detail.request_id;
  els.detailAction.className = `hero-chip ${detail.action}`;
  els.detailAction.textContent = `${detail.action} | ${detail.fraud_score}`;
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
  if (detail.shadow_comparison) {
    const shadow = detail.shadow_comparison;
    const scoreDelta = Number(shadow.delta_score || 0);
    const shadowReasons = (shadow.shadow_reasons || []).map(reason => `<span class="badge muted">${reason}</span>`).join(' ');
    els.detailShadow.innerHTML = `
      <div class="signal-item model-summary-item detail-callout">
        <div>
          <strong>${shadow.challenger_version || 'challenger'}</strong>
          <div class="case-meta">${describeShadowDecision(shadow)}</div>
          <div class="case-meta">Score delta ${formatSignedMetricValue(scoreDelta, 3)} | ${shadow.diverged ? 'decision drift detected' : 'decision aligned with production'}</div>
          <div class="model-metrics-grid">
            <span>Production <strong>${shadow.production_action}</strong></span>
            <span>Prod score <strong>${formatMetricValue(shadow.production_score, 3)}</strong></span>
            <span>Challenger <strong>${shadow.shadow_action}</strong></span>
            <span>Shadow score <strong>${formatMetricValue(shadow.shadow_score, 3)}</strong></span>
          </div>
          <div class="case-meta">Shadow reasons</div>
          <div>${shadowReasons || '<span class="case-meta">No challenger reasons captured.</span>'}</div>
        </div>
        <div>${shadow.diverged ? 'drift' : 'match'}</div>
      </div>
    `;
  } else {
    els.detailShadow.innerHTML = '<div class="empty-state">No shadow comparison recorded for this case.</div>';
  }
  els.caseStatus.value = detail.case_status;
  refreshCustomSelect(els.caseStatus);
  els.caseAssignee.value = detail.assigned_to || '';
  els.feedbackNotes.value = detail.feedback_notes || '';
  if (detail.feedback_label) {
    els.feedbackLabel.value = detail.feedback_label;
  }
  refreshCustomSelect(els.feedbackLabel);
  els.detailModelEvidence.innerHTML = (detail.model_evidence || []).map(item => `
    <div class="signal-item model-summary-item detail-callout">
      <div>
        <strong>${item.component}</strong>
        <div class="case-meta">${item.model_name} | ${formatModelSource(item.source)}</div>
        <div class="case-meta">${item.version_id || 'no promoted version'} | ${item.artifact_path || 'no artifact path'}</div>
      </div>
      <div class="model-metrics-grid">
        <span>Used <strong>${item.model_used ? 'yes' : 'no'}</strong></span>
        <span>Heuristic <strong>${item.heuristic_score}</strong></span>
        <span>Output <strong>${item.output_score}</strong></span>
      </div>
    </div>
  `).join('') || '<div class="empty-state">No model evidence recorded for this case.</div>';
  els.detailPayload.textContent = JSON.stringify(detail.request_payload, null, 2);
  els.detailActivity.innerHTML = (detail.activity || []).map(item => `
    <div class="signal-item">
      <div>
        <strong>${item.event_type}</strong>
        <div class="case-meta">${item.actor_id || 'system'} | ${formatDate(item.created_at)}</div>
        <div class="case-meta">${formatActivityDetails(item.details)}</div>
      </div>
    </div>
  `).join('') || '<div class="empty-state">No case activity recorded yet.</div>';
  els.detailLinkedCases.innerHTML = (detail.linked_cases || []).map(item => {
    const graphButtons = item.matched_signals.map(signal => {
      const link = graphLinkForSignal(detail.request_payload, signal);
      if (!link) {
        return '';
      }
      return `<button type="button" class="ghost small linked-case-graph-jump" data-entity-type="${link.entityType}" data-entity-id="${link.entityId}">Inspect ${formatLinkedSignal(signal)}</button>`;
    }).filter(Boolean).join('');
    return `
      <div class="signal-item">
        <div>
          <strong>${item.route.toUpperCase()} | ${item.fraud_score}</strong>
          <div class="case-meta">${item.request_id}</div>
          <div class="case-meta">${item.case_status}${item.assigned_to ? ` | ${item.assigned_to}` : ''}</div>
          <div class="case-meta">${item.matched_signals.map(formatLinkedSignal).join(' | ')}</div>
        </div>
        <div class="actions">
          <button type="button" class="ghost small linked-case-open" data-id="${item.request_id}">Open</button>
          ${graphButtons}
        </div>
      </div>
    `;
  }).join('') || '<div class="empty-state">No linked cases found for this request.</div>';
  bindLinkedCaseActions();
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
  const search = els.caseSearch.value.trim();
  await Promise.all([loadHealth(), loadPrincipal(), loadTenant()]);
  const summary = await api('/v1/ops/summary');
  const [cases, monitoring, jobs, models, webhooks, connectors, analysts, apiKeys, securityAudit, datasets, modelSummary, shadowSummary, shadowDecisions, pilotReport] = await Promise.all([
    api(`/v1/ops/cases?limit=30${action ? `&action=${encodeURIComponent(action)}` : ''}${caseStatus ? `&case_status=${encodeURIComponent(caseStatus)}` : ''}${search ? `&search=${encodeURIComponent(search)}` : ''}`),
    safeApi('/v1/ops/monitoring'),
    safeApi('/v1/ops/jobs?limit=10'),
    safeApi('/v1/ops/models?limit=10'),
    safeApi('/v1/ops/webhook-deliveries?limit=10'),
    safeApi('/v1/ops/connectors'),
    safeApi('/v1/ops/analysts'),
    safeApi('/v1/ops/api-keys'),
    safeApi('/v1/ops/security-audit?limit=10'),
    safeApi('/v1/ops/datasets'),
    safeApi('/v1/ops/model-evaluation-summary'),
    safeApi('/v1/ops/shadow-summary'),
    safeApi('/v1/ops/shadow-decisions?limit=6&diverged_only=true'),
    safeApi('/v1/ops/pilot-report'),
  ]);

  renderMetrics(summary.metrics, monitoring);
  renderSignals(summary.top_signals);
  renderCases(cases?.items || []);
  renderMonitoring(monitoring);
  renderDatasets(datasets);
  renderJobs(jobs);
  renderModelSummary(modelSummary, models || []);
  renderShadowSummary(shadowSummary);
  renderShadowDecisions(shadowDecisions?.items || []);
  renderPilotReport(pilotReport);
  renderModels(models, modelSummary);
  renderWebhookDeliveries(webhooks);
  renderConnectors(connectors);
  renderAnalysts(analysts);
  renderApiKeys(apiKeys);
  renderSecurityAudit(securityAudit);

  els.lastRefresh.textContent = `Refreshed ${new Date().toLocaleTimeString()}`;
  setStatus(`Loaded ${cases?.items?.length || 0} cases${search ? ` for ${search}` : ''}`);
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

async function createAnalyst(event) {
  event.preventDefault();
  await api('/v1/ops/analysts', {
    method: 'POST',
    body: JSON.stringify({
      full_name: els.analystFullName.value.trim(),
      email: els.analystCreateEmail.value.trim(),
      password: els.analystCreatePassword.value,
      role: els.analystCreateRole.value,
    }),
  });
  setStatus(`Analyst ${els.analystCreateEmail.value.trim()} created`);
  els.analystCreateForm.reset();
  refreshCustomSelect(els.analystCreateRole);
  await loadSummary();
}

async function toggleAnalystStatus(analystId, currentlyActive) {
  await api(`/v1/ops/analysts/${encodeURIComponent(analystId)}/status`, {
    method: 'PATCH',
    body: JSON.stringify({ is_active: !currentlyActive }),
  });
  setStatus(`Analyst ${currentlyActive ? 'deactivated' : 'reactivated'}`, 'neutral');
  await loadSummary();
}

function assignAnalystIdentity(identity) {
  if (!identity) return;
  if (els.caseAssignee) {
    els.caseAssignee.value = identity;
  }
  if (els.bulkAssignee) {
    els.bulkAssignee.value = identity;
  }
  setStatus(`Prepared assignment for ${identity}`, 'neutral');
}

function assignCurrentUser() {
  const identity = state.principal?.email || state.principal?.actor_id || '';
  if (!identity) {
    throw new Error('No current analyst identity available for assignment');
  }
  assignAnalystIdentity(identity);
}

function clearAssigneeInputs() {
  if (els.caseAssignee) {
    els.caseAssignee.value = '';
  }
  if (els.bulkAssignee) {
    els.bulkAssignee.value = '';
  }
  setStatus('Assignment cleared', 'neutral');
}

function toggleCaseSelection(event) {
  const requestId = event.target.dataset.id;
  if (!requestId) {
    return;
  }
  if (event.target.checked) {
    state.selectedCaseIds.add(requestId);
  } else {
    state.selectedCaseIds.delete(requestId);
  }
  renderCaseQueueStats(state.cases);
  setStatus(`${state.selectedCaseIds.size} cases selected`, 'neutral');
}

async function applyBulkCaseStatus() {
  const requestIds = Array.from(state.selectedCaseIds);
  if (!requestIds.length) {
    throw new Error('Select at least one case first');
  }
  const payload = await api('/v1/ops/cases/bulk-status', {
    method: 'POST',
    body: JSON.stringify({
      request_ids: requestIds,
      case_status: els.bulkCaseStatus.value,
      assigned_to: els.bulkAssignee.value || null,
    }),
  });
  setStatus(`Bulk updated ${payload.updated} cases`, 'neutral');
  state.selectedCaseIds.clear();
  await loadSummary();
  if (state.selectedId) {
    await loadCase(state.selectedId);
  }
}

function clearCaseSelection() {
  state.selectedCaseIds.clear();
  renderCases(state.cases);
  setStatus('Case selection cleared', 'neutral');
}

async function quickUpdateCaseStatus(event) {
  const requestId = event.target.dataset.id;
  const caseStatus = event.target.dataset.status;
  if (!requestId || !caseStatus) {
    return;
  }
  const current = state.cases.find(item => item.request_id === requestId);
  await api(`/v1/ops/cases/${requestId}/status`, {
    method: 'PATCH',
    body: JSON.stringify({ case_status: caseStatus, assigned_to: current?.assigned_to || null }),
  });
  setStatus(`Case ${requestId} marked ${caseStatus.toLowerCase()}`, 'neutral');
  await loadSummary();
  if (state.selectedId === requestId) {
    await loadCase(requestId);
  }
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
      <strong>${result.action} | ${result.fraud_score}</strong>
      <div class="case-meta">${result.reasons.join(' | ')}</div>
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




async function exportShadowDecisions() {
  const response = await fetch('/v1/ops/shadow-decisions/export?limit=250&diverged_only=true', {
    headers: authHeaders(false),
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `Request failed: ${response.status}`);
  }
  const blob = await response.blob();
  const url = window.URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  const disposition = response.headers.get('content-disposition') || '';
  const match = disposition.match(/filename=\"?([^\";]+)\"?/i);
  anchor.href = url;
  anchor.download = match ? match[1] : 'shadow_decisions.csv';
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.URL.revokeObjectURL(url);
  setStatus('Shadow decisions exported', 'neutral');
}

async function exportCaseActivity() {
  if (!state.selectedId) {
    throw new Error('Select a case first');
  }
  const response = await fetch(`/v1/ops/cases/${encodeURIComponent(state.selectedId)}/activity/export`, {
    headers: authHeaders(false),
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `Request failed: ${response.status}`);
  }
  const blob = await response.blob();
  const url = window.URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  const disposition = response.headers.get('content-disposition') || '';
  const match = disposition.match(/filename="?([^";]+)"?/i);
  anchor.href = url;
  anchor.download = match ? match[1] : 'case_activity.csv';
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.URL.revokeObjectURL(url);
  setStatus('Case timeline exported', 'neutral');
}

async function exportCaseQueue() {
  const action = els.caseActionFilter.value;
  const caseStatus = els.caseStatusFilter.value;
  const search = els.caseSearch.value.trim();
  const query = new URLSearchParams({ limit: '250' });
  if (action) {
    query.set('action', action);
  }
  if (caseStatus) {
    query.set('case_status', caseStatus);
  }
  if (search) {
    query.set('search', search);
  }
  const response = await fetch(`/v1/ops/cases/export?${query.toString()}`, {
    headers: authHeaders(false),
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `Request failed: ${response.status}`);
  }
  const blob = await response.blob();
  const url = window.URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  const disposition = response.headers.get('content-disposition') || '';
  const match = disposition.match(/filename="?([^";]+)"?/i);
  anchor.href = url;
  anchor.download = match ? match[1] : 'case_queue.csv';
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.URL.revokeObjectURL(url);
  setStatus('Case queue exported', 'neutral');
}

async function exportCaseReport() {
  if (!state.selectedId) {
    throw new Error('Select a case first');
  }
  const response = await fetch(`/v1/ops/cases/${encodeURIComponent(state.selectedId)}/export`, {
    headers: authHeaders(false),
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `Request failed: ${response.status}`);
  }
  const blob = await response.blob();
  const url = window.URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  const disposition = response.headers.get('content-disposition') || '';
  const match = disposition.match(/filename="?([^";]+)"?/i);
  anchor.href = url;
  anchor.download = match ? match[1] : 'case_report.md';
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.URL.revokeObjectURL(url);
  setStatus('Case report exported', 'neutral');
}

async function exportPilotReport() {
  const response = await fetch('/v1/ops/pilot-report/export', {
    headers: authHeaders(false),
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `Request failed: ${response.status}`);
  }
  const blob = await response.blob();
  const url = window.URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  const disposition = response.headers.get('content-disposition') || '';
  const match = disposition.match(/filename="?([^";]+)"?/i);
  anchor.href = url;
  anchor.download = match ? match[1] : 'pilot_report.md';
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.URL.revokeObjectURL(url);
  setStatus('Pilot report exported', 'neutral');
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

function on(node, eventName, handler) {
  if (node) {
    node.addEventListener(eventName, handler);
  }
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

on(els.authMode, 'change', syncAuthMode);
on(els.connectBtn, 'click', () => connect().catch(handleError));
on(els.bootstrapBtn, 'click', () => bootstrapAdmin().catch(handleError));
on(els.seedBtn, 'click', () => seedDemo().catch(handleError));
on(els.dispatchBtn, 'click', () => dispatchWebhooks().catch(handleError));
on(els.exportPilotReportBtn, 'click', () => exportPilotReport().catch(handleError));
on(els.exportShadowBtn, 'click', () => exportShadowDecisions().catch(handleError));
on(els.refreshBtn, 'click', () => loadSummary().catch(handleError));
on(els.autoRefreshBtn, 'click', toggleAutoRefresh);
on(els.enqueueRetrainingBtn, 'click', () => enqueueRetraining().catch(handleError));
on(els.newKeyBtn, 'click', () => createApiKey().catch(handleError));
on(els.saveStatusBtn, 'click', () => saveCaseStatus().catch(handleError));
on(els.exportCaseBtn, 'click', () => exportCaseReport().catch(handleError));
on(els.exportCasesBtn, 'click', () => exportCaseQueue().catch(handleError));
on(els.applyBulkCasesBtn, 'click', () => applyBulkCaseStatus().catch(handleError));
on(els.clearCaseSelectionBtn, 'click', clearCaseSelection);
on(els.assignMeBtn, 'click', () => { try { assignCurrentUser(); } catch (error) { handleError(error); } });
on(els.clearAssigneeBtn, 'click', clearAssigneeInputs);
on(els.exportActivityBtn, 'click', () => exportCaseActivity().catch(handleError));
on(els.analystCreateForm, 'submit', event => createAnalyst(event).catch(handleError));
on(els.feedbackForm, 'submit', event => saveFeedback(event).catch(handleError));
on(els.phishingForm, 'submit', event => submitPhishing(event).catch(handleError));
on(els.graphForm, 'submit', event => submitGraphLookup(event).catch(handleError));
on(els.connectorForm, 'submit', event => createConnector(event).catch(handleError));
on(els.caseActionFilter, 'change', () => loadSummary().catch(handleError));
on(els.caseStatusFilter, 'change', () => loadSummary().catch(handleError));
on(els.caseSearch, 'input', () => loadSummary().catch(handleError));

function handleError(error) {
  console.error(error);
  setStatus(String(error.message || error).slice(0, 160), 'neutral');
}

initCustomSelects();
syncAuthMode();
loadSummary().catch(error => {
  console.error(error);
  setStatus('Connect with a valid API key or analyst login', 'neutral');
});


















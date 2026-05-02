/* ── Config ─────────────────────────────────────────────────────────── */
const API = {
  gateway:    'http://localhost:8080',
  ingestion:  'http://localhost:8081',
  analytics:  'http://localhost:8086',
  database:   'http://localhost:8085',
};

const SERVICES = [
  { name: 'API Gateway',        port: 8080, path: '/gateway/health',           color: '#3b82f6', endpoints: ['/gateway/health', '/gateway/routes'] },
  { name: 'Ingestion Service',  port: 8081, path: '/api/v1/ingest/health',     color: '#ef4444', endpoints: ['/api/v1/ingest/abuseipdb', '/api/v1/ingest/alienvault', '/api/v1/ingest/all'] },
  { name: 'Extraction Service', port: 8082, path: '/api/v1/extract/health',    color: '#a855f7', endpoints: ['/api/v1/extract/**'] },
  { name: 'Processing Service', port: 8083, path: '/api/v1/processing/health', color: '#f97316', endpoints: ['/api/v1/processing/iocs', '/api/v1/processing/iocs/top'] },
  { name: 'Ranking Service',    port: 8084, path: '/api/v1/rank/health',       color: '#ef4444', endpoints: ['/api/v1/rank/health', '/api/v1/rank/run'] },
  { name: 'Database Service',   port: 8085, path: '/api/v1/db/health',         color: '#22c55e', endpoints: ['/api/v1/db/iocs', '/api/v1/db/stats'] },
  { name: 'Analytics Service',  port: 8086, path: '/api/v1/analytics/health',  color: '#6366f1', endpoints: ['/api/v1/analytics/summary', '/api/v1/analytics/top-threats'] },
];

/* ── State ──────────────────────────────────────────────────────────── */
let charts = {};
let allIocs = [];
let currentPage = 'dashboard';

/* ── Helpers ─────────────────────────────────────────────────────────── */
async function apiFetch(baseUrl, path) {
  const res = await fetch(baseUrl + path);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

function toast(msg, type = 'info') {
  const c = document.getElementById('toast-container');
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.innerHTML = `<span>${msg}</span>`;
  c.appendChild(el);
  setTimeout(() => el.remove(), 3500);
}

function severityBadge(s) {
  if (!s) return '<span class="badge badge-pending">Unknown</span>';
  const map = { CRITICAL:'badge-critical', HIGH:'badge-high', MEDIUM:'badge-medium', LOW:'badge-low' };
  return `<span class="badge ${map[s] || 'badge-pending'}">${s}</span>`;
}

function statusBadge(s) {
  const map = { PENDING:'badge-pending', VALIDATED:'badge-validated', RANKED:'badge-ranked', FAILED:'badge-failed' };
  return `<span class="badge ${map[s] || 'badge-pending'}">${s || '—'}</span>`;
}

function typeBadge(t) {
  return `<span class="badge ${t==='IP'?'badge-ip':'badge-domain'}">${t}</span>`;
}

function scoreColor(n) {
  if (n >= 90) return '#ef4444';
  if (n >= 70) return '#f97316';
  if (n >= 40) return '#eab308';
  return '#22c55e';
}

function scoreBar(score) {
  const c = scoreColor(score);
  return `<div class="score-cell">
    <span style="color:${c};font-weight:700">${score}</span>
    <div class="score-bar-wrap"><div class="score-bar" style="width:${score}%;background:${c}"></div></div>
  </div>`;
}

function formatDate(d) {
  if (!d) return '—';
  return new Date(d).toLocaleDateString('en-US', { month:'short', day:'numeric', hour:'2-digit', minute:'2-digit' });
}

function destroyChart(key) {
  if (charts[key]) { charts[key].destroy(); delete charts[key]; }
}

/* ── Chart theme ────────────────────────────────────────────────────── */
Chart.defaults.color = '#64748b';
Chart.defaults.borderColor = 'rgba(255,255,255,0.07)';
Chart.defaults.font.family = "'Inter', sans-serif";

function makeDonut(id, labels, data, colors) {
  destroyChart(id);
  const ctx = document.getElementById(id);
  if (!ctx) return;
  charts[id] = new Chart(ctx, {
    type: 'doughnut',
    data: { labels, datasets: [{ data, backgroundColor: colors, borderWidth: 0, hoverOffset: 6 }] },
    options: {
      responsive: true, maintainAspectRatio: false, cutout: '68%',
      plugins: { legend: { position: 'bottom', labels: { padding: 14, boxWidth: 10, font: { size: 11 } } }, tooltip: { callbacks: { label: ctx => ` ${ctx.label}: ${ctx.raw}` } } }
    }
  });
}

function makeBar(id, labels, data, colors) {
  destroyChart(id);
  const ctx = document.getElementById(id);
  if (!ctx) return;
  charts[id] = new Chart(ctx, {
    type: 'bar',
    data: { labels, datasets: [{ data, backgroundColor: colors, borderRadius: 6, borderSkipped: false }] },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false }, ticks: { font: { size: 11 } } },
        y: { grid: { color: 'rgba(255,255,255,0.05)' }, beginAtZero: true, ticks: { font: { size: 11 } } }
      }
    }
  });
}

function makeLine(id, labels, data) {
  destroyChart(id);
  const ctx = document.getElementById(id);
  if (!ctx) return;
  charts[id] = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        data, fill: true,
        backgroundColor: 'rgba(59,130,246,0.08)',
        borderColor: '#3b82f6', borderWidth: 2.5,
        pointBackgroundColor: '#3b82f6', pointRadius: 4,
        tension: 0.4
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false }, ticks: { font: { size: 11 } } },
        y: { grid: { color: 'rgba(255,255,255,0.05)' }, beginAtZero: true, ticks: { precision: 0 } }
      }
    }
  });
}

/* ── Navigation ─────────────────────────────────────────────────────── */
function navigate(page) {
  currentPage = page;
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById(`page-${page}`)?.classList.add('active');
  document.getElementById(`nav-${page}`)?.classList.add('active');

  const titles = { dashboard: ['Dashboard', 'Threat Intelligence Overview'], iocs: ['IOC Explorer', 'Browse & filter all IOC records'], ingest: ['Ingestion Control', 'Trigger data pipeline from external APIs'], analytics: ['Analytics', 'Deep-dive trend analysis'], services: ['Service Health', 'Microservice status & endpoints'] };
  const [t, s] = titles[page] || ['', ''];
  document.getElementById('page-title').textContent = t;
  document.getElementById('page-subtitle').textContent = s;

  if (page === 'dashboard')  loadDashboard();
  if (page === 'iocs')       loadIocs();
  if (page === 'analytics')  loadAnalytics();
  if (page === 'services')   loadServices();
}

document.querySelectorAll('.nav-item').forEach(el => {
  el.addEventListener('click', e => { e.preventDefault(); navigate(el.dataset.page); });
});

document.getElementById('refresh-btn').addEventListener('click', () => {
  const btn = document.getElementById('refresh-btn');
  btn.disabled = true;
  navigate(currentPage);
  setTimeout(() => btn.disabled = false, 1500);
});

/* ── Gateway health check ───────────────────────────────────────────── */
async function checkGateway() {
  const dot  = document.querySelector('#gateway-status-badge .status-dot');
  const text = document.getElementById('gateway-status-text');
  try {
    await apiFetch(API.gateway, '/gateway/health');
    dot.className  = 'status-dot dot-up';
    text.textContent = 'Gateway UP';
  } catch {
    dot.className  = 'status-dot dot-down';
    text.textContent = 'Gateway DOWN';
  }
}

/* ── Dashboard ──────────────────────────────────────────────────────── */
async function loadDashboard() {
  try {
    const [summary, severity, source, type, top, country] = await Promise.allSettled([
      apiFetch(API.analytics, '/api/v1/analytics/summary'),
      apiFetch(API.analytics, '/api/v1/analytics/by-severity'),
      apiFetch(API.analytics, '/api/v1/analytics/by-source'),
      apiFetch(API.analytics, '/api/v1/analytics/by-type'),
      apiFetch(API.analytics, '/api/v1/analytics/top-threats?limit=15'),
      apiFetch(API.analytics, '/api/v1/analytics/by-country?limit=8'),
    ]);

    if (summary.status === 'fulfilled') {
      const d = summary.value;
      document.getElementById('kpi-total-val').textContent   = d.totalIocs ?? '—';
      document.getElementById('kpi-critical-val').textContent = d.critical  ?? '—';
      document.getElementById('kpi-high-val').textContent     = d.high      ?? '—';
      document.getElementById('kpi-ranked-val').textContent   = d.ranked    ?? '—';
      document.getElementById('kpi-pending-val').textContent  = d.pending   ?? '—';
      document.getElementById('kpi-avg-val').textContent      = d.avgSeverityScore != null ? Number(d.avgSeverityScore).toFixed(1) : '—';
    } else { toast('Analytics service unreachable – check :8086 is running', 'error'); }

    if (severity.status === 'fulfilled') {
      const d = severity.value;
      makeDonut('severity-chart',
        Object.keys(d), Object.values(d),
        ['#ef4444','#f97316','#eab308','#22c55e']);
    }

    if (source.status === 'fulfilled') {
      const d = source.value;
      makeDonut('source-chart', Object.keys(d), Object.values(d), ['#3b82f6','#a855f7']);
    }

    if (type.status === 'fulfilled') {
      const d = type.value;
      makeDonut('type-chart', Object.keys(d), Object.values(d), ['#06b6d4','#6366f1']);
    }

    if (top.status === 'fulfilled') {
      renderTopThreats(top.value);
    }

    if (country.status === 'fulfilled') {
      renderCountries(country.value);
    }

  } catch (err) {
    toast('Dashboard load failed: ' + err.message, 'error');
  }
}

function renderTopThreats(list) {
  const el = document.getElementById('top-threats-list');
  document.getElementById('top-threat-count').textContent = `${list.length} threats`;
  if (!list.length) { el.innerHTML = '<p style="color:var(--text3);text-align:center;padding:1rem">No ranked threats yet</p>'; return; }
  el.innerHTML = list.map(t => `
    <div class="threat-item">
      ${typeBadge(t.type)}
      <span class="threat-value">${t.value}</span>
      ${severityBadge(t.severity)}
      <span class="threat-score" style="color:${scoreColor(t.severityScore)}">${t.severityScore}</span>
    </div>`).join('');
}

function renderCountries(data) {
  const el = document.getElementById('country-list');
  const entries = Object.entries(data);
  if (!entries.length) { el.innerHTML = '<p style="color:var(--text3)">No data</p>'; return; }
  const max = Math.max(...entries.map(e => e[1]));
  el.innerHTML = entries.map(([code, cnt]) => `
    <div class="country-item">
      <span class="country-flag">${countryFlag(code)}</span>
      <span class="country-name">${code || '??'}</span>
      <div class="country-bar-wrap"><div class="country-bar" style="width:${Math.round(cnt/max*100)}%"></div></div>
      <span class="country-count">${cnt}</span>
    </div>`).join('');
}

function countryFlag(code) {
  if (!code || code.length !== 2) return '🌐';
  return String.fromCodePoint(...[...code.toUpperCase()].map(c => 0x1F1E6 - 65 + c.charCodeAt(0)));
}

/* ── IOC Explorer ───────────────────────────────────────────────────── */
async function loadIocs() {
  const tbody = document.getElementById('ioc-tbody');
  tbody.innerHTML = '<tr><td colspan="10" class="table-loading">Loading IOCs…</td></tr>';
  try {
    allIocs = await apiFetch(API.database, '/api/v1/db/iocs');
    renderIocTable(allIocs);
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="10" class="table-loading" style="color:var(--red)">Error: ${err.message}</td></tr>`;
    toast('Database service unreachable – check :8085 is running', 'error');
  }
}

function renderIocTable(data) {
  const badge = document.getElementById('ioc-count-badge');
  badge.textContent = `${data.length} records`;
  const tbody = document.getElementById('ioc-tbody');
  if (!data.length) {
    tbody.innerHTML = '<tr><td colspan="10" class="table-loading">No IOCs found</td></tr>';
    return;
  }
  tbody.innerHTML = data.map(r => `
    <tr>
      <td class="mono" style="color:var(--text3)">#${r.id}</td>
      <td class="mono">${r.value}</td>
      <td>${typeBadge(r.type)}</td>
      <td style="font-size:.8rem">${r.source}</td>
      <td>${severityBadge(r.severity)}</td>
      <td>${scoreBar(r.severityScore || 0)}</td>
      <td>${r.countryCode ? `${countryFlag(r.countryCode)} ${r.countryCode}` : '—'}</td>
      <td>${r.reportCount ?? 0}</td>
      <td>${statusBadge(r.status)}</td>
      <td style="color:var(--text3);font-size:.78rem">${formatDate(r.createdAt)}</td>
    </tr>`).join('');
}

document.getElementById('apply-filters-btn').addEventListener('click', () => {
  const search   = document.getElementById('ioc-search').value.toLowerCase();
  const type     = document.getElementById('filter-type').value;
  const severity = document.getElementById('filter-severity').value;
  const source   = document.getElementById('filter-source').value;

  let filtered = allIocs;
  if (search)   filtered = filtered.filter(r => r.value?.toLowerCase().includes(search) || r.countryCode?.toLowerCase().includes(search));
  if (type)     filtered = filtered.filter(r => r.type === type);
  if (severity) filtered = filtered.filter(r => r.severity === severity);
  if (source)   filtered = filtered.filter(r => r.source?.toLowerCase().includes(source.toLowerCase()));
  renderIocTable(filtered);
});

/* ── Ingestion ──────────────────────────────────────────────────────── */
function bindIngest(btnId, resultId, path) {
  document.getElementById(btnId).addEventListener('click', async () => {
    const btn    = document.getElementById(btnId);
    const result = document.getElementById(resultId);
    btn.disabled = true;
    result.className = 'ingest-result show';
    result.textContent = '⏳ Sending request…';
    try {
      const data = await apiFetch(API.ingestion, path);
      result.className = 'ingest-result show success';
      result.textContent = JSON.stringify(data, null, 2);
      toast('Ingestion triggered successfully ✓', 'success');
    } catch (err) {
      result.className = 'ingest-result show error';
      result.textContent = '✗ ' + err.message + '\n\nMake sure the ingestion service is running on :8081';
      toast('Ingestion failed: ' + err.message, 'error');
    } finally {
      btn.disabled = false;
    }
  });
}

bindIngest('btn-ingest-abuseipdb', 'result-abuseipdb', '/api/v1/ingest/abuseipdb');
bindIngest('btn-ingest-alienvault', 'result-alienvault', '/api/v1/ingest/alienvault');
bindIngest('btn-ingest-all', 'result-all', '/api/v1/ingest/all');

/* ── Analytics page ─────────────────────────────────────────────────── */
async function loadAnalytics() {
  const hours = document.getElementById('trend-hours').value;
  try {
    const [trend, country, summary] = await Promise.allSettled([
      apiFetch(API.analytics, `/api/v1/analytics/trend?hours=${hours}`),
      apiFetch(API.analytics, '/api/v1/analytics/by-country?limit=10'),
      apiFetch(API.analytics, '/api/v1/analytics/summary'),
    ]);

    if (trend.status === 'fulfilled') {
      const d = trend.value;
      document.getElementById('trend-badge').textContent = `${d.count} IOCs in ${d.hours}h`;

      // Group by hour
      const hourMap = {};
      (d.records || []).forEach(r => {
        const h = new Date(r.createdAt).getHours();
        const label = `${h}:00`;
        hourMap[label] = (hourMap[label] || 0) + 1;
      });

      const now = new Date();
      const labels = [];
      for (let i = parseInt(hours) - 1; i >= 0; i--) {
        const h = new Date(now - i * 3600000);
        labels.push(`${h.getHours()}:00`);
      }
      const vals = labels.map(l => hourMap[l] || 0);
      makeLine('trend-chart', labels, vals);
    }

    // Score distribution bar chart from top-threats
    try {
      const threats = await apiFetch(API.analytics, '/api/v1/analytics/top-threats?limit=50');
      const buckets = { '0-20':0, '21-40':0, '41-60':0, '61-80':0, '81-100':0 };
      threats.forEach(t => {
        const s = t.severityScore || 0;
        if (s <= 20) buckets['0-20']++;
        else if (s <= 40) buckets['21-40']++;
        else if (s <= 60) buckets['41-60']++;
        else if (s <= 80) buckets['61-80']++;
        else buckets['81-100']++;
      });
      makeBar('score-chart', Object.keys(buckets), Object.values(buckets), ['#22c55e','#eab308','#f97316','#ef4444','#dc2626']);
    } catch { /* ok */ }

    if (country.status === 'fulfilled') {
      renderCountryBars(country.value);
    }

    if (summary.status === 'fulfilled') {
      renderSummaryStats(summary.value);
    }

  } catch (err) {
    toast('Analytics load failed: ' + err.message, 'error');
  }
}

function renderCountryBars(data) {
  const el = document.getElementById('country-bars');
  const entries = Object.entries(data);
  if (!entries.length) { el.innerHTML = '<p style="color:var(--text3)">No data</p>'; return; }
  const max = Math.max(...entries.map(e => e[1]));
  el.innerHTML = entries.map(([code, cnt]) => `
    <div class="cbar-row">
      <span class="cbar-name">${code || '??'}</span>
      <div class="cbar-track"><div class="cbar-fill" style="width:${Math.round(cnt/max*100)}%"></div></div>
      <span class="cbar-val">${cnt}</span>
    </div>`).join('');
}

function renderSummaryStats(d) {
  const el = document.getElementById('analytics-stats-list');
  const rows = [
    ['Total IOCs', d.totalIocs],
    ['IPs', d.totalIps],
    ['Domains', d.totalDomains],
    ['Ranked', d.ranked],
    ['Pending', d.pending],
    ['Critical', d.critical],
    ['High', d.high],
    ['Medium', d.medium],
    ['Low', d.low],
    ['Avg Score', d.avgSeverityScore != null ? Number(d.avgSeverityScore).toFixed(1) : '—'],
    ['Max Score', d.maxSeverityScore],
    ['AbuseIPDB', d.abuseipdbCount],
    ['AlienVault', d.alienvaultCount],
  ];
  el.innerHTML = rows.map(([k, v]) => `
    <div class="stat-row">
      <span class="stat-key">${k}</span>
      <span class="stat-val">${v ?? '—'}</span>
    </div>`).join('');
}

document.getElementById('trend-hours').addEventListener('change', () => {
  if (currentPage === 'analytics') loadAnalytics();
});

/* ── Services page ──────────────────────────────────────────────────── */
async function loadServices() {
  const grid = document.getElementById('services-grid');
  grid.innerHTML = SERVICES.map((s, i) => `
    <div class="service-card" id="svc-card-${i}">
      <div class="service-header">
        <div>
          <div class="service-name" style="color:${s.color}">${s.name}</div>
          <div class="service-port">:${s.port}</div>
        </div>
        <div class="service-status-badge svc-checking" id="svc-badge-${i}">
          <span class="status-dot dot-checking"></span>
          <span id="svc-status-text-${i}">Checking…</span>
        </div>
      </div>
      <div class="service-endpoints">
        ${s.endpoints.map(e => `<span class="endpoint-tag">${e}</span>`).join('')}
      </div>
    </div>`).join('');

  SERVICES.forEach(async (s, i) => {
    const badge = document.getElementById(`svc-badge-${i}`);
    const text  = document.getElementById(`svc-status-text-${i}`);
    try {
      await fetch(`http://localhost:${s.port}${s.path}`);
      badge.className = 'service-status-badge svc-up';
      badge.querySelector('.status-dot').className = 'status-dot dot-up';
      text.textContent = 'UP';
    } catch {
      badge.className = 'service-status-badge svc-down';
      badge.querySelector('.status-dot').className = 'status-dot dot-down';
      text.textContent = 'DOWN';
    }
  });
}

/* ── Bootstrap ──────────────────────────────────────────────────────── */
checkGateway();
setInterval(checkGateway, 30000);
navigate('dashboard');

/**
 * Options Page Script — Generic Threat Detection Extension
 * 
 * Supports full per-site management:
 * - Add/remove any domain
 * - Enable/disable per domain
 * - Edit sensitive paths per domain
 * - Edit sensitive fields per domain
 * - Reset to default demo config
 */

// ============================================
// DOMAIN MATCHING UTILITIES (shared logic)
// ============================================

function normalizeDomain(input) {
  return input
    .replace(/^https?:\/\//, "")
    .replace(/^www\./, "")
    .replace(/\/.*$/, "")
    .trim()
    .toLowerCase();
}

// ============================================
// DEFAULT CONFIGURATION
// ============================================

const DEFAULT_SENSITIVE_PATHS = [
  '/login', '/signin', '/signup', '/register', '/dashboard', '/admin',
  '/profile', '/account', '/settings', '/payment', '/checkout',
  '/patient', '/emergency', '/hospital', '/ambulance', '/records'
];
const DEFAULT_SENSITIVE_FIELDS = ['password', 'otp', 'email', 'phone', 'card', 'cvv', 'token', 'pin'];
const DEFAULT_HIGH_RISK = ['form_submit', 'password_focus', 'copy_paste', 'rapid_clicking', 'tab_blur'];

const DEFAULT_CONFIG = {
  backendUrl: 'http://localhost:8081',
  monitoringEnabled: true,
  demoMode: true,
  monitoredSites: [{
    domain: 'example.com',
    enabled: true,
    sensitivePaths: DEFAULT_SENSITIVE_PATHS,
    sensitiveFields: DEFAULT_SENSITIVE_FIELDS,
    highRiskActions: DEFAULT_HIGH_RISK
  }]
};

// ============================================
// STATE
// ============================================

let editingIndex = -1;

// ============================================
// INITIALIZATION
// ============================================

document.addEventListener('DOMContentLoaded', loadSettings);

async function loadSettings() {
  const data = await chrome.storage.local.get(['backendUrl', 'monitoringEnabled', 'demoMode', 'monitoredSites']);

  document.getElementById('backendUrl').value = data.backendUrl || DEFAULT_CONFIG.backendUrl;

  const enabled = data.monitoringEnabled !== false;
  document.getElementById('monitoringStatus').textContent =
    enabled ? '✓ Monitoring is currently ENABLED' : '✗ Monitoring is currently DISABLED';
  document.getElementById('monitoringStatus').className =
    'monitoring-status-text ' + (enabled ? 'status-enabled' : 'status-disabled');

  const demoEnabled = data.demoMode !== false;
  document.getElementById('demoModeStatus').textContent =
    demoEnabled ? '✓ Demo Mode is ON' : '✗ Demo Mode is OFF';
  document.getElementById('demoModeStatus').className =
    'monitoring-status-text ' + (demoEnabled ? 'status-enabled' : 'status-disabled');

  renderSiteList(data.monitoredSites || DEFAULT_CONFIG.monitoredSites);
}

// ============================================
// SITE LIST RENDERING
// ============================================

function renderSiteList(sites) {
  const list = document.getElementById('siteList');
  list.innerHTML = '';

  if (!sites || sites.length === 0) {
    list.innerHTML = '<div class="empty-state">No monitored sites configured. Add a domain below to start monitoring.</div>';
    return;
  }

  sites.forEach((site, index) => {
    const card = document.createElement('div');
    card.className = 'site-card' + (site.enabled === false ? ' site-disabled' : '');

    const pathCount = (site.sensitivePaths || []).length;
    const fieldCount = (site.sensitiveFields || []).length;
    const statusLabel = site.enabled === false ? 'Disabled' : 'Active';
    const statusClass = site.enabled === false ? 'badge-off' : 'badge-on';

    card.innerHTML = `
      <div class="site-card-header">
        <div class="site-card-domain">${site.domain}</div>
        <span class="site-status-badge ${statusClass}">${statusLabel}</span>
      </div>
      <div class="site-card-meta">
        <span>${pathCount} sensitive paths</span>
        <span>·</span>
        <span>${fieldCount} sensitive fields</span>
      </div>
      <div class="site-card-actions">
        <button class="card-btn card-btn-edit" data-index="${index}" title="Edit paths & fields">✏️ Edit</button>
        <button class="card-btn card-btn-toggle" data-index="${index}" title="${site.enabled === false ? 'Enable' : 'Disable'} monitoring">
          ${site.enabled === false ? '▶ Enable' : '⏸ Disable'}
        </button>
        <button class="card-btn card-btn-remove" data-index="${index}" title="Remove domain">🗑 Remove</button>
      </div>
    `;
    list.appendChild(card);
  });

  // Attach handlers
  list.querySelectorAll('.card-btn-remove').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      const idx = parseInt(e.currentTarget.dataset.index);
      const data = await chrome.storage.local.get('monitoredSites');
      const sites = data.monitoredSites || [];
      const removedDomain = sites[idx]?.domain || 'Domain';
      sites.splice(idx, 1);
      await chrome.storage.local.set({ monitoredSites: sites });
      renderSiteList(sites);
      showToast(`${removedDomain} removed`);
    });
  });

  list.querySelectorAll('.card-btn-toggle').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      const idx = parseInt(e.currentTarget.dataset.index);
      const data = await chrome.storage.local.get('monitoredSites');
      const sites = data.monitoredSites || [];
      if (sites[idx]) {
        sites[idx].enabled = sites[idx].enabled === false ? true : false;
        await chrome.storage.local.set({ monitoredSites: sites });
        renderSiteList(sites);
        showToast(`${sites[idx].domain} ${sites[idx].enabled ? 'enabled' : 'disabled'}`);
      }
    });
  });

  list.querySelectorAll('.card-btn-edit').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      const idx = parseInt(e.currentTarget.dataset.index);
      const data = await chrome.storage.local.get('monitoredSites');
      const sites = data.monitoredSites || [];
      if (sites[idx]) {
        openEditModal(idx, sites[idx]);
      }
    });
  });
}

// ============================================
// EDIT MODAL
// ============================================

function openEditModal(index, site) {
  editingIndex = index;
  document.getElementById('editDomain').value = site.domain;
  document.getElementById('editPaths').value = (site.sensitivePaths || []).join('\n');
  document.getElementById('editFields').value = (site.sensitiveFields || []).join(', ');
  document.getElementById('editModal').style.display = 'flex';
}

function closeEditModal() {
  editingIndex = -1;
  document.getElementById('editModal').style.display = 'none';
}

document.getElementById('modalClose').addEventListener('click', closeEditModal);
document.getElementById('modalCancel').addEventListener('click', closeEditModal);

document.getElementById('modalSave').addEventListener('click', async () => {
  if (editingIndex < 0) return;

  const pathsRaw = document.getElementById('editPaths').value;
  const fieldsRaw = document.getElementById('editFields').value;

  const paths = pathsRaw
    .split('\n')
    .map(p => p.trim())
    .filter(p => p.length > 0)
    .map(p => p.startsWith('/') ? p : '/' + p);

  const fields = fieldsRaw
    .split(',')
    .map(f => f.trim().toLowerCase())
    .filter(f => f.length > 0);

  const data = await chrome.storage.local.get('monitoredSites');
  const sites = data.monitoredSites || [];

  if (sites[editingIndex]) {
    sites[editingIndex].sensitivePaths = paths;
    sites[editingIndex].sensitiveFields = fields;
    await chrome.storage.local.set({ monitoredSites: sites });
    renderSiteList(sites);
    showToast('Site configuration saved');
  }

  closeEditModal();
});

// Close modal on backdrop click
document.getElementById('editModal').addEventListener('click', (e) => {
  if (e.target === document.getElementById('editModal')) {
    closeEditModal();
  }
});

// ============================================
// SAVE BACKEND URL
// ============================================

document.getElementById('saveBackendUrl').addEventListener('click', async () => {
  const url = document.getElementById('backendUrl').value.trim().replace(/\/+$/, '');
  if (!url) return;
  await chrome.storage.local.set({ backendUrl: url });
  showToast('Backend URL saved');
});

// ============================================
// ADD DOMAIN
// ============================================

document.getElementById('addDomain').addEventListener('click', async () => {
  let domain = document.getElementById('newDomain').value.trim();
  if (!domain) return;

  // Normalize domain
  domain = normalizeDomain(domain);
  if (!domain) return;

  const data = await chrome.storage.local.get('monitoredSites');
  const sites = data.monitoredSites || [];

  // Check duplicate
  if (sites.some(s => normalizeDomain(s.domain) === domain)) {
    showToast('Domain already exists');
    return;
  }

  sites.push({
    domain: domain,
    enabled: true,
    sensitivePaths: [...DEFAULT_SENSITIVE_PATHS],
    sensitiveFields: [...DEFAULT_SENSITIVE_FIELDS],
    highRiskActions: [...DEFAULT_HIGH_RISK]
  });

  await chrome.storage.local.set({ monitoredSites: sites });
  document.getElementById('newDomain').value = '';
  renderSiteList(sites);
  showToast(`${domain} added`);
});

// Enter key support for domain input
document.getElementById('newDomain').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    e.preventDefault();
    document.getElementById('addDomain').click();
  }
});

// ============================================
// ENABLE / DISABLE MONITORING
// ============================================

document.getElementById('enableMonitoring').addEventListener('click', async () => {
  await chrome.storage.local.set({ monitoringEnabled: true });
  document.getElementById('monitoringStatus').textContent = '✓ Monitoring is currently ENABLED';
  document.getElementById('monitoringStatus').className = 'monitoring-status-text status-enabled';
  showToast('Monitoring enabled');
});

document.getElementById('disableMonitoring').addEventListener('click', async () => {
  await chrome.storage.local.set({ monitoringEnabled: false });
  document.getElementById('monitoringStatus').textContent = '✗ Monitoring is currently DISABLED';
  document.getElementById('monitoringStatus').className = 'monitoring-status-text status-disabled';
  showToast('Monitoring disabled');
});

// ============================================
// DEMO MODE CONTROL
// ============================================

document.getElementById('enableDemoMode').addEventListener('click', async () => {
  await chrome.storage.local.set({ demoMode: true });
  document.getElementById('demoModeStatus').textContent = '✓ Demo Mode is ON';
  document.getElementById('demoModeStatus').className = 'monitoring-status-text status-enabled';
  showToast('Demo Mode enabled');
});

document.getElementById('disableDemoMode').addEventListener('click', async () => {
  await chrome.storage.local.set({ demoMode: false });
  document.getElementById('demoModeStatus').textContent = '✗ Demo Mode is OFF';
  document.getElementById('demoModeStatus').className = 'monitoring-status-text status-disabled';
  showToast('Demo Mode disabled');
});

// ============================================
// RESET DEFAULTS
// ============================================

document.getElementById('resetDefaults').addEventListener('click', async () => {
  await chrome.storage.local.set(DEFAULT_CONFIG);
  loadSettings();
  showToast('Settings reset to defaults');
});

// ============================================
// TOAST
// ============================================

function showToast(msg) {
  const toast = document.getElementById('toast');
  toast.textContent = msg;
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 2000);
}

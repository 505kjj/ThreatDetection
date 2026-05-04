/**
 * Popup Script — Generic Threat Detection Extension
 * 
 * Shows monitoring status for the current website.
 * Uses generic domain matching — works for any configured domain.
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

function getMatchingSiteConfig(hostname, monitoredSites) {
  if (!monitoredSites || !Array.isArray(monitoredSites)) return null;
  const normalizedHost = normalizeDomain(hostname);

  return monitoredSites.find(site => {
    const normalizedSite = normalizeDomain(site.domain);
    return site.enabled !== false && (
      normalizedHost === normalizedSite ||
      normalizedHost.endsWith("." + normalizedSite)
    );
  });
}

// ============================================
// DEFAULT CONFIG VALUES
// ============================================

const DEFAULT_SENSITIVE_PATHS = [
  '/login', '/signin', '/signup', '/register', '/dashboard', '/admin',
  '/profile', '/account', '/settings', '/payment', '/checkout',
  '/patient', '/emergency', '/hospital', '/ambulance', '/records'
];
const DEFAULT_SENSITIVE_FIELDS = ['password', 'otp', 'email', 'phone', 'card', 'cvv', 'token', 'pin'];
const DEFAULT_HIGH_RISK_ACTIONS = ['form_submit', 'password_focus', 'copy_paste', 'rapid_clicking', 'tab_blur'];

// ============================================
// MAIN
// ============================================

document.addEventListener('DOMContentLoaded', async () => {
  // Get current tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  let currentDomain = '';
  try {
    currentDomain = new URL(tab.url).hostname;
  } catch (e) { currentDomain = ''; }

  const normalizedCurrent = currentDomain ? normalizeDomain(currentDomain) : '';
  document.getElementById('currentDomain').textContent = normalizedCurrent || 'N/A';

  // Load config
  const data = await chrome.storage.local.get(['backendUrl', 'monitoringEnabled', 'demoMode', 'monitoredSites']);
  const backendUrl = data.backendUrl || 'http://localhost:8081';
  const monitoringEnabled = data.monitoringEnabled !== false;
  const demoMode = data.demoMode !== false;
  const monitoredSites = data.monitoredSites || [];

  document.getElementById('demoModeStatus').textContent = demoMode ? 'ON' : 'OFF';

  // Check if current site is monitored using generic domain matching
  const matchingSite = getMatchingSiteConfig(currentDomain, monitoredSites);
  const isMonitored = monitoringEnabled && !!matchingSite;

  // Status bar
  const statusDot = document.getElementById('statusDot');
  const statusText = document.getElementById('statusText');
  const monBadge = document.getElementById('monitoringBadge');

  if (!monitoringEnabled) {
    statusDot.className = 'status-dot offline';
    statusText.textContent = 'Monitoring Disabled';
    monBadge.textContent = 'Disabled';
    monBadge.className = 'monitoring-badge badge-off';
  } else if (isMonitored) {
    statusDot.className = 'status-dot online';
    statusText.textContent = 'Monitoring Active';
    monBadge.textContent = '✓ Monitored';
    monBadge.className = 'monitoring-badge badge-on';
  } else {
    statusDot.className = 'status-dot idle';
    statusText.textContent = 'Not Monitored';
    monBadge.textContent = 'Not Monitored';
    monBadge.className = 'monitoring-badge badge-off';
  }

  // Show not-monitored notice or risk data
  if (currentDomain && monitoringEnabled && !isMonitored) {
    document.getElementById('notMonitoredNotice').style.display = 'block';
  }

  // Show/hide add/remove buttons
  if (currentDomain && monitoringEnabled) {
    if (isMonitored) {
      document.getElementById('btnRemoveSite').style.display = 'block';
    } else {
      document.getElementById('btnAddSite').style.display = 'block';
    }
  }

  // Check backend health
  const backendDot = document.getElementById('backendDot');
  const backendText = document.getElementById('backendText');
  try {
    const res = await fetch(`${backendUrl}/api/health`, { signal: AbortSignal.timeout(3000) });
    if (res.ok) {
      backendDot.className = 'status-dot-sm online';
      backendText.textContent = 'Backend connected';
    } else throw new Error();
  } catch (e) {
    backendDot.className = 'status-dot-sm offline';
    backendText.textContent = 'Backend unavailable';
  }

  // Load latest risk data — try session storage first (set by background), then local (set by content)
  let sessionData = {};
  try { sessionData = await chrome.storage.session.get(['latestRisk', 'latestRiskDomain']); } catch (_) {}
  if (!sessionData.latestRisk) {
    const localData = await chrome.storage.local.get(['_latestRisk', '_latestDomain']);
    if (localData._latestRisk) { sessionData = { latestRisk: localData._latestRisk, latestRiskDomain: localData._latestDomain }; }
  }
  if (isMonitored && sessionData.latestRisk && sessionData.latestRiskDomain === normalizedCurrent) {
    showRiskData(sessionData.latestRisk);
  } else if (isMonitored) {
    document.getElementById('noData').style.display = 'block';
  }

  // Button handlers
  document.getElementById('btnAddSite').addEventListener('click', async () => {
    const sites = (await chrome.storage.local.get('monitoredSites')).monitoredSites || [];
    const domainToAdd = normalizedCurrent;
    
    // Check duplicate
    if (sites.some(s => normalizeDomain(s.domain) === domainToAdd)) {
      return;
    }

    sites.push({
      domain: domainToAdd,
      enabled: true,
      sensitivePaths: DEFAULT_SENSITIVE_PATHS,
      sensitiveFields: DEFAULT_SENSITIVE_FIELDS,
      highRiskActions: DEFAULT_HIGH_RISK_ACTIONS
    });
    await chrome.storage.local.set({ monitoredSites: sites });
    // Reload tab to activate monitoring
    chrome.tabs.reload(tab.id);
    window.close();
  });

  document.getElementById('btnRemoveSite').addEventListener('click', async () => {
    let sites = (await chrome.storage.local.get('monitoredSites')).monitoredSites || [];
    sites = sites.filter(s => {
      const normalizedSite = normalizeDomain(s.domain);
      return normalizedCurrent !== normalizedSite && !normalizedCurrent.endsWith('.' + normalizedSite);
    });
    await chrome.storage.local.set({ monitoredSites: sites });
    chrome.tabs.reload(tab.id);
    window.close();
  });

  document.getElementById('btnOptions').addEventListener('click', () => {
    chrome.runtime.openOptionsPage();
  });
});

function showRiskData(risk) {
  document.getElementById('riskSection').style.display = 'block';
  document.getElementById('noData').style.display = 'none';
  document.getElementById('notMonitoredNotice').style.display = 'none';

  const level = risk.riskLevel || 'Safe';
  document.getElementById('riskLevel').textContent = level;
  document.getElementById('riskLevel').className = 'risk-level level-' + level.toLowerCase().replace(/\s+/g, '-');
  document.getElementById('riskScore').textContent = risk.riskScore || 0;
  document.getElementById('trustScore').textContent = risk.trustScore || 0;

  const circle = document.getElementById('riskScoreCircle');
  if (risk.riskScore <= 30) circle.className = 'risk-score-circle score-safe';
  else if (risk.riskScore <= 60) circle.className = 'risk-score-circle score-suspicious';
  else if (risk.riskScore <= 90) circle.className = 'risk-score-circle score-high';
  else circle.className = 'risk-score-circle score-critical';

  document.getElementById('actionValue').textContent = risk.action || '—';

  const blockingStatus = document.getElementById('blockingStatus');
  if (level === 'Critical' || risk.action === 'ADMIN_ALERT') {
    blockingStatus.textContent = 'Critical Blocked';
    blockingStatus.style.color = '#ef4444';
  } else if (level === 'High Risk' || risk.action === 'FORCE_RELOGIN') {
    blockingStatus.textContent = 'Blocked';
    blockingStatus.style.color = '#f97316';
  } else if (level === 'Suspicious' || risk.action === 'SHOW_WARNING') {
    blockingStatus.textContent = 'Warning';
    blockingStatus.style.color = '#eab308';
  } else {
    blockingStatus.textContent = 'Not Blocked';
    blockingStatus.style.color = '#4ade80';
  }

  if (risk.reasons && risk.reasons.length) {
    document.getElementById('reasonsBox').style.display = 'block';
    document.getElementById('reasonsList').innerHTML = risk.reasons.map(r => `<li>${r}</li>`).join('');
  }

  if (risk.tags && risk.tags.length) {
    document.getElementById('tagsBox').style.display = 'block';
    document.getElementById('tagsList').innerHTML = risk.tags.map(t => `<span class="tag">${t}</span>`).join('');
  }
}

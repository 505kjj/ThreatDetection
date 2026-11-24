import { backendOrigin, newSite, readSites } from './settings.mjs';

const byId = id => document.getElementById(id);
const title = {
  confirmed: 'Known malicious website',
  warning: 'Suspicious activity, unconfirmed',
  no_match: 'No known threat match',
  unavailable: 'Protection unavailable',
  waiting: 'Waiting for an activity check',
  paused: 'Monitoring paused',
  unmonitored: 'Site is not monitored',
  unsupported: 'Open a website to check monitoring'
};
const cause = {
  credential: 'Set a browser token in Settings.',
  authentication: 'The backend rejected the browser credential. Check Settings.',
  permission: 'Allow access to the backend host in Settings.',
  backend: 'The secured backend could not provide an activity result.',
  reputation: 'A current reputation snapshot is unavailable.'
};
let current;
let refreshRevision = 0;
let protectionEnabled;

async function refresh() {
  const revision = ++refreshRevision;
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const [status, protection] = await Promise.all([
      chrome.runtime.sendMessage({ type: 'GET_TAB_STATUS', tabId: tab?.id }),
      chrome.runtime.sendMessage({ type: 'GET_POPUP_CONTEXT' })
    ]);
    if (revision === refreshRevision) render(status ?? { state: 'unavailable' }, protection);
  } catch {
    if (revision === refreshRevision) render({ state: 'unavailable' });
  }
}

function render(status, protection) {
  current = status;
  const evidence = status.impersonation ?? [];
  const caution = evidence.length > 0 && (status.state === 'no_match' || status.state === 'warning');
  const label = caution ? 'Possible financial website impersonation'
    : title[status.state] ?? title.unavailable;
  if (byId('statusText').textContent !== label) byId('statusText').textContent = label;
  const signal = status.state === 'confirmed' ? 'offline'
    : caution || status.state === 'warning' ? 'caution' : status.state === 'no_match' ? 'online' : 'idle';
  byId('statusDot').className = 'status-dot ' + signal;
  byId('currentDomain').textContent = status.host ?? '—';
  const detail = {
    confirmed: status.threat === 'MALWARE' ? 'Known malware match. Leave this page.' :
      'Known phishing match. Leave this page without entering information.',
    no_match: 'The snapshot has no match for this page. It may still be unsafe.'
  };
  byId('details').textContent = caution ? 'Verify the official address before entering information.'
    : cause[status.cause] ?? detail[status.state] ?? '';
  byId('btnAddSite').hidden = !status.host || status.siteEnabled || !status.monitoringEnabled;
  byId('btnRemoveSite').hidden = !status.host || !status.siteEnabled || !status.monitoringEnabled;
  byId('riskSection').hidden = status.state !== 'warning';
  byId('riskScore').textContent = status.riskScore ?? '';
  byId('impersonationSection').hidden = evidence.length === 0;
  renderReasons('impersonationReasons', evidence.map(item => item.reason));
  renderReasons('reasonsList', status.reasons ?? []);
  renderProtection(protection);
}

function renderProtection(protection) {
  const report = protection?.reporting;
  protectionEnabled = protection?.enabled;
  byId('btnPauseProtection').hidden = typeof protectionEnabled !== 'boolean';
  byId('btnPauseProtection').textContent = protectionEnabled ? 'Pause protection' : 'Resume protection';
  byId('popupReputation').textContent = {
    current: 'Current snapshot', paused: 'Paused', unavailable: 'Unavailable'
  }[protection?.reputation] ?? 'Status unavailable';
  byId('popupReporting').textContent = report?.optedIn === false ? 'Off' : {
    connected: 'Connected', waiting: 'Waiting', paused: 'Paused', disconnected: 'Unavailable'
  }[report?.status] ?? 'Status unavailable';
  const origin = backendOrigin(protection?.origin);
  byId('popupBackend').textContent = report?.status === 'connected' ? 'Reporting connected'
    : protection?.hasToken ? 'Configured · check in Settings' : origin ? 'Browser token required' : 'Status unavailable';
  const dashboard = byId('openDashboard');
  dashboard.hidden = !origin;
  if (origin) dashboard.href = origin + '/monitor';
  else dashboard.removeAttribute('href');
}

async function toggleProtection() {
  if (typeof protectionEnabled !== 'boolean') return;
  const button = byId('btnPauseProtection');
  button.disabled = true;
  const message = byId('popupMessage');
  message.hidden = true;
  try {
    await chrome.storage.local.set({ monitoringEnabled: !protectionEnabled });
    await refresh();
  } catch {
    message.textContent = 'Could not change protection. Try again in Settings.';
    message.hidden = false;
  } finally {
    button.disabled = false;
  }
}

function renderReasons(list, reasons) {
  byId(list).replaceChildren(...reasons.map(reason => {
    const item = document.createElement('li');
    item.textContent = reason;
    return item;
  }));
}

async function setMonitoring(enabled) {
  const host = current?.host;
  if (!host) return;
  const { monitoredSites } = await chrome.storage.local.get('monitoredSites');
  const sites = readSites(monitoredSites);
  const site = sites.find(entry => entry.domain === host);
  if (site) site.enabled = enabled;
  else sites.push({ ...newSite(host), enabled });
  await chrome.storage.local.set({ monitoredSites: sites });
  await refresh();
}

byId('btnAddSite').addEventListener('click', () => void setMonitoring(true));
byId('btnRemoveSite').addEventListener('click', () => void setMonitoring(false));
byId('btnOptions').addEventListener('click', () => void chrome.runtime.openOptionsPage());
byId('btnPauseProtection').addEventListener('click', () => void toggleProtection());
chrome.storage.onChanged.addListener(() => void refresh());
setInterval(refresh, 2000);
void refresh();

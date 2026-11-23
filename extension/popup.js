import { newSite, readSites } from './settings.mjs';

const byId = id => document.getElementById(id);
const title = {
  safe: 'No warning from activity checks',
  warning: 'Unusual activity detected',
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
  backend: 'The secured backend could not provide a result.'
};
let current;
let refreshRevision = 0;

async function refresh() {
  const revision = ++refreshRevision;
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const status = await chrome.runtime.sendMessage({ type: 'GET_TAB_STATUS', tabId: tab?.id });
    if (revision === refreshRevision) render(status ?? { state: 'unavailable' });
  } catch {
    if (revision === refreshRevision) render({ state: 'unavailable' });
  }
}

function render(status) {
  current = status;
  byId('statusText').textContent = title[status.state] ?? title.unavailable;
  byId('statusDot').className = 'status-dot ' + (status.state === 'safe' ? 'online'
    : status.state === 'unavailable' || status.state === 'warning' ? 'offline' : 'idle');
  byId('currentDomain').textContent = status.host ?? '—';
  byId('details').textContent = cause[status.cause] ?? (status.state === 'waiting'
    ? 'Switch back to the website to let it send an activity check.' : '');
  byId('btnAddSite').hidden = !status.host || status.siteEnabled || !status.monitoringEnabled;
  byId('btnRemoveSite').hidden = !status.host || !status.siteEnabled || !status.monitoringEnabled;
  byId('riskSection').hidden = !['safe', 'warning'].includes(status.state);
  byId('riskScore').textContent = status.riskScore ?? '';
  byId('reasonsList').replaceChildren(...(status.reasons ?? []).map(reason => {
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
chrome.storage.onChanged.addListener(() => void refresh());
void refresh();

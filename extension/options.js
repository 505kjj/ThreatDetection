import { DEFAULT_ORIGIN, backendOrigin, backendPermission, newSite, readSites, siteHostname } from './settings.mjs';
import { validToken } from './backend-api.mjs';

const byId = id => document.getElementById(id);
let editingDomain = null;
let connectionBusy = false;

function announce(text) {
  byId('message').textContent = text;
}

async function loadConnection() {
  const result = await chrome.runtime.sendMessage({ type: 'GET_CONNECTION' });
  if (!result?.origin) throw new Error('Settings unavailable');
  byId('backendOrigin').value = result.origin;
  byId('tokenStatus').textContent = result.hasToken ? 'Browser token set for this session.' : 'Browser token required.';
  byId('clearToken').disabled = !result.hasToken;
}

async function getSites() {
  const { monitoredSites } = await chrome.storage.local.get('monitoredSites');
  return readSites(monitoredSites);
}

async function renderMonitoring() {
  const { monitoringEnabled } = await chrome.storage.local.get('monitoringEnabled');
  const enabled = monitoringEnabled !== false;
  byId('monitoringStatus').textContent = enabled ? 'Monitoring enabled for configured sites.' : 'Monitoring paused.';
  byId('enableMonitoring').disabled = enabled;
  byId('disableMonitoring').disabled = !enabled;
}

function button(label, onClick) {
  const element = document.createElement('button');
  element.type = 'button';
  element.className = 'card-btn';
  element.textContent = label;
  element.addEventListener('click', () => void onClick());
  return element;
}

async function updateSite(domain, update) {
  const sites = await getSites();
  const index = sites.findIndex(site => site.domain === domain);
  if (index === -1) return;
  const changed = update(sites[index]);
  if (changed) sites[index] = changed;
  else sites.splice(index, 1);
  await chrome.storage.local.set({ monitoredSites: sites });
  await renderSites();
}

async function renderSites() {
  const sites = await getSites();
  const list = byId('siteList');
  list.replaceChildren();
  if (!sites.length) {
    const empty = document.createElement('p');
    empty.className = 'empty-state';
    empty.textContent = 'No sites are monitored.';
    list.append(empty);
  }
  for (const site of sites) {
    const card = document.createElement('div');
    card.className = 'site-card';
    const name = document.createElement('div');
    name.className = 'site-card-domain';
    name.textContent = site.domain;
    const controls = document.createElement('div');
    controls.className = 'site-card-actions';
    controls.append(
      button('Edit', () => openEditor(site)),
      button(site.enabled ? 'Pause' : 'Monitor', () => updateSite(site.domain, current =>
        ({ ...current, enabled: !current.enabled }))),
      button('Remove', () => updateSite(site.domain, () => null))
    );
    card.append(name, controls);
    list.append(card);
  }
}

function openEditor(site) {
  editingDomain = site.domain;
  byId('editDomain').value = site.domain;
  byId('editPaths').value = site.sensitivePaths.join('\n');
  byId('editFields').value = site.sensitiveFields.join(', ');
  byId('editModal').style.display = 'flex';
  byId('editPaths').focus();
}

function closeEditor() {
  editingDomain = null;
  byId('editModal').style.display = 'none';
}

byId('saveConnection').addEventListener('click', async () => {
  if (connectionBusy) return;
  const origin = backendOrigin(byId('backendOrigin').value);
  const token = byId('browserToken').value.trim();
  if (!origin) {
    announce('Enter an HTTPS origin or a local HTTP origin such as http://127.0.0.1:8081.');
    return;
  }
  if (token && !validToken(token)) {
    announce('Enter the 43-character browser token issued for this backend.');
    return;
  }
  connectionBusy = true;
  try {
    if (origin.startsWith('https:') && !await chrome.permissions.request(backendPermission(origin))) {
      announce('Allow access to the backend host to save this connection.');
      return;
    }
    const result = await chrome.runtime.sendMessage({ type: 'SAVE_CONNECTION', origin, token });
    if (!result?.saved) throw new Error('Connection rejected');
    byId('browserToken').value = '';
    await loadConnection();
    announce('Connection settings saved.');
  } catch {
    announce('Could not save the connection.');
  } finally {
    connectionBusy = false;
  }
});

byId('clearToken').addEventListener('click', async () => {
  try {
    await chrome.runtime.sendMessage({ type: 'CLEAR_CONNECTION' });
    byId('browserToken').value = '';
    await loadConnection();
    announce('Browser token cleared.');
  } catch {
    announce('Could not clear the browser token.');
  }
});

byId('addDomain').addEventListener('click', async () => {
  const input = byId('newDomain');
  const host = siteHostname(input.value.trim());
  if (!host) {
    announce('Enter a hostname, for example example.com.');
    return;
  }
  const sites = await getSites();
  if (sites.some(site => site.domain === host)) {
    announce('This hostname is already configured.');
    return;
  }
  await chrome.storage.local.set({ monitoredSites: [...sites, newSite(host)] });
  input.value = '';
  await renderSites();
  announce('Site added.');
});

byId('newDomain').addEventListener('keydown', event => {
  if (event.key === 'Enter') byId('addDomain').click();
});

byId('modalClose').addEventListener('click', closeEditor);
byId('modalCancel').addEventListener('click', closeEditor);
byId('modalSave').addEventListener('click', async () => {
  if (!editingDomain) return;
  const split = (value, separator) => value.split(separator).map(item => item.trim()).filter(Boolean);
  const paths = split(byId('editPaths').value, '\n').map(path => path.startsWith('/') ? path : '/' + path);
  const fields = split(byId('editFields').value, ',');
  const [site] = readSites([{ domain: editingDomain, sensitivePaths: paths, sensitiveFields: fields }]);
  if (site.sensitivePaths.length !== new Set(paths).size || site.sensitiveFields.length !== new Set(fields).size) {
    announce('Enter up to 50 short paths and field names. Use letters, numbers, dashes, or underscores for field names.');
    return;
  }
  await updateSite(editingDomain, current => ({ ...current, sensitivePaths: paths, sensitiveFields: fields }));
  closeEditor();
  announce('Site settings saved.');
});

for (const [id, enabled] of [['enableMonitoring', true], ['disableMonitoring', false]]) {
  byId(id).addEventListener('click', async () => {
    await chrome.storage.local.set({ monitoringEnabled: enabled });
    await renderMonitoring();
  });
}

byId('resetDefaults').addEventListener('click', async () => {
  await chrome.runtime.sendMessage({ type: 'CLEAR_CONNECTION' });
  await chrome.storage.local.set({ backendOrigin: DEFAULT_ORIGIN, monitoredSites: [], monitoringEnabled: true });
  byId('browserToken').value = '';
  await Promise.all([loadConnection(), renderSites(), renderMonitoring()]);
  announce('Settings reset.');
});

Promise.all([loadConnection(), renderSites(), renderMonitoring()]).catch(() => announce('Could not load settings.'));

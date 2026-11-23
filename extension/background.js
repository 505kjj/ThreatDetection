import { analysisFields, analyze, downloadSnapshot, requestFailure, startSession, validToken } from './backend-api.mjs';
import { detectImpersonation } from './impersonation.mjs';
import { checkDestination, createSnapshotCache, destinationFor } from './reputation.mjs';
import { DEFAULT_ORIGIN, backendOrigin, backendPermission, matchingSite, pageHostname, readSites } from './settings.mjs';

const CREDENTIAL = 'backendCredential';
const statusKey = tabId => 'tab-status:' + tabId;
const navigationKey = tabId => 'tab-navigation:' + tabId;
const requests = new Map();
const navigations = new Map();
const local = chrome.storage.local;
const session = chrome.storage.session;
const reputation = createSnapshotCache(session, downloadSnapshot);
const REPUTATION_EXPIRY = 'reputation-expiry';
let connectionRevision = 0;

const setup = initialize();
async function initialize() {
  await Promise.all([
    local.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' }),
    session.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' })
  ]);
  const old = await local.get(null);
  if (!old.backendOrigin) {
    await local.set({ backendOrigin: backendOrigin(old.backendUrl) ?? DEFAULT_ORIGIN });
  }
  const legacyKeys = Object.keys(old).filter(key =>
    key.startsWith('session_') || ['backendUrl', 'demoMode', '_latestRisk', '_latestDomain', '_latestTime'].includes(key));
  if (legacyKeys.length) await local.remove(legacyKeys);
}

function optionsSender(sender) {
  return sender.url === chrome.runtime.getURL('options.html');
}

async function settings() {
  const data = await local.get(['backendOrigin', 'monitoringEnabled', 'monitoredSites']);
  return {
    origin: backendOrigin(data.backendOrigin),
    enabled: data.monitoringEnabled !== false,
    sites: readSites(data.monitoredSites)
  };
}

async function credentialFor(origin) {
  const { [CREDENTIAL]: credential } = await session.get(CREDENTIAL);
  return origin && credential?.origin === origin && validToken(credential.token) ? credential : null;
}

async function currentPage(tabId) {
  if (!Number.isInteger(tabId) || tabId < 0) return null;
  const navigation = navigations.get(tabId);
  const settingsRevision = connectionRevision;
  try {
    const frame = await chrome.webNavigation.getFrame({ tabId, frameId: 0 });
    const destination = destinationFor(frame?.url);
    return destination && frame.documentId && frame.documentLifecycle === 'active'
      ? { tabId, documentId: frame.documentId, host: destination.host, destination, navigation, settingsRevision } : null;
  } catch {
    return null;
  }
}

function samePage(page, latest) {
  return latest?.documentId === page.documentId && latest.destination.key === page.destination.key &&
    latest.navigation === page.navigation && navigations.get(page.tabId) === page.navigation;
}

async function verifiedPage(sender) {
  if (sender.frameId !== 0 || sender.documentLifecycle !== 'active' || !sender.tab) return null;
  const page = await currentPage(sender.tab.id);
  return page && page.documentId === sender.documentId && page.host === pageHostname(sender.url) ? page : null;
}

async function pageSettings(page) {
  const config = await settings();
  const site = matchingSite(config.sites, page.host);
  const canMonitor = config.enabled && site?.enabled === true;
  const credential = config.enabled ? await credentialFor(config.origin) : null;
  const permitted = credential ? await chrome.permissions.contains(backendPermission(credential.origin)) : false;
  return { ...config, site, canMonitor, credential, permitted };
}

function clearBadge(tabId) {
  return chrome.action.setBadgeText({ tabId, text: '' });
}

function withImpersonation(verdict, evidence) {
  return evidence?.length ? { ...verdict, impersonation: evidence } : verdict;
}

async function reputationFor(page, config) {
  const revision = page.settingsRevision;
  let result;
  if (!config.enabled) result = { state: 'paused' };
  else if (!config.credential) result = { state: 'unavailable', cause: 'credential' };
  else if (!config.permitted) result = { state: 'unavailable', cause: 'permission' };
  else result = await checkDestination(await reputation.current(config.credential), page.destination);
  const latest = await currentPage(page.tabId);
  if (revision !== connectionRevision || !samePage(page, latest)) return { state: 'inactive' };
  if (result.expires <= Date.now()) result = { state: 'unavailable', cause: 'reputation' };
  if (result.expires) {
    const alarm = await chrome.alarms.get(REPUTATION_EXPIRY);
    if (revision !== connectionRevision || !samePage(page, latest)) return { state: 'inactive' };
    if (result.expires <= Date.now()) result = { state: 'unavailable', cause: 'reputation' };
    else if (!alarm || alarm.scheduledTime > result.expires) {
      await chrome.alarms.create(REPUTATION_EXPIRY, { when: result.expires });
    }
  }
  if (revision !== connectionRevision || !samePage(page, latest)) return { state: 'inactive' };
  const impersonation = config.enabled ? detectImpersonation(page.host) : [];
  if (result.state === 'confirmed') {
    await Promise.all([
      chrome.action.setBadgeBackgroundColor({ tabId: page.tabId, color: '#b91c1c' }),
      chrome.action.setBadgeText({ tabId: page.tabId, text: 'STOP' })
    ]);
  } else if (result.state === 'no_match' && impersonation.length) {
    await Promise.all([
      chrome.action.setBadgeBackgroundColor({ tabId: page.tabId, color: '#92400e' }),
      chrome.action.setBadgeText({ tabId: page.tabId, text: '!' })
    ]);
  } else {
    await clearBadge(page.tabId);
  }
  return withImpersonation(result, impersonation);
}

async function saveConnection(message) {
  const origin = backendOrigin(message.origin);
  const { token } = message;
  if (!origin || (token !== '' && !validToken(token))) return { saved: false };
  if (!await chrome.permissions.contains(backendPermission(origin))) return { saved: false };
  // The credential includes its origin so it cannot be reused after an endpoint change.
  if (token) await session.set({ [CREDENTIAL]: { id: crypto.randomUUID(), origin, token } });
  else if (!await credentialFor(origin)) await session.remove(CREDENTIAL);
  await local.set({ backendOrigin: origin });
  return { saved: true };
}

async function pageConfiguration(page) {
  const config = await pageSettings(page);
  const verdict = await reputationFor(page, config);
  if (!config.canMonitor || verdict.state !== 'no_match') {
    return { active: false, verdict, recheck: config.permitted && verdict.state !== 'inactive' };
  }
  return {
    active: true,
    verdict,
    sensitivePaths: config.site.sensitivePaths,
    sensitiveFields: config.site.sensitiveFields
  };
}

async function tabStatus(tabId) {
  const page = await currentPage(tabId);
  if (!page) return { state: 'unsupported' };
  const config = await pageSettings(page);
  const display = { host: page.host, monitoringEnabled: config.enabled, site: config.site?.domain ?? null,
    siteEnabled: config.site?.enabled === true };
  const verdict = await reputationFor(page, config);
  if (verdict.state !== 'no_match' || !config.canMonitor) return { ...display, ...verdict };
  const key = statusKey(tabId);
  const { [key]: previous } = await session.get(key);
  if (previous?.documentId === page.documentId && previous.credentialId === config.credential.id &&
      previous.navigation === (page.navigation ?? null) && Date.now() - previous.checkedAt < 45000 &&
      previous.verdict.state !== 'safe') {
    return { ...display, ...verdict, ...previous.verdict };
  }
  return { ...display, ...verdict };
}

async function submitTelemetry(page, message) {
  const { tabId, documentId, host } = page;
  const existing = requests.get(tabId);
  if (existing?.documentId === documentId && !existing.controller.signal.aborted) return { state: 'waiting' };
  existing?.controller.abort();
  const task = { documentId, controller: new AbortController() };
  requests.set(tabId, task);
  const { signal } = task.controller;
  try {
    const config = await pageSettings(page);
    if (!config.canMonitor) return { state: 'inactive' };
    const { credential } = config;
    const localVerdict = await reputationFor(page, config);
    if (localVerdict.state !== 'no_match') return localVerdict;

    const key = statusKey(tabId);
    const navKey = navigationKey(tabId);
    const saved = await session.get([key, navKey]);
    const nav = saved[navKey];
    const fields = analysisFields(message, nav?.documentId === documentId && nav.redirected);
    if (!fields) return { state: 'inactive' };
    const previous = saved[key];
    const previousDocument = previous?.documentId === documentId && previous.credentialId === credential.id;
    let id = previousDocument ? previous.sessionId : null;
    if (previousDocument && previous.navigation === (page.navigation ?? null) &&
        Date.now() - previous.checkedAt < 500 &&
        message.eventType !== 'recheck_risk') {
      return withImpersonation(previous.verdict, localVerdict.impersonation);
    }

    let verdict;
    try {
      signal.throwIfAborted();
      id ??= await startSession(credential, host, signal);
      signal.throwIfAborted();
      verdict = await analyze(credential, id, fields, signal);
      if (!verdict) {
        // In-memory backend sessions disappear on restart. Renew once on a 404.
        id = null;
        id = await startSession(credential, host, signal);
        verdict = await analyze(credential, id, fields, signal);
        if (!verdict) id = null;
      }
      verdict ??= { state: 'unavailable', cause: 'backend' };
    } catch (error) {
      verdict = { state: 'unavailable', cause: requestFailure(error) };
    }

    const latest = await currentPage(tabId);
    if (signal.aborted || page.settingsRevision !== connectionRevision || !samePage(page, latest)) {
      return { state: 'inactive' };
    }
    if (localVerdict.expires <= Date.now()) verdict = { state: 'unavailable', cause: 'reputation' };
    await session.set({
      [key]: { documentId, navigation: page.navigation ?? null, credentialId: credential.id,
        sessionId: id, verdict, checkedAt: Date.now() }
    });
    return withImpersonation(verdict, localVerdict.impersonation);
  } finally {
    if (requests.get(tabId) === task) requests.delete(tabId);
  }
}

async function handleMessage(message, sender) {
  await setup;
  if (optionsSender(sender)) {
    if (message.type === 'GET_CONNECTION') {
      const { origin } = await settings();
      return { origin: origin ?? DEFAULT_ORIGIN, hasToken: !!await credentialFor(origin) };
    }
    if (message.type === 'SAVE_CONNECTION') return saveConnection(message);
    if (message.type === 'CLEAR_CONNECTION') {
      await session.remove(CREDENTIAL);
      return { saved: true };
    }
  }
  if (sender.url === chrome.runtime.getURL('popup.html') && message.type === 'GET_TAB_STATUS') {
    return tabStatus(message.tabId);
  }
  if (message.type === 'PAGE_CONFIGURATION' || message.type === 'TELEMETRY') {
    const page = await verifiedPage(sender);
    if (!page) return { state: 'inactive' };
    return message.type === 'PAGE_CONFIGURATION' ? pageConfiguration(page) : submitTelemetry(page, message);
  }
  return { state: 'inactive' };
}

chrome.runtime.onMessage.addListener((message, sender, respond) => {
  if (sender.id !== chrome.runtime.id || typeof message?.type !== 'string') return false;
  handleMessage(message, sender).then(respond, () => respond({ state: 'unavailable', cause: 'backend' }));
  return true;
});

chrome.webNavigation.onCommitted.addListener(({ tabId, frameId, documentId, transitionQualifiers = [] }) => {
  if (frameId !== 0) return;
  navigations.set(tabId, crypto.randomUUID());
  requests.get(tabId)?.controller.abort();
  void clearBadge(tabId).catch(() => {});
  const redirected = transitionQualifiers.includes('server_redirect') || transitionQualifiers.includes('client_redirect');
  void session.set({ [navigationKey(tabId)]: { documentId, redirected } }).catch(() => {});
});

chrome.webNavigation.onHistoryStateUpdated.addListener(({ tabId, frameId, documentId }) => {
  if (frameId !== 0) return;
  navigations.set(tabId, crypto.randomUUID());
  requests.get(tabId)?.controller.abort();
  void clearBadge(tabId).catch(() => {});
  void chrome.tabs.sendMessage(tabId, { type: 'REFRESH_CONFIGURATION' }, { documentId }).catch(() => {});
});

chrome.tabs.onRemoved.addListener(tabId => {
  navigations.delete(tabId);
  requests.get(tabId)?.controller.abort();
  void session.remove([statusKey(tabId), navigationKey(tabId)]).catch(() => {});
});

async function refreshOpenPages() {
  connectionRevision++;
  for (const task of requests.values()) task.controller.abort();
  const tabs = await chrome.tabs.query({});
  await Promise.allSettled(tabs.map(async tab => {
    await clearBadge(tab.id);
    await chrome.tabs.sendMessage(tab.id, { type: 'REFRESH_CONFIGURATION' }, { frameId: 0 });
  }));
}

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'session' && CREDENTIAL in changes) {
    void reputation.clear().catch(() => {});
    void refreshOpenPages().catch(() => {});
  } else if (area === 'local' && ['backendOrigin', 'monitoredSites', 'monitoringEnabled'].some(key => key in changes)) {
    void refreshOpenPages().catch(() => {});
  }
});

chrome.permissions.onRemoved.addListener(() => {
  void refreshOpenPages().catch(() => {});
});

chrome.alarms.onAlarm.addListener(alarm => {
  if (alarm.name === REPUTATION_EXPIRY) void refreshOpenPages().catch(() => {});
});

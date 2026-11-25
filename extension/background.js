import { analysisFields, analyze, downloadSnapshot, probeReputationConnection,
  requestFailure, startSession, validToken } from './backend-api.mjs';
import { createBlockRules } from './block-rules.mjs';
import { BYPASS_ALARM, createBrowserProtection } from './browser-protection.mjs';
import { detectImpersonation, verifiedFinancialHost } from './impersonation.mjs';
import { loginEvidence } from './login-risk.mjs';
import { checkDestination, createSnapshotCache, destinationFor } from './reputation.mjs';
import { DEFAULT_ORIGIN, backendOrigin, backendPermission, matchingSite, pageHostname, readSites } from './settings.mjs';
import { createThreatReporting, REPORTING_ALARM } from './threat-reporting.mjs';

const CREDENTIAL = 'backendCredential';
const statusKey = tabId => 'tab-status:' + tabId;
const navigationKey = tabId => 'tab-navigation:' + tabId;
const requests = new Map();
const navigations = new Map();
const financialChecks = new Map();
const local = chrome.storage.local;
const session = chrome.storage.session;
const reputation = createSnapshotCache(session, downloadSnapshot);
const rules = createBlockRules(chrome.declarativeNetRequest, chrome.runtime.id);
const reporting = createThreatReporting(chrome, reportingConnection, () => !!rules.snapshot());
const protection = createBrowserProtection(chrome, rules, Date.now, reporting.report);
const REPUTATION_REFRESH = 'reputation-refresh';
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
  const data = await local.get(['backendOrigin', 'monitoringEnabled', 'monitoredSites', 'threatReportingOrigin']);
  const origin = backendOrigin(data.backendOrigin);
  return {
    origin,
    enabled: data.monitoringEnabled !== false,
    sites: readSites(data.monitoredSites),
    reporting: !!origin && data.threatReportingOrigin === origin
  };
}

async function credentialFor(origin) {
  const { [CREDENTIAL]: credential } = await session.get(CREDENTIAL);
  return origin && credential?.origin === origin && validToken(credential.token) ? credential : null;
}

async function reportingConnection() {
  await setup;
  const config = await settings();
  if (!config.reporting || !config.enabled) return null;
  const credential = await credentialFor(config.origin);
  return credential && await chrome.permissions.contains(backendPermission(credential.origin)) ? credential : null;
}

async function reportingStatus(config) {
  return { optedIn: config.reporting, status: !config.enabled ? 'paused'
    : await reportingConnection() ? reporting.status() : 'disconnected' };
}

async function synchronizeRules(revision = connectionRevision) {
  const config = await settings();
  const credential = config.enabled ? await credentialFor(config.origin) : null;
  const permitted = credential && await chrome.permissions.contains(backendPermission(credential.origin));
  if (!rules.snapshot()) {
    const cached = permitted ? await reputation.cached(credential) : null;
    if (revision !== connectionRevision) return null;
    await rules.setSnapshot(cached);
  }
  const snapshot = permitted ? await reputation.current(credential) : null;
  if (revision !== connectionRevision) return null;
  await rules.setSnapshot(snapshot);
  if (revision !== connectionRevision) return null;
  if (permitted) {
    const when = Math.min(Date.now() + 60000, snapshot?.expires ?? Infinity);
    const alarm = await chrome.alarms.get(REPUTATION_REFRESH);
    if (!alarm || alarm.scheduledTime > when) await chrome.alarms.create(REPUTATION_REFRESH, { when });
  }
  return snapshot;
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

function discardFinancialCheck(tabId) {
  clearTimeout(financialChecks.get(tabId)?.timer);
  financialChecks.delete(tabId);
}

function financialCheck(page, config, result, domainEvidence) {
  if (!domainEvidence.length || !['no_match', 'unavailable'].includes(result.state)) {
    discardFinancialCheck(page.tabId);
    return null;
  }
  let check = financialChecks.get(page.tabId);
  if (!check || check.documentId !== page.documentId || check.navigation !== page.navigation ||
      check.revision !== page.settingsRevision) {
    discardFinancialCheck(page.tabId);
    check = { id: crypto.randomUUID(), documentId: page.documentId, navigation: page.navigation,
      revision: page.settingsRevision, inspected: [], observations: 0 };
    financialChecks.set(page.tabId, check);
  }
  check.domainEvidence = domainEvidence;
  if (config.reporting && !check.reported && !check.timer) {
    check.timer = setTimeout(() => {
      if (financialChecks.get(page.tabId) === check && check.revision === connectionRevision) publishFinancial(page, check);
    }, 1100);
  }
  return check;
}

function publishFinancial(page, check) {
  if (!check.timer || check.reported) return;
  clearTimeout(check.timer);
  check.timer = null;
  check.reported = true;
  const key = check.inspected.find(item => item.kind === 'financial_external_form')?.kind ??
    check.inspected[0]?.kind ?? check.domainEvidence[0].kind;
  reporting.report(key.toUpperCase(), 'WARNED', page.documentId, 'FINANCIAL_IMPERSONATION');
}

async function inspectLogin(page, message) {
  const check = financialChecks.get(page.tabId);
  if (!check || verifiedFinancialHost(page.host) || message.id !== check.id || check.documentId !== page.documentId ||
      check.navigation !== page.navigation || check.revision !== connectionRevision ||
      check.observations >= 8) return { inspected: false };
  check.observations++;
  const key = navigationKey(page.tabId);
  const { [key]: nav } = await session.get(key);
  const latest = await currentPage(page.tabId);
  if (financialChecks.get(page.tabId) !== check || check.revision !== connectionRevision ||
      !samePage(page, latest)) return { inspected: false };
  check.inspected = loginEvidence(message.forms, new URL(page.destination.key).origin,
    check.domainEvidence, nav?.documentId === page.documentId && nav.redirected);
  publishFinancial(page, check);
  return { inspected: true, evidence: [...check.domainEvidence, ...check.inspected] };
}

async function reputationFor(page, config) {
  const revision = page.settingsRevision;
  let result;
  if (!config.enabled) result = { state: 'paused' };
  else if (!config.credential) result = { state: 'unavailable', cause: 'credential' };
  else if (!config.permitted) result = { state: 'unavailable', cause: 'permission' };
  else {
    const snapshot = await synchronizeRules(revision).catch(() => null);
    result = await checkDestination(snapshot, page.destination);
  }
  const latest = await currentPage(page.tabId);
  if (revision !== connectionRevision || !samePage(page, latest)) return { state: 'inactive' };
  if (result.expires <= Date.now()) result = { state: 'unavailable', cause: 'reputation' };
  // Indicator values are needed only by the worker's private warning flow.
  delete result.evidence;
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
  if (revision !== connectionRevision || navigations.get(page.tabId) !== page.navigation) return { state: 'inactive' };
  const financial = financialCheck(page, config, result, impersonation);
  return withImpersonation(result, financial ? [...impersonation, ...financial.inspected] : impersonation);
}

async function saveConnection(message) {
  const origin = backendOrigin(message.origin);
  const { token } = message;
  if (!origin || (token !== '' && !validToken(token))) return { saved: false };
  if (!await chrome.permissions.contains(backendPermission(origin))) return { saved: false };
  if ((await settings()).origin !== origin) await local.remove('threatReportingOrigin');
  // The credential includes its origin so it cannot be reused after an endpoint change.
  if (token) await session.set({ [CREDENTIAL]: { id: crypto.randomUUID(), origin, token } });
  else if (!await credentialFor(origin)) await session.remove(CREDENTIAL);
  await local.set({ backendOrigin: origin });
  return { saved: true };
}

async function pageConfiguration(page) {
  const config = await pageSettings(page);
  const verdict = await reputationFor(page, config);
  const scan = !verifiedFinancialHost(page.host) && ['no_match', 'unavailable'].includes(verdict.state)
    ? financialChecks.get(page.tabId)?.id : null;
  if (!config.canMonitor || verdict.state !== 'no_match') {
    return { active: false, verdict, scan, recheck: config.permitted && verdict.state !== 'inactive' };
  }
  return {
    active: true,
    verdict,
    scan,
    sensitivePaths: config.site.sensitivePaths,
    sensitiveFields: config.site.sensitiveFields
  };
}

async function tabStatus(tabId) {
  const page = await currentPage(tabId);
  if (!page) {
    if (!Number.isInteger(tabId) || tabId < 0) return { state: 'unsupported' };
    return await protection.tabStatus(tabId) ?? { state: 'unsupported' };
  }
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
    if (config.reporting && verdict.state === 'warning') {
      reporting.report('SUSPICIOUS_BEHAVIOR', 'WARNED', documentId);
    }
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
    if (message.type === 'CHECK_CANDIDATE') {
      const origin = backendOrigin(message.origin);
      if (!origin || !validToken(message.token)) return { status: 'unexpected' };
      if (!await chrome.permissions.contains(backendPermission(origin))) return { status: 'permission' };
      return { status: await probeReputationConnection({ origin, token: message.token }) };
    }
    if (message.type === 'CHECK_CONNECTION') {
      const config = await settings();
      const credential = await credentialFor(config.origin);
      if (!credential) return { status: 'missing-token' };
      if (!await chrome.permissions.contains(backendPermission(credential.origin))) return { status: 'permission' };
      const status = await probeReputationConnection(credential);
      const latest = await settings();
      if ((await credentialFor(latest.origin))?.id !== credential.id) return { status: 'changed' };
      return { status, reputation: !latest.enabled ? 'paused' : rules.snapshot() ? 'current' : 'unavailable' };
    }
    if (message.type === 'GET_THREAT_REPORTING') {
      return reportingStatus(await settings());
    }
    if (message.type === 'SET_THREAT_REPORTING' && typeof message.enabled === 'boolean') {
      const { origin } = await settings();
      if (message.enabled && !origin) return { saved: false };
      if (message.enabled) await local.set({ threatReportingOrigin: origin });
      else await local.remove('threatReportingOrigin');
      return { saved: true };
    }
    if (message.type === 'SAVE_CONNECTION') return saveConnection(message);
    if (message.type === 'CLEAR_CONNECTION') {
      await session.remove(CREDENTIAL);
      return { saved: true };
    }
  }
  if (sender.url === chrome.runtime.getURL('popup.html')) {
    if (message.type === 'GET_TAB_STATUS') return tabStatus(message.tabId);
    if (message.type === 'GET_POPUP_CONTEXT') {
      const config = await settings();
      return {
        enabled: config.enabled,
        origin: config.origin,
        hasToken: !!await credentialFor(config.origin),
        reputation: !config.enabled ? 'paused' : rules.snapshot() ? 'current' : 'unavailable',
        reporting: await reportingStatus(config)
      };
    }
  }
  if (['GET_NETWORK_WARNING', 'PROCEED_ONCE', 'LEAVE_NETWORK_WARNING'].includes(message.type)) {
    if (!rules.snapshot()) void synchronizeRules().catch(() => {});
    return protection.message(message.type, sender, message.token);
  }
  if (message.type === 'LOGIN_STRUCTURE') {
    const page = await verifiedPage(sender);
    return page ? inspectLogin(page, message) : { inspected: false };
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

chrome.webNavigation.onBeforeNavigate.addListener(details => void protection.start(details).catch(() => {}));
chrome.webNavigation.onErrorOccurred.addListener(details => {
  if (details.frameId !== 0 || (details.error !== 'net::ERR_BLOCKED_BY_CLIENT' && !rules.bypass(details.tabId))) return;
  void setup.then(async () => {
    if (!rules.snapshot()) await synchronizeRules();
    await protection.failed(details);
  }).catch(() => {});
});
chrome.webNavigation.onCommitted.addListener(details => {
  const { tabId, frameId, documentId, transitionQualifiers = [] } = details;
  if (frameId !== 0) return;
  navigations.set(tabId, crypto.randomUUID());
  discardFinancialCheck(tabId);
  requests.get(tabId)?.controller.abort();
  void clearBadge(tabId).catch(() => {});
  const redirected = transitionQualifiers.includes('server_redirect') || transitionQualifiers.includes('client_redirect');
  void session.set({ [navigationKey(tabId)]: { documentId, redirected } }).catch(() => {});
  void setup.then(() => protection.committed(details)).catch(() => {});
});

chrome.webNavigation.onHistoryStateUpdated.addListener(details => {
  const { tabId, frameId, documentId } = details;
  if (frameId !== 0) return;
  navigations.set(tabId, crypto.randomUUID());
  discardFinancialCheck(tabId);
  requests.get(tabId)?.controller.abort();
  void clearBadge(tabId).catch(() => {});
  void chrome.tabs.sendMessage(tabId, { type: 'REFRESH_CONFIGURATION' }, { documentId }).catch(() => {});
  void setup.then(() => protection.history(details)).catch(() => {});
});

chrome.tabs.onRemoved.addListener(tabId => {
  navigations.delete(tabId);
  discardFinancialCheck(tabId);
  requests.get(tabId)?.controller.abort();
  void session.remove([statusKey(tabId), navigationKey(tabId)]).catch(() => {});
  void protection.remove(tabId).catch(() => {});
});

async function refreshOpenPages() {
  const tabs = await chrome.tabs.query({});
  await Promise.allSettled(tabs.map(async tab => {
    await clearBadge(tab.id);
    await chrome.tabs.sendMessage(tab.id, { type: 'REFRESH_CONFIGURATION' }, { frameId: 0 });
  }));
}

function invalidateRequests() {
  connectionRevision++;
  for (const tabId of financialChecks.keys()) discardFinancialCheck(tabId);
  for (const task of requests.values()) task.controller.abort();
}

async function resetProtection(clearCache) {
  invalidateRequests();
  const clearingRules = rules.setSnapshot(null, true);
  if (clearCache) await reputation.clear();
  await clearingRules;
  await Promise.all([refreshOpenPages(), synchronizeRules()]);
}

chrome.storage.onChanged.addListener((changes, area) => {
  if ((area === 'session' && CREDENTIAL in changes) ||
      (area === 'local' && ['threatReportingOrigin', 'backendOrigin', 'monitoringEnabled'].some(key => key in changes))) {
    void reporting.reset().then(() => reporting.refreshAlarm()).catch(() => {});
  }
  if (area === 'session' && CREDENTIAL in changes) {
    void resetProtection(true).catch(() => {});
  } else if (area === 'local' && ['backendOrigin', 'monitoringEnabled'].some(key => key in changes)) {
    void resetProtection(false).catch(() => {});
  } else if (area === 'local' && 'monitoredSites' in changes) {
    invalidateRequests();
    void refreshOpenPages().catch(() => {});
  }
});

chrome.permissions.onRemoved.addListener(() => {
  void resetProtection(false).catch(() => {});
  void reporting.reset().then(() => reporting.refreshAlarm()).catch(() => {});
});

chrome.alarms.onAlarm.addListener(alarm => {
  if (alarm.name === REPUTATION_REFRESH) {
    void setup.then(synchronizeRules).then(refreshOpenPages).then(reporting.heartbeat).catch(() => {});
  } else if (alarm.name === REPORTING_ALARM) {
    void initialRules.then(reporting.heartbeat).catch(() => {});
  } else if (alarm.name.startsWith(BYPASS_ALARM)) {
    void protection.expire(Number(alarm.name.slice(BYPASS_ALARM.length))).catch(() => {});
  }
});
const initialRules = setup.then(synchronizeRules).catch(() => {});
void initialRules.then(reporting.refreshAlarm).catch(() => {});

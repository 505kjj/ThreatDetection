import { detectImpersonation } from './impersonation.mjs';
import { checkDestination, destinationFor, threatFor } from './reputation.mjs';

const BYPASS_MS = 20000;
const WARNING_MS = 30 * 60000;
const warningKey = tabId => 'network-warning:' + tabId;
export const BYPASS_ALARM = 'network-bypass:';

export function createBrowserProtection(chrome, rules, now = Date.now) {
  const warningPage = chrome.runtime.getURL('warning.html');
  const starts = new Map();
  const admitted = new Map();
  const claims = new Set();
  const opening = new Map();
  const storage = chrome.storage.session;

  const pageFor = token => warningPage + '#' + token;
  const isWarning = url => url?.split('#', 1)[0] === warningPage;
  const discard = tabId => storage.remove(warningKey(tabId));

  async function start(details) {
    const { tabId, frameId, timeStamp, url } = details;
    if (frameId !== 0) return;
    starts.set(tabId, { timeStamp });
    admitted.delete(tabId);
    const bypass = rules.bypass(tabId);
    if (bypass && (bypass.key !== url || bypass.deadline <= now())) await rules.revoke(tabId);
  }

  function unchanged(tabId, marker) {
    return starts.get(tabId) === marker;
  }

  async function show(details, phase) {
    const { tabId, url, timeStamp } = details;
    const marker = starts.get(tabId);
    if (timeStamp < (marker?.timeStamp ?? 0) ||
        (opening.has(tabId) && opening.get(tabId) === marker)) return;
    const destination = destinationFor(url);
    const snapshot = rules.snapshot();
    if (!destination || !snapshot) return;
    opening.set(tabId, marker);
    try {
      const result = await checkDestination(snapshot, destination, now);
      if (result.state !== 'confirmed' || !unchanged(tabId, marker) || rules.snapshot() !== snapshot) return;
      if (phase === 'after_commit') {
        const frame = await chrome.webNavigation.getFrame({ tabId, frameId: 0 }).catch(() => null);
        if (frame?.documentId !== details.documentId || destinationFor(frame?.url)?.key !== destination.key) return;
      }
      if (!unchanged(tabId, marker) || rules.snapshot() !== snapshot) return;
      const token = crypto.randomUUID();
      const resume = result.threat === 'PHISHING' && phase === 'before_request'
        ? resumeDestination(result.evidence, destination) : null;
      await storage.set({ [warningKey(tabId)]: { token, host: destination.host, evidence: result.evidence,
        phase, threat: result.threat, until: Math.min(now() + WARNING_MS, result.expires), resume } });
      if (unchanged(tabId, marker) && rules.snapshot() === snapshot) {
        // The warning is never a web-accessible resource.
        await chrome.tabs.update(tabId, { url: pageFor(token) });
      }
    } finally {
      if (opening.get(tabId) === marker) opening.delete(tabId);
    }
  }

  async function failed(details) {
    if (details.frameId !== 0) return;
    if (rules.bypass(details.tabId)) await rules.revoke(details.tabId);
    if (details.error === 'net::ERR_BLOCKED_BY_CLIENT') await show(details, 'before_request');
  }

  async function committed(details) {
    const { tabId, frameId, url, documentId, timeStamp, documentLifecycle } = details;
    if (frameId !== 0 || (documentLifecycle && documentLifecycle !== 'active')) return;
    starts.set(tabId, { timeStamp });
    const bypass = rules.bypass(tabId);
    admitted.delete(tabId);
    if (bypass) await rules.revoke(tabId);
    if (isWarning(url)) return;
    await discard(tabId);
    if (bypass?.key === url && bypass.deadline > now()) {
      admitted.set(tabId, { documentId, key: bypass.key });
      return;
    }
    await show(details, 'after_commit');
  }

  async function history(details) {
    if (details.frameId !== 0 || (details.documentLifecycle && details.documentLifecycle !== 'active')) return;
    starts.set(details.tabId, { timeStamp: details.timeStamp });
    const accepted = admitted.get(details.tabId);
    if (accepted?.documentId === details.documentId && accepted.key === destinationFor(details.url)?.key) return;
    await show(details, 'after_commit');
  }

  async function remove(tabId) {
    starts.delete(tabId);
    admitted.delete(tabId);
    opening.delete(tabId);
    await Promise.all([discard(tabId), rules.revoke(tabId)]);
  }

  async function warningContext(tabId) {
    const contexts = await chrome.runtime.getContexts({ contextTypes: ['TAB'], tabIds: [tabId], frameIds: [0] });
    return contexts.find(context => isWarning(context.documentUrl));
  }

  async function verified(sender, token) {
    const tabId = sender.tab?.id;
    if (!Number.isInteger(tabId) || sender.frameId !== 0 || sender.documentLifecycle !== 'active' ||
        !sender.documentId || !isWarning(sender.url)) return null;
    const context = await warningContext(tabId);
    if (context?.documentId !== sender.documentId) return null;
    const key = warningKey(tabId);
    const { [key]: warning } = await storage.get(key);
    return warning && warning.token === token ? warning : null;
  }

  function current(warning) {
    const snapshot = rules.snapshot();
    return warning && warning.until > now() && snapshot &&
      threatFor(snapshot, warning.evidence) === warning.threat ? snapshot : null;
  }

  async function tabStatus(tabId) {
    const context = await warningContext(tabId);
    if (!context) return null;
    const key = warningKey(tabId);
    const { [key]: record } = await storage.get(key);
    if (context.documentUrl !== pageFor(record?.token)) return { state: 'unavailable', cause: 'reputation' };
    return current(record) ? { state: 'confirmed', host: record.host, threat: record.threat,
      impersonation: detectImpersonation(record.host) } : { state: 'unavailable', cause: 'reputation' };
  }

  async function message(type, sender, token) {
    const record = await verified(sender, token);
    if (type === 'LEAVE_NETWORK_WARNING') {
      if (record) await discard(sender.tab.id);
      return { active: false };
    }
    if (record && record.until <= now()) await discard(sender.tab.id);
    const snapshot = current(record);
    if (!record || !snapshot) return { active: false };
    const tabId = sender.tab.id;
    if (type === 'GET_NETWORK_WARNING') {
      return { active: true, host: record.host, kind: record.evidence.kind, phase: record.phase,
        threat: record.threat, until: Math.min(record.until, snapshot.expires), canProceed: !!record.resume,
        impersonation: detectImpersonation(record.host) };
    }
    if (type !== 'PROCEED_ONCE' || !record.resume || claims.has(tabId)) return { active: false };
    claims.add(tabId);
    try {
      const deadline = Math.min(now() + BYPASS_MS, record.until, snapshot.expires);
      if (!await rules.allowOnce(tabId, record.resume, deadline)) return { active: false };
      if ((await verified(sender, token))?.token !== record.token || current(record) !== snapshot || deadline <= now()) {
        await rules.revoke(tabId);
        return { active: false };
      }
      await discard(tabId);
      await chrome.alarms.create(BYPASS_ALARM + tabId, { when: deadline });
      setTimeout(() => void expire(tabId).catch(() => {}), Math.max(0, deadline - now()));
      return { active: true, destination: record.resume, deadline };
    } catch (error) {
      await rules.revoke(tabId);
      throw error;
    } finally {
      claims.delete(tabId);
    }
  }

  async function expire(tabId) {
    const bypass = rules.bypass(tabId);
    if (bypass && bypass.deadline <= now()) await rules.revoke(tabId);
  }

  return { start, failed, committed, history, remove, message, expire, tabStatus };
}

function resumeDestination(evidence, destination) {
  if (evidence.kind === 'URL_PATH') return evidence.value;
  if (evidence.kind === 'HOST') return new URL(destination.key).origin + '/';
  return null;
}

import { postMonitoring } from './backend-api.mjs';

export const REPORTING_ALARM = 'threat-reporting';
const JOURNAL = 'threat-reporting-journal';
const JOURNAL_TTL = 5 * 60000;
const JOURNAL_LIMIT = 256;

export function createThreatReporting(chrome, connection, reputationAvailable) {
  let cancellation = new AbortController();
  let active = null;
  let lastHeartbeat = null;
  let queue = Promise.resolve();
  let lastResult = 'waiting';
  let pending = 0;
  const session = chrome.storage.session;

  function serial(operation) {
    const result = queue.then(operation);
    queue = result.catch(() => {});
    return result;
  }

  function reset() {
    cancellation.abort();
    cancellation = new AbortController();
    active = null;
    lastHeartbeat = null;
    lastResult = 'waiting';
    const signal = cancellation.signal;
    return serial(async () => {
      if (!signal.aborted) await session.remove(JOURNAL);
    });
  }

  async function refreshAlarm() {
    const signal = cancellation.signal;
    const credential = await connection();
    if (signal.aborted) return;
    if (!credential) {
      await chrome.alarms.clear(REPORTING_ALARM);
      return;
    }
    if (!await chrome.alarms.get(REPORTING_ALARM) && !signal.aborted) {
      await chrome.alarms.create(REPORTING_ALARM, { periodInMinutes: 1 });
    }
    await heartbeat();
  }

  async function sendHeartbeat(credential, signal, force = false) {
    const now = Date.now();
    const protection = reputationAvailable() ? 'REPUTATION_AVAILABLE' : 'REPUTATION_UNAVAILABLE';
    if (!force && lastHeartbeat?.id === credential.id && lastHeartbeat.protection === protection &&
        now - lastHeartbeat.at < 45000) return;
    await postMonitoring(credential, 'heartbeat', { protection }, signal);
    signal.throwIfAborted();
    lastHeartbeat = { id: credential.id, protection, at: now };
    lastResult = 'connected';
  }

  function heartbeat() {
    if (active) return active;
    const signal = cancellation.signal;
    const operation = serial(async () => {
      const credential = await connection();
      if (!credential || signal.aborted) return;
      try {
        await sendHeartbeat(credential, signal);
      } catch {
        if (!signal.aborted) lastResult = 'disconnected';
      }
    });
    active = operation;
    return operation.finally(() => { if (active === operation) active = null; });
  }

  async function remember(credentialId, key, time) {
    const { [JOURNAL]: entries = [] } = await session.get(JOURNAL);
    const recent = entries.filter(entry => entry.credentialId === credentialId && time - entry.at < JOURNAL_TTL);
    if (recent.some(entry => entry.key === key)) return false;
    recent.push({ credentialId, key, at: time });
    await session.set({ [JOURNAL]: recent.slice(-JOURNAL_LIMIT) });
    return true;
  }

  function report(signalCode, action, navigationKey, dedupeSignal = signalCode) {
    const signal = cancellation.signal;
    const detectedAt = Date.now();
    // Limit queued requests even during an outage. Protection does not wait for this queue.
    if (pending >= 8) return;
    pending++;
    void serial(async () => {
      if (signal.aborted || Date.now() - detectedAt > 15000) return;
      const credential = await connection();
      if (!credential || signal.aborted ||
          !await remember(credential.id, [dedupeSignal, action, navigationKey].join(':'), detectedAt) ||
          signal.aborted) return;
      const body = { id: crypto.randomUUID(), signal: signalCode, action,
        detectedAt: new Date(detectedAt).toISOString() };
      await sendHeartbeat(credential, signal);
      const accepted = await postMonitoring(credential, 'events', body, signal);
      if (!accepted) {
        // A restarted backend may have forgotten a previously accepted heartbeat.
        await sendHeartbeat(credential, signal, true);
        await postMonitoring(credential, 'events', body, signal);
      }
    }).catch(() => {
      if (!signal.aborted) lastResult = 'disconnected';
    }).finally(() => pending--);
  }

  return { report, refreshAlarm, reset, heartbeat, status: () => lastResult };
}

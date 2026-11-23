const SESSION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const BROWSER_TOKEN = /^[A-Za-z0-9_-]{43}$/;
const ACTION_TYPES = new Map([
  ['page_view', 'navigation'],
  ['navigation_change', 'navigation'],
  ['password_focus', 'sensitive_action'],
  ['form_focus', 'sensitive_action'],
  ['form_submit', 'sensitive_action'],
  ['rapid_clicking', 'behavior_anomaly'],
  ['copy_paste', 'behavior_anomaly'],
  ['tab_blur', 'session_anomaly'],
  ['heartbeat', 'normal_action'],
  ['recheck_risk', 'normal_action']
]);

export function validToken(value) {
  return typeof value === 'string' && BROWSER_TOKEN.test(value);
}

function boundedInteger(value, min, max, fallback = 0) {
  return Number.isInteger(value) ? Math.min(max, Math.max(min, value)) : fallback;
}

export function analysisFields(event, redirected) {
  const actionType = ACTION_TYPES.get(event?.eventType);
  if (!actionType) return null;
  return {
    eventType: event.eventType,
    actionType,
    pageCategory: event.sensitivePage === true ? 'sensitive_page' : 'normal_page',
    redirectCount: redirected ? 1 : 0,
    averageClickGapMs: boundedInteger(event.averageClickGapMs, -1, 10000, -1),
    clicksLast10Sec: boundedInteger(event.clicksLast10Sec, 0, 1000),
    pagesVisitedLast30Sec: boundedInteger(event.pagesVisitedLast30Sec, 0, 1000),
    tabSwitchCount: boundedInteger(event.tabSwitchCount, 0, 1000),
    copyPasteCount: boundedInteger(event.copyPasteCount, 0, 1000),
    formSubmitCount: boundedInteger(event.formSubmitCount, 0, 1000)
  };
}

class BackendStatus extends Error {
  constructor(status) {
    super('Backend request failed');
    this.status = status;
  }
}

function request(credential, route, signal, payload) {
  return fetch(credential.origin + '/api/threat/' + route, {
    method: payload ? 'POST' : 'GET',
    headers: {
      Authorization: 'Bearer ' + credential.token,
      ...(payload ? { 'Content-Type': 'application/json' } : {}),
      Accept: 'application/json'
    },
    body: payload ? JSON.stringify(payload) : undefined,
    credentials: 'omit',
    redirect: 'error',
    referrerPolicy: 'no-referrer',
    cache: 'no-store',
    signal: AbortSignal.any([signal, AbortSignal.timeout(5000)])
  });
}

async function post(credential, route, payload, signal) {
  const response = await request(credential, route, signal, payload);
  if (!response.ok) throw new BackendStatus(response.status);
  return response.json();
}

export async function downloadSnapshot(credential) {
  // A transport failure can use the previous still-fresh snapshot. A server rejection cannot.
  const response = await request(credential, 'reputation/snapshot', new AbortController().signal);
  if (!response.ok || !response.body) return null;
  const limit = 3 * 1024 * 1024;
  const reader = response.body.getReader();
  const decoder = new TextDecoder('utf-8', { fatal: true });
  let json = '';
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return JSON.parse(json + decoder.decode());
      size += value.byteLength;
      if (size > limit) return null;
      json += decoder.decode(value, { stream: true });
    }
  } catch {
    return null;
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

export async function startSession(credential, host, signal) {
  const result = await post(credential, 'session/start', { domain: host }, signal);
  if (typeof result?.sessionId !== 'string' || !SESSION_ID.test(result.sessionId)) {
    throw new Error('Invalid session response');
  }
  return result.sessionId;
}

export async function analyze(credential, sessionId, fields, signal) {
  let result;
  try {
    result = await post(credential, 'analyze', { sessionId, ...fields }, signal);
  } catch (error) {
    if (error instanceof BackendStatus && error.status === 404) return null;
    throw error;
  }
  const { riskLevel, riskScore, action, reasons } = result ?? {};
  const state = riskLevel === 'Safe' && action === 'ALLOW' ? 'safe'
    : riskLevel === 'Suspicious' && action === 'SHOW_WARNING' ? 'warning' : null;
  if (!state || !Number.isInteger(riskScore) || (state === 'safe' ? riskScore < 0 || riskScore > 30
    : riskScore < 31 || riskScore > 60) || !Array.isArray(reasons)) {
    throw new Error('Invalid behavior verdict');
  }
  return {
    state,
    riskScore,
    reasons: reasons.filter(reason => typeof reason === 'string').slice(0, 8).map(reason => reason.slice(0, 200))
  };
}

export function requestFailure(error) {
  return error instanceof BackendStatus && [401, 403].includes(error.status) ? 'authentication' : 'backend';
}

const byId = id => document.getElementById(id);
const categories = {
  PHISHING: 'Phishing',
  MALWARE: 'Malware',
  FINANCIAL_IMPERSONATION: 'Financial impersonation',
  SUSPICIOUS_BEHAVIOR: 'Suspicious behavior'
};
const sources = { REPUTATION: 'Reputation snapshot', FINANCIAL_RULES: 'Financial domain rules',
  BEHAVIOR_RULES: 'Activity rules' };
const actions = { BLOCKED: 'Blocked', WARNED: 'Warned', BYPASSED: 'Bypassed' };
const severities = { HIGH: 'High', CAUTION: 'Caution' };
const number = new Intl.NumberFormat();
const date = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'medium' });
let token = '';
let scope = 'REAL';
let pending;

function status(text, state = '') {
  byId('backend-state').textContent = text;
  byId('backend-state').dataset.state = state;
}

function showToken(visible) {
  byId('token').type = visible ? 'text' : 'password';
  byId('show-token').setAttribute('aria-pressed', String(visible));
  byId('show-token').setAttribute('aria-label', visible ? 'Hide token' : 'Show token');
}

function navigate(threats, focus = true) {
  byId('overview').hidden = threats;
  byId('page-title').textContent = threats ? 'Threat Centre' : 'Security overview';
  byId('page-description').textContent = threats ? 'Review the latest reported event evidence.' : 'Reports from browsers that opted in to monitoring.';
  byId('history-title').textContent = threats ? 'Reported events' : 'Recent detections';
  byId(threats ? 'nav-threats' : 'nav-overview').setAttribute('aria-current', 'page');
  byId(threats ? 'nav-overview' : 'nav-threats').removeAttribute('aria-current');
  if (focus) byId('page-title').focus();
}

function plain(tag, content, className) {
  const node = document.createElement(tag);
  node.textContent = content;
  if (className) node.className = className;
  return node;
}

function clearData() {
  byId('snapshot').hidden = true;
  byId('history').replaceChildren();
  byId('categories').replaceChildren();
  byId('extension-state').textContent = '';
  byId('reputation-state').textContent = '';
  byId('last-contact').textContent = '';
  byId('retention').textContent = '';
  for (const metric of ['total', 'blocked', 'warned', 'bypassed']) byId(metric).textContent = '';
}

function signOut(message = '') {
  pending?.abort();
  pending = undefined;
  token = '';
  clearData();
  byId('token').value = '';
  showToken(false);
  byId('sign-in-button').disabled = false;
  byId('sign-in-error').textContent = message;
  byId('sign-in-error').hidden = !message;
  byId('sign-in').hidden = false;
  byId('dashboard').hidden = true;
  status('Signed out');
}

function render(result) {
  for (const metric of ['total', 'blocked', 'warned', 'bypassed']) {
    byId(metric).textContent = number.format(result[metric]);
  }
  const breakdown = Object.entries(categories).map(([key, label]) => {
    const row = document.createElement('div');
    row.append(plain('dt', label), plain('dd', number.format(result.categories[key])));
    return row;
  });
  byId('categories').replaceChildren(...breakdown);
  byId('retention').textContent = 'Last ' + result.retentionDays + ' days. Bypasses are counted separately from detections.';
  const available = result.clientStatus.REPUTATION_AVAILABLE;
  const unavailable = result.clientStatus.REPUTATION_UNAVAILABLE;
  const count = available + unavailable;
  byId('extension-state').textContent = count
    ? count + (count === 1 ? ' browser reporting' : ' browsers reporting')
    : 'No recent contact from reporting browsers';
  byId('reputation-state').textContent = count
    ? [available && available + ' with current reputation data', unavailable && unavailable + ' reporting protection unavailable']
      .filter(Boolean).join(' · ')
    : 'Unknown until a browser reports';
  byId('last-contact').textContent = result.lastContact ? date.format(new Date(result.lastContact)) : 'No heartbeat received';
  const rows = result.recent.map(entry => {
    const row = document.createElement('tr');
    const detection = plain('td', categories[entry.category]);
    const timestamp = plain('time', date.format(new Date(entry.detectedAt)));
    timestamp.dateTime = entry.detectedAt;
    detection.append(timestamp);
    const action = document.createElement('td');
    action.append(plain('span', actions[entry.action], 'badge action-' + entry.action.toLowerCase()));
    const evidence = plain('td', entry.reason);
    const outcome = entry.action === 'BLOCKED' ? 'Navigation interrupted before reaching the destination.'
      : entry.action === 'BYPASSED' ? 'A one-time exception was used in that tab.'
        : entry.source === 'REPUTATION' ? 'The browser opened a warning after navigation.'
          : 'An advisory was shown without blocking.';
    evidence.append(plain('p', outcome));
    evidence.append(plain('small', sources[entry.source] + ' · ' + severities[entry.severity]));
    row.append(detection, action, evidence);
    return row;
  });
  byId('history').replaceChildren(...rows);
  byId('empty-history').hidden = rows.length > 0;
  byId('history-table').hidden = rows.length === 0;
  byId('snapshot').hidden = false;
  byId('load-state').hidden = true;
}

async function refresh(initial = false, preserve = false) {
  if (!token) return;
  pending?.abort();
  const request = new AbortController();
  pending = request;
  const requestedScope = scope;
  if (!preserve) {
    clearData();
    byId('load-state').textContent = 'Loading reports…';
    byId('load-state').hidden = false;
    status('Connecting…');
  }
  byId('scope-notice').hidden = requestedScope !== 'SYNTHETIC';
  try {
    const response = await fetch('/api/threat/monitoring/dashboard?scope=' + requestedScope, {
      headers: { Authorization: 'Bearer ' + token, Accept: 'application/json' },
      credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer', cache: 'no-store',
      signal: AbortSignal.any([request.signal, AbortSignal.timeout(5000)])
    });
    if (request.signal.aborted) return;
    if (response.status === 401 || response.status === 403) {
      signOut('Access denied. Enter a valid admin token for this backend.');
      return;
    }
    if (response.status === 503 && response.headers.get('X-Threat-Monitoring-Status') === 'storage-unavailable') {
      clearData();
      byId('sign-in').hidden = true;
      byId('dashboard').hidden = false;
      status('Backend reachable', 'error');
      byId('load-state').textContent = 'Monitoring storage unavailable. Try refreshing after the database recovers.';
      byId('load-state').hidden = false;
      return;
    }
    if (!response.ok) throw new Error('Dashboard request failed');
    const result = await response.json();
    if (request.signal.aborted) return;
    if (result.synthetic !== (requestedScope === 'SYNTHETIC')) throw new Error('Unexpected data scope');
    render(result);
    byId('sign-in').hidden = true;
    byId('dashboard').hidden = false;
    status('Backend connected', 'ok');
    if (initial) byId('page-title').focus();
  } catch {
    if (request.signal.aborted) return;
    const message = 'Backend unavailable. Reports and browser protection status could not be refreshed.';
    if (initial) {
      signOut(message);
    } else {
      clearData();
      status('Backend unavailable', 'error');
      byId('load-state').textContent = message;
      byId('load-state').hidden = false;
    }
  } finally {
    if (pending === request) {
      pending = undefined;
      byId('sign-in-button').disabled = false;
    }
  }
}

function selectScope(value) {
  scope = value;
  byId('real').setAttribute('aria-pressed', String(value === 'REAL'));
  byId('synthetic').setAttribute('aria-pressed', String(value === 'SYNTHETIC'));
}

byId('token-form').addEventListener('submit', event => {
  event.preventDefault();
  const supplied = byId('token').value.trim();
  byId('token').value = '';
  showToken(false);
  if (!/^[A-Za-z0-9_-]{43}$/.test(supplied)) {
    signOut('Enter the 43-character admin token issued for this backend.');
    return;
  }
  token = supplied;
  selectScope('REAL');
  navigate(false, false);
  byId('sign-in-error').hidden = true;
  byId('sign-in-button').disabled = true;
  void refresh(true);
});
byId('show-token').addEventListener('click', () => showToken(byId('token').type === 'password'));
byId('theme').addEventListener('click', () => {
  const light = document.documentElement.dataset.theme !== 'light';
  document.documentElement.dataset.theme = light ? 'light' : 'dark';
  byId('theme').setAttribute('aria-pressed', String(light));
  byId('theme').setAttribute('aria-label', light ? 'Use dark appearance' : 'Use light appearance');
});
byId('nav-overview').addEventListener('click', () => navigate(false));
byId('nav-threats').addEventListener('click', () => navigate(true));
for (const [id, value] of [['real', 'REAL'], ['synthetic', 'SYNTHETIC']]) {
  byId(id).addEventListener('click', () => {
    selectScope(value);
    void refresh();
  });
}
byId('refresh').addEventListener('click', () => void refresh());
byId('sign-out').addEventListener('click', () => {
  signOut();
  byId('token').focus();
});
window.addEventListener('pagehide', () => signOut());
setInterval(() => {
  if (!pending && !byId('dashboard').hidden && document.visibilityState === 'visible') void refresh(false, true);
}, 30000);

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
let recentEvents = [];
let chartData = '';
let threatView = false;
let sortKey = 'detectedAt';
let sortDirection = -1;
const counts = new Map();
const motion = matchMedia('(prefers-reduced-motion: reduce)');
const metricNames = ['total', 'blocked', 'warned', 'bypassed'];
const chartColors = ['violet', 'red', 'lilac', 'amber'];

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
  threatView = threats;
  byId('event-filters').hidden = !threats;
  byId('overview').hidden = threats;
  byId('page-title').textContent = threats ? 'Threat Centre' : 'Security overview';
  byId('page-description').textContent = threats ? 'Review the latest reported event evidence.' : 'Reports from browsers that opted in to monitoring.';
  byId('history-title').textContent = threats ? 'Reported events' : 'Recent detections';
  byId(threats ? 'nav-threats' : 'nav-overview').setAttribute('aria-current', 'page');
  byId(threats ? 'nav-overview' : 'nav-threats').removeAttribute('aria-current');
  renderHistory();
  if (focus) byId('page-title').focus();
}

function plain(tag, content, className) {
  const node = document.createElement(tag);
  node.textContent = content;
  if (className) node.className = className;
  return node;
}

function clearData() {
  byId('event-drawer').close();
  byId('drawer-fields').replaceChildren();
  byId('drawer-reason').textContent = '';
  byId('drawer-outcome').textContent = '';
  recentEvents = [];
  chartData = '';
  byId('filter-count').textContent = '';
  byId('snapshot').hidden = true;
  byId('history').replaceChildren();
  byId('categories').replaceChildren();
  byId('extension-state').textContent = '';
  byId('reputation-state').textContent = '';
  byId('last-contact').textContent = '';
  byId('retention').textContent = '';
  for (const id of ['activity-chart', 'category-chart', 'source-chart']) byId(id).replaceChildren();
  for (const metric of metricNames) {
    const state = counts.get(metric);
    if (state) cancelAnimationFrame(state.frame);
    byId(metric).textContent = '';
    byId(metric + '-visual').textContent = '';
  }
  counts.clear();
}

function signOut(message = '') {
  pending?.abort();
  pending = undefined;
  token = '';
  clearData();
  resetFilters();
  byId('token').value = '';
  showToken(false);
  byId('sign-in-button').disabled = false;
  byId('sign-in-error').textContent = message;
  byId('sign-in-error').hidden = !message;
  byId('sign-in').hidden = false;
  byId('dashboard').hidden = true;
  status('Signed out');
}

function metricValue(metric, value, animate) {
  byId(metric).textContent = number.format(value);
  const visual = byId(metric + '-visual');
  const previous = counts.get(metric);
  if (previous?.target === value && (animate || previous.value === value)) return;
  if (previous) cancelAnimationFrame(previous.frame);
  const start = animate && !motion.matches ? (previous?.value ?? 0) : value;
  const state = { value: start, target: value, frame: 0 };
  counts.set(metric, state);
  visual.textContent = number.format(start);
  if (start === value) return;
  const begun = performance.now();
  const tick = now => {
    const progress = Math.min(1, (now - begun) / 700);
    state.value = Math.round(start + (value - start) * (1 - (1 - progress) ** 3));
    visual.textContent = number.format(state.value);
    if (progress < 1) state.frame = requestAnimationFrame(tick);
  };
  state.frame = requestAnimationFrame(tick);
}

function vector(tag, attributes = {}, value) {
  const element = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [key, entry] of Object.entries(attributes)) element.setAttribute(key, entry);
  if (value !== undefined) element.textContent = value;
  return element;
}

function chart(id, summary, viewBox) {
  const svg = vector('svg', { role: 'img', 'aria-label': summary, viewBox, class: 'chart' });
  svg.append(vector('title', {}, summary));
  byId(id).replaceChildren(svg);
  return svg;
}

function chartEmpty(id, message) {
  byId(id).replaceChildren(plain('p', message, 'chart-empty muted'));
}

function renderCategories(result) {
  const items = Object.entries(categories).map(([key, label], i) => ({
    label, value: result.categories[key], color: chartColors[i]
  }));
  byId('categories').replaceChildren(...items.map(({label, value, color}) => {
    const row = document.createElement('div');
    const term = plain('dt', label);
    term.prepend(plain('span', '', 'legend-dot color-' + color));
    row.append(term, plain('dd', number.format(value)));
    return row;
  }));
  if (result.total === 0) {
    chartEmpty('category-chart', 'No reported detections');
    return;
  }
  const svg = chart('category-chart', items.map(({label, value}) => label + ': ' + value).join(', '), '0 0 140 140');
  svg.append(vector('circle', {cx: 70, cy: 70, r: 53, class: 'donut-track'}));
  let offset = 0;
  for (const {label, value, color} of items) {
    if (!value) continue;
    const portion = 100 * value / result.total;
    const segment = vector('circle', {cx: 70, cy: 70, r: 53, pathLength: 100,
      'stroke-dasharray': portion + ' ' + (100 - portion), 'stroke-dashoffset': -offset,
      transform: 'rotate(-90 70 70)', class: 'donut-segment color-' + color});
    segment.append(vector('title', {}, label + ': ' + number.format(value)));
    svg.append(segment);
    offset += portion;
  }
  svg.append(vector('text', {x: 70, y: 77, 'text-anchor': 'middle', class: 'donut-value'}, number.format(result.total)));
}

function renderActivity(events) {
  const dates = {};
  for (const event of events) {
    const key = event.detectedAt.slice(0, 10);
    dates[key] = (dates[key] ?? 0) + 1;
  }
  const items = Object.entries(dates).sort(([a], [b]) => a.localeCompare(b));
  if (!items.length) return chartEmpty('activity-chart', 'No detections in the recent event sample.');
  const svg = chart('activity-chart', items.map(([day, count]) => day + ': ' + count).join(', '), '0 0 540 165');
  const defs = vector('defs');
  const gradient = vector('linearGradient', {id: 'activity-gradient', x2: '0%', y2: '100%'});
  gradient.append(vector('stop', {offset: 0, class: 'area-top'}), vector('stop', {offset: 1, class: 'area-bottom'}));
  defs.append(gradient);
  svg.append(defs);
  const maximum = Math.max(...items.map(([, count]) => count));
  for (const ratio of [0, .5, 1]) {
    const y = 132 - 108 * ratio;
    svg.append(vector('line', {x1: 32, x2: 517, y1: y, y2: y, class: 'chart-grid'}));
    if (ratio !== .5) svg.append(vector('text', {x: 24, y: y + 4, 'text-anchor': 'end', class: 'chart-label'}, Math.round(ratio * maximum)));
  }
  const points = items.map(([, value], i) => [items.length === 1 ? 270 : 40 + 465 * i / (items.length - 1), 132 - 108 * value / maximum]);
  if (points.length > 1) {
    const line = points.map(([x, y]) => x + ',' + y).join(' ');
    svg.append(vector('polygon', {points: points[0][0] + ',132 ' + line + ' ' + points.at(-1)[0] + ',132', class: 'activity-area'}));
    svg.append(vector('polyline', {points: line, class: 'activity-line'}));
  }
  points.forEach(([x, y], i) => {
    const [day, count] = items[i];
    if (points.length === 1) svg.append(vector('line', {x1: x, x2: x, y1: 132, y2: y, class: 'chart-grid'}));
    const point = vector('circle', {cx: x, cy: y, r: 5, class: 'activity-point'});
    point.append(vector('title', {}, day + ': ' + count + ' reported'));
    svg.append(point);
    if (i === 0 || i === points.length - 1) svg.append(vector('text', {x, y: 155, 'text-anchor': 'middle', class: 'chart-label'}, day.slice(5)));
  });
}

function renderSources(events) {
  if (!events.length) return chartEmpty('source-chart', 'No detections in the recent event sample.');
  const rows = Object.entries(sources).map(([key, label]) => {
    const count = events.filter(event => event.source === key).length;
    const row = plain('div', '', 'source-row');
    const labelRow = plain('div', '', 'section-heading');
    labelRow.append(plain('span', label), plain('strong', number.format(count)));
    const progress = document.createElement('progress');
    progress.max = events.length;
    progress.value = count;
    progress.setAttribute('aria-label', label + ' share of recent detections');
    row.append(labelRow, progress);
    return row;
  });
  byId('source-chart').replaceChildren(...rows);
}

const filters = {category: 'filter-category', severity: 'filter-severity', action: 'filter-action', source: 'filter-source'};
const labels = {category: categories, severity: severities, action: actions, source: sources};
for (const [key, id] of Object.entries(filters)) {
  for (const [value, label] of Object.entries(labels[key])) {
    byId(id).append(new Option(label, value));
  }
}

function resetFilters() {
  byId('event-filters').reset();
  sortKey = 'detectedAt';
  sortDirection = -1;
  updateSort();
}

function updateSort() {
  for (const button of document.querySelectorAll('[data-sort]')) {
    if (button.dataset.sort === sortKey) button.parentElement.setAttribute('aria-sort', sortDirection < 0 ? 'descending' : 'ascending');
    else button.parentElement.removeAttribute('aria-sort');
  }
}

function eventOutcome(entry) {
  if (entry.action === 'BLOCKED') return 'Navigation interrupted before reaching the destination.';
  if (entry.action === 'BYPASSED') return 'A one-time exception was used in that tab.';
  return entry.source === 'REPUTATION' ? 'The browser opened a warning after navigation.' : 'An advisory was shown without blocking.';
}

function inspect(entry) {
  const details = [['Detected at', date.format(new Date(entry.detectedAt))],
    ['Category', categories[entry.category]], ['Severity', severities[entry.severity]],
    ['Action', actions[entry.action]], ['Detection source', sources[entry.source]]];
  byId('drawer-fields').replaceChildren(...details.map(([key, value]) => {
    const row = document.createElement('div');
    row.append(plain('dt', key), plain('dd', value));
    return row;
  }));
  byId('drawer-reason').textContent = entry.reason;
  byId('drawer-outcome').textContent = eventOutcome(entry);
  byId('event-drawer').showModal();
}

function renderHistory() {
  const query = byId('event-search').value.trim().toLowerCase();
  const day = byId('filter-day').value;
  const entries = recentEvents.filter(entry => !threatView ||
    ((!day || entry.detectedAt.startsWith(day)) && Object.entries(filters).every(([field, id]) => !byId(id).value || byId(id).value === entry[field]) &&
      (!query || [entry.reason, ...Object.keys(labels).map(key => labels[key][entry[key]])].join(' ').toLowerCase().includes(query))));
  entries.sort((a, b) => sortDirection * String(labels[sortKey]?.[a[sortKey]] ?? a[sortKey])
    .localeCompare(String(labels[sortKey]?.[b[sortKey]] ?? b[sortKey])));
  const rows = entries.map(entry => {
    const row = document.createElement('tr');
    const detection = plain('td', categories[entry.category]);
    const timestamp = plain('time', date.format(new Date(entry.detectedAt)));
    timestamp.dateTime = entry.detectedAt;
    detection.append(timestamp);
    const action = document.createElement('td');
    action.append(plain('span', actions[entry.action], 'badge action-' + entry.action.toLowerCase()));
    const evidence = plain('td', entry.reason);
    evidence.append(plain('small', sources[entry.source] + ' · ' + severities[entry.severity]));
    const detailCell = document.createElement('td');
    const button = plain('button', 'Details', 'quiet');
    button.type = 'button';
    button.setAttribute('aria-label', 'Details for ' + categories[entry.category] + ', ' + date.format(new Date(entry.detectedAt)));
    button.addEventListener('click', () => inspect(entry));
    detailCell.append(button);
    row.append(detection, action, evidence, detailCell);
    return row;
  });
  byId('history').replaceChildren(...rows);
  byId('filter-count').textContent = entries.length + ' of ' + recentEvents.length + ' recent events';
  byId('empty-history').textContent = recentEvents.length ? 'No recent events match your filters.' : 'No events reported for this view. Reporting is optional.';
  byId('empty-history').hidden = rows.length > 0;
  byId('history-table').hidden = rows.length === 0;
}

function render(result, animate) {
  for (const metric of metricNames) metricValue(metric, result[metric], animate);
  const nextChartData = JSON.stringify([result.categories, result.recent]);
  if (byId('snapshot').hidden || nextChartData !== chartData) {
    renderCategories(result);
    const detections = result.recent.filter(entry => entry.action !== 'BYPASSED');
    renderActivity(detections);
    renderSources(detections);
    recentEvents = result.recent;
    renderHistory();
    chartData = nextChartData;
  }
  byId('retention').textContent = result.retentionDays + '-day reporting window';
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
    render(result, initial || preserve);
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
    if (scope === value) return;
    selectScope(value);
    resetFilters();
    void refresh();
  });
}
byId('refresh').addEventListener('click', () => void refresh(false, true));
byId('event-filters').addEventListener('submit', event => event.preventDefault());
byId('event-filters').addEventListener('input', renderHistory);
byId('clear-filters').addEventListener('click', () => {
  resetFilters();
  renderHistory();
});
byId('close-drawer').addEventListener('click', () => byId('event-drawer').close());
for (const button of document.querySelectorAll('[data-sort]')) button.addEventListener('click', () => {
  sortDirection = sortKey === button.dataset.sort ? -sortDirection : 1;
  sortKey = button.dataset.sort;
  updateSort();
  renderHistory();
});
motion.addEventListener('change', () => {
  if (!motion.matches) return;
  for (const [name, state] of counts) metricValue(name, state.target, false);
});
byId('sign-out').addEventListener('click', () => {
  signOut();
  byId('token').focus();
});
window.addEventListener('pagehide', () => signOut());
setInterval(() => {
  if (!pending && !byId('dashboard').hidden && document.visibilityState === 'visible') void refresh(false, true);
}, 30000);

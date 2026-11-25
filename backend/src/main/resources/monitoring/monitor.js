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
const views = {
  overview: ['Security overview', 'Reports from browsers that opted in to monitoring.'],
  threats: ['Threat Centre', 'Review the latest reported event evidence.'],
  intelligence: ['Threat Intelligence', 'Check the reputation provider and its current snapshot.'],
  financial: ['Financial Protection', 'Verified financial domains and local advisory coverage.'],
  ml: ['ML Laboratory', 'Compare frozen offline phishing research.'],
  visual: ['Visual Intelligence', 'Review controlled financial-brand similarity experiments.'],
  datasets: ['Dataset Laboratory', 'Review provenance, cohort construction and evaluation eligibility.'],
  browsers: ['Connected Browsers', 'Heartbeat and reputation availability in the selected scope.'],
  health: ['System Health', 'Check the APIs used by this console.'],
  privacy: ['Privacy Centre', 'Review the data used by optional browser reporting.'],
  settings: ['Settings', 'Set your console preferences and find local setup instructions.']
};
const reportViews = new Set(['overview', 'threats', 'browsers', 'health']);
const feedViews = new Set(['intelligence', 'health']);
const researchViews = new Set(['financial', 'ml', 'visual', 'datasets']);
const modelNames = {
  'url-ngram': 'Character TF-IDF', 'url-xgboost': 'Lexical XGBoost', 'url-blend': 'URL-only blend',
  'dom-full': 'DOM full', 'dom-reduced': 'DOM reduced', 'dom-regularized': 'DOM regularized',
  'dom-context': 'DOM context', 'dom-weighted': 'DOM weighted', fixed: 'Fixed 75:25 fusion',
  stack: 'Logistic stacking', adaptive: 'Adaptive fusion', selective: 'Selective content routing',
  ngram: 'Character TF-IDF', cnn: 'Character CNN', xgboost: 'Lexical XGBoost',
  mixed: 'Source-balanced TF-IDF', fusion: 'Frozen URL-only blend',
  transformer: 'Lightweight Transformer', logistic: 'Numerical Logistic Regression', logistic_regression: 'Numerical Logistic Regression',
  forest: 'Random Forest', random_forest: 'Random Forest', mlp: 'Small MLP',
  'url-weighted-75': 'TF-IDF and XGBoost 75:25',
  'dom-logistic': 'DOM Logistic Regression', 'dom-forest': 'DOM Random Forest', 'dom-xgboost': 'DOM XGBoost',
  'url-dom-xgboost': 'URL and DOM XGBoost', 'url-fusion': 'URL-only ensemble', 'url-dom-fusion': 'URL and DOM fusion',
  'phresh-20000-path-forest': 'Hostname and path Random Forest',
  'fusion-mixed-20000-two': 'Two-model weighted fusion',
  'fusion-mixed-20000-four': 'Four-model weighted fusion',
  'fusion-mixed-20000-stack': 'Stacked fusion'
};
const percent = new Intl.NumberFormat(undefined, { style: 'percent', maximumFractionDigits: 2, minimumFractionDigits: 2 });
const fixed = new Intl.NumberFormat(undefined, { maximumFractionDigits: 4, minimumFractionDigits: 4 });
const cutoffNumber = new Intl.NumberFormat(undefined, { maximumSignificantDigits: 10 });
const milli = value => value.toFixed(2) + ' ms';
const batchTime = value => value.toFixed(4) + ' ms';
const metricOptions = {
  recall: ['Recall', value => percent.format(value)],
  precision: ['Precision', value => percent.format(value)],
  f1: ['F1-score', value => percent.format(value)],
  prAuc: ['PR-AUC (average precision)', value => fixed.format(value)],
  rocAuc: ['ROC-AUC', value => fixed.format(value)],
  urlFpr: ['URL false-positive rate', value => percent.format(value)],
  domainFpr: ['Domain false-positive rate', value => percent.format(value)],
  domainFprUpper: ['Domain FPR 95% upper bound', value => percent.format(value)],
  computeMs: ['Median inference', milli],
  batchMs: ['Batch inference per URL', batchTime],
  projectionMs: ['Median including projection', milli],
  bytes: ['Checkpoint size', value => number.format(value) + ' B'],
  fitSeconds: ['Reported fitting time', value => value.toFixed(2) + ' s']
};
const thresholdMetrics = new Set(['recall', 'precision', 'f1', 'urlFpr', 'domainFpr', 'domainFprUpper']);
const cutoffNames = {
  '0.01': '1% domain FPR calibration target',
  '0.001': '0.1% domain FPR calibration target',
  '0.0001': '0.01% domain FPR calibration target',
  '0.5': 'Fixed score cutoff 0.5'
};
let comparisons = [];
let token = '';
let scope = 'REAL';
let pending;
let feedPending;
let researchPending;
let research;
let activeView = 'overview';
let viewMotion;
let arrivalMotion;
let entranceShown = false;
let recentEvents = [];
let chartData = '';
let sortKey = 'detectedAt';
let sortDirection = -1;
const counts = new Map();
const motion = matchMedia('(prefers-reduced-motion: reduce)');
const metricNames = ['total', 'blocked', 'warned', 'bypassed'];
const chartColors = ['violet', 'red', 'lilac', 'amber'];
const activeCharts = new WeakMap();
const architecture = {
  fusion: [
    ['URL and DOM inputs', 'Phase 5F matched URL text with sanitized structural features from the same record. Models used the grouped training and validation partitions.'],
    ['Character TF-IDF', 'Character sequences from the URL become weighted sparse features. The URL model scores these features without looking at page content.'],
    ['Weighted DOM classifier', 'The content model scores structural inputs such as form, navigation and document features. Training upweights selected benign records. Diagnostic fixtures were scored after fitting.'],
    ['Calibration and fusion', 'Tuning calibrates the component scores. The fixed blend assigns 75% to URL evidence and 25% to DOM evidence. A separate calibration partition determines the cutoff.'],
    ['Experimental score', 'The blended score is compared with a frozen research cutoff. Phase 5G evaluated zero eligible independent paired records.']
  ],
  cnn: [
    ['URL characters', 'Phase 5C encodes up to 160 URL characters as token IDs and masks padding.'],
    ['Token embeddings', 'The model maps token IDs to 16-dimensional character embeddings.'],
    ['Parallel convolutions', 'Convolutions with widths 3, 5 and 7 find character patterns across different local spans.'],
    ['Masked max pooling', 'The model takes the strongest valid activation across each branch. Padded positions contribute no evidence.'],
    ['Binary research score', 'The pooled features feed a binary score head. Cutoffs and evaluation outcomes are reported in the Phase 5C cohort.']
  ],
  transformer: [
    ['URL character prefix', 'Phase 5D uses up to 80 URL characters and the Phase 5C character vocabulary.'],
    ['Position and character embeddings', 'The encoder combines learned character and position embeddings and includes a classification token.'],
    ['Attention encoders', 'Two encoder layers with four attention heads each relate characters across nonpadding input.'],
    ['Classification token', 'The binary head reads the contextual representation of the classification token.'],
    ['Temporal comparison', 'The same family was evaluated on separately dated near and far cohorts. Switch cohorts below to inspect each result.']
  ]
};
const datasetSteps = [
  ['Raw data', 'Offline development uses pinned published sources. Licenses and ingestion records establish eligible inputs.'],
  ['Validation', 'The pipeline checks the required fields, labels and eligibility criteria before accepting records.'],
  ['Normalization', 'Canonical URLs and structural feature extraction provide consistent inputs for the relevant experiment.'],
  ['Deduplication', 'The experiment removes overlapping domains and repeated records. Phase 5F also quarantines structural overlap across partitions.'],
  ['Partitioning', 'Training, tuning, calibration and validation use separate partitions. Phase 5D also separates chronological windows.'],
  ['Model representations', 'Experiments use numerical URL features, character sequences or matched DOM structure. This view presents only aggregate receipts.']
];
const visualSteps = [
  ['Reference crops', 'Phase 6A used three reference crops and controlled transformations. A production logo locator is unimplemented.'],
  ['Normalize pixels', 'Readable crops are normalized before comparison. The tested native browser preprocessing missed the documented parity threshold.'],
  ['Calculate similarity', 'pHash compares perceptual fingerprints, ORB compares local keypoints and MobileNetV3 compares image embeddings.'],
  ['Review evidence', 'Visual matches need independent verification and verified brand-domain context. Low-quality, ambiguous or absent evidence remains inconclusive.']
];

function status(text, state = '') {
  const element = byId('backend-state');
  if (element.textContent !== text) element.textContent = text;
  element.dataset.state = state;
}

function health(backend, storage, auth) {
  byId('health-backend').textContent = backend;
  byId('health-storage').textContent = storage;
  byId('health-auth').textContent = auth;
}

function showToken(visible) {
  byId('token').type = visible ? 'text' : 'password';
  byId('show-token').setAttribute('aria-pressed', String(visible));
  byId('show-token').setAttribute('aria-label', visible ? 'Hide token' : 'Show token');
}

function navigate(view, focus = true) {
  const threats = view === 'threats';
  const changed = view !== activeView;
  activeView = view;
  byId('event-filters').hidden = !threats;
  byId('report-toolbar').hidden = !reportViews.has(view);
  byId('load-state').classList.toggle('scope-independent', !reportViews.has(view));
  byId('report-placeholder').classList.toggle('scope-independent', view !== 'overview');
  byId('scope-notice').classList.toggle('scope-independent', !reportViews.has(view));
  for (const [id, [title, description]] of Object.entries(views)) {
    const button = byId('nav-' + id);
    if (view === id) {
      button.setAttribute('aria-current', 'page');
      byId('page-title').textContent = title;
      byId('page-description').textContent = description;
    } else button.removeAttribute('aria-current');
    byId(id).hidden = id === 'threats' ? !['overview', 'threats'].includes(view) : id !== view;
  }
  byId('history-title').textContent = threats ? 'Reported events' : 'Recent detections';
  if (view === 'overview' || threats) renderHistory();
  if (feedViews.has(view)) {
    if (!feedPending || feedPending.signal.aborted) void refreshFeed();
  } else feedPending?.abort();
  byId('research-state').hidden = !researchViews.has(view) || Boolean(research);
  if (researchViews.has(view) && !research) void loadResearch();
  if (focus) byId('page-title').focus();
  if (changed && !reducedMotion()) {
    viewMotion?.cancel();
    viewMotion = byId(view).animate([{opacity: .78, transform: 'translateY(4px)'}, {opacity: 1, transform: 'none'}],
      {duration: 220, easing: 'ease-out'});
  }
}

function plain(tag, content, className) {
  const node = document.createElement(tag);
  node.textContent = content;
  if (className) node.className = className;
  return node;
}

function renderDiagram(stepsId, detailId, stages) {
  const list = byId(stepsId);
  const detail = byId(detailId);
  const rows = stages.map(([label, explanation], index) => {
    const row = document.createElement('li');
    const button = plain('button', label);
    button.type = 'button';
    button.setAttribute('aria-pressed', String(index === 0));
    button.setAttribute('aria-controls', detailId);
    button.addEventListener('click', () => {
      list.querySelector('[aria-pressed="true"]')?.setAttribute('aria-pressed', 'false');
      button.setAttribute('aria-pressed', 'true');
      if (detail.textContent === explanation) return;
      detail.textContent = explanation;
      if (!reducedMotion()) detail.animate([{opacity: .64}, {opacity: 1}], {duration: 210, easing: 'ease-out'});
    });
    row.append(button);
    return row;
  });
  list.replaceChildren(...rows);
  detail.textContent = stages[0][1];
}

function clearData() {
  arrivalMotion?.cancel();
  byId('report-arrival').textContent = '';
  byId('event-drawer').close();
  byId('drawer-fields').replaceChildren();
  byId('drawer-reason').textContent = '';
  byId('drawer-outcome').textContent = '';
  recentEvents = [];
  chartData = '';
  byId('filter-count').textContent = '';
  byId('snapshot').hidden = true;
  byId('report-placeholder').hidden = true;
  resetChartTooltip(byId('activity-tooltip'));
  resetChartTooltip(byId('category-tooltip'));
  byId('history').replaceChildren();
  byId('categories').replaceChildren();
  byId('extension-state').textContent = '';
  byId('reputation-state').textContent = '';
  byId('last-contact').textContent = '';
  byId('retention').textContent = '';
  byId('privacy-retention').textContent = 'The configured retention window is unavailable.';
  renderReporting();
  for (const id of ['activity-chart', 'category-chart', 'source-chart']) byId(id).replaceChildren();
  for (const metric of metricNames) {
    const state = counts.get(metric);
    if (state) {
      cancelAnimationFrame(state.frame);
      state.roll?.cancel();
    }
    byId(metric).textContent = '';
    byId(metric + '-visual').textContent = '';
  }
  counts.clear();
}

function signOut(message = '') {
  pending?.abort();
  pending = undefined;
  feedPending?.abort();
  feedPending = undefined;
  setFeedStatus('Unavailable');
  researchPending?.abort();
  researchPending = undefined;
  research = undefined;
  comparisons = [];
  byId('ml-controls').disabled = true;
  viewMotion?.cancel();
  entranceShown = false;
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
  byId('skip-content').href = '#sign-in-title';
  if (message) byId('token').focus();
  status('Signed out');
}

function reducedMotion() {
  return motion.matches || byId('reduce-motion').checked;
}

function metricValue(metric, value, animate) {
  byId(metric).textContent = number.format(value);
  const visual = byId(metric + '-visual');
  const previous = counts.get(metric);
  if (previous?.target === value && (animate || previous.value === value)) return;
  if (previous) {
    cancelAnimationFrame(previous.frame);
    previous.roll?.cancel();
  }
  const start = animate && !reducedMotion() ? (previous?.value ?? 0) : value;
  const state = { value: start, target: value, frame: 0 };
  counts.set(metric, state);
  visual.textContent = number.format(start);
  if (start === value) return;
  const rise = start < value ? '24%' : '-24%';
  state.roll = visual.animate([{transform: 'translateY(' + rise + ')'}, {transform: 'none'}],
    {duration: 270, easing: 'cubic-bezier(.22,.76,.24,1)'});
  const begun = performance.now();
  const tick = now => {
    const progress = Math.min(1, (now - begun) / 610);
    const next = Math.round(start + (value - start) * (1 - (1 - progress) ** 2.4));
    if (next !== state.value) {
      state.value = next;
      visual.textContent = number.format(next);
    }
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

function chart(id, summary, viewBox, role = 'img') {
  const svg = vector('svg', { role, 'aria-label': summary, viewBox, class: 'chart' });
  svg.append(vector('title', {}, summary));
  byId(id).replaceChildren(svg);
  return svg;
}

function chartEmpty(id, message) {
  byId(id).replaceChildren(plain('p', message, 'chart-empty muted'));
}

function resetChartTooltip(tooltip) {
  activeCharts.get(tooltip)?.forEach(element => element.removeAttribute('data-chart-active'));
  activeCharts.delete(tooltip);
  tooltip.hidden = true;
}

function chartTarget(target, tooltip, label, related = []) {
  const show = () => {
    resetChartTooltip(tooltip);
    const highlighted = [target, ...related];
    highlighted.forEach(element => element.setAttribute('data-chart-active', ''));
    activeCharts.set(tooltip, highlighted);
    tooltip.textContent = label;
    tooltip.hidden = false;
  };
  const hide = () => {
    if (activeCharts.get(tooltip)?.includes(target)) resetChartTooltip(tooltip);
  };
  target.addEventListener('pointerenter', show);
  target.addEventListener('focus', show);
  target.addEventListener('blur', hide);
  target.addEventListener('click', show);
  target.addEventListener('keydown', event => {
    if (event.key === 'Escape') hide();
    if (target instanceof SVGElement && (event.key === 'Enter' || event.key === ' ')) {
      event.preventDefault();
      show();
    }
  });
}

function renderCategories(result) {
  const tooltip = byId('category-tooltip');
  resetChartTooltip(tooltip);
  const items = Object.entries(categories).map(([key, label], i) => ({
    label, value: result.categories[key], color: chartColors[i]
  }));
  const svg = result.total
    ? chart('category-chart', items.map(({label, value}) => label + ': ' + value).join(', '), '0 0 140 140')
    : undefined;
  const slices = svg && vector('g', {class: 'donut-slices'});
  if (svg) svg.append(vector('circle', {cx: 70, cy: 70, r: 53, class: 'donut-track'}), slices);
  else chartEmpty('category-chart', 'No reported detections');
  let offset = 0;
  byId('categories').replaceChildren(...items.map(({label, value, color}) => {
    const row = document.createElement('div');
    const term = document.createElement('dt');
    const control = svg ? plain('button', label, 'legend-control') : plain('span', label);
    const dot = plain('span', '', 'legend-dot color-' + color);
    dot.setAttribute('aria-hidden', 'true');
    control.prepend(dot);
    term.append(control);
    row.append(term, plain('dd', number.format(value)));
    if (!svg) return row;

    control.type = 'button';
    const share = value / result.total;
    const description = label + ' · ' + number.format(value) + ' of ' + number.format(result.total) + ' · ' + percent.format(share);
    control.setAttribute('aria-label', description);
    if (value) {
      const portion = 100 * share;
      const segment = vector('circle', {cx: 70, cy: 70, r: 53, pathLength: 100,
        'stroke-dasharray': portion + ' ' + (100 - portion), 'stroke-dashoffset': -offset,
        transform: 'rotate(-90 70 70)', class: 'donut-segment color-' + color});
      slices.append(segment);
      chartTarget(control, tooltip, description, [segment]);
      chartTarget(segment, tooltip, description, [control]);
      offset += portion;
    } else chartTarget(control, tooltip, description);
    return row;
  }));
  svg?.append(vector('text', {x: 70, y: 77, 'text-anchor': 'middle', class: 'donut-value'}, number.format(result.total)));
}

function renderActivity(events) {
  const tooltip = byId('activity-tooltip');
  resetChartTooltip(tooltip);
  const dates = {};
  for (const event of events) {
    const key = event.detectedAt.slice(0, 10);
    dates[key] = (dates[key] ?? 0) + 1;
  }
  const items = Object.entries(dates).sort(([a], [b]) => a.localeCompare(b));
  if (!items.length) return chartEmpty('activity-chart', 'No detections in the recent event sample.');
  const svg = chart('activity-chart', 'Detection activity by UTC day, latest report sample', '0 0 540 165', 'group');
  const defs = vector('defs');
  const gradient = vector('linearGradient', {id: 'activity-gradient', x2: '0%', y2: '100%'});
  gradient.append(vector('stop', {offset: 0, class: 'area-top'}), vector('stop', {offset: 1, class: 'area-bottom'}));
  defs.append(gradient);
  svg.append(defs);
  const maximum = Math.max(...items.map(([, count]) => count));
  for (const count of [...new Set([0, Math.ceil(maximum / 2), maximum])]) {
    const y = 132 - 101 * count / maximum;
    svg.append(vector('line', {x1: 32, x2: 517, y1: y, y2: y, class: 'chart-grid'}));
    svg.append(vector('text', {x: 24, y: y + 4, 'text-anchor': 'end', class: 'chart-label'}, count));
  }
  const firstDay = Date.parse(items[0][0]);
  const elapsed = Date.parse(items.at(-1)[0]) - firstDay;
  const points = items.map(([day, value]) => [elapsed ? 40 + 465 * (Date.parse(day) - firstDay) / elapsed : 270,
    132 - 101 * value / maximum]);
  if (points.length > 1) {
    const line = points.map(([x, y]) => x + ',' + y).join(' ');
    svg.append(vector('polygon', {points: points[0][0] + ',132 ' + line + ' ' + points.at(-1)[0] + ',132', class: 'activity-area'}));
    svg.append(vector('polyline', {points: line, pathLength: 1, class: 'activity-line'}));
  }
  points.forEach(([x, y], i) => {
    const [day, count] = items[i];
    if (points.length === 1) {
      svg.append(vector('rect', {x: x - 17, y, width: 34, height: 132 - y, rx: 5, class: 'activity-stem'}));
      svg.append(vector('text', {x, y: y - 12, 'text-anchor': 'middle', class: 'activity-value'}, count));
    }
    const description = day + ' UTC · ' + number.format(count) + (count === 1 ? ' detection' : ' detections');
    const point = vector('g', {tabindex: 0, role: 'button', 'aria-label': description, class: 'chart-point'});
    point.append(vector('circle', {cx: x, cy: y, r: 25, class: 'chart-point-hit'}),
      vector('circle', {cx: x, cy: y, r: 5, class: 'activity-point'}));
    chartTarget(point, tooltip, description);
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
  byId('close-drawer').focus();
}

function renderHistory() {
  const query = byId('event-search').value.trim().toLowerCase();
  const day = byId('filter-day').value;
  const entries = recentEvents.filter(entry => activeView !== 'threats' ||
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
    const evidence = plain('td', '', 'event-evidence');
    evidence.append(plain('span', entry.reason, 'event-reason'),
      plain('small', sources[entry.source] + ' · ' + severities[entry.severity]));
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
  const countLabel = entries.length + ' of ' + recentEvents.length + ' recent events';
  if (byId('filter-count').textContent !== countLabel) byId('filter-count').textContent = countLabel;
  byId('empty-history').textContent = recentEvents.length ? 'No recent events match your filters.' : 'No events reported for this view. Reporting is optional.';
  byId('empty-history').hidden = rows.length > 0;
  byId('history-table').hidden = rows.length === 0;
}

function render(result) {
  for (const metric of metricNames) metricValue(metric, result[metric], true);
  const nextChartData = JSON.stringify([result.categories, result.recent]);
  if (byId('snapshot').hidden || nextChartData !== chartData) {
    const newest = result.recent[0]?.detectedAt;
    const liveArrival = scope === 'REAL' && !byId('snapshot').hidden && newest > (recentEvents[0]?.detectedAt ?? '');
    renderCategories(result);
    const detections = result.recent.filter(entry => entry.action !== 'BYPASSED');
    renderActivity(detections);
    renderSources(detections);
    recentEvents = result.recent;
    renderHistory();
    chartData = nextChartData;
    if (liveArrival && (activeView === 'overview' || activeView === 'threats')) {
      const announcement = byId('report-arrival');
      announcement.textContent = 'New report received at ' + date.format(new Date(newest));
      if (!reducedMotion()) {
        arrivalMotion?.cancel();
        arrivalMotion = byId('history').firstElementChild?.animate(
          [{backgroundColor: 'var(--accent-wash)'}, {backgroundColor: 'transparent'}], {duration: 420, easing: 'ease-out'});
      }
    }
  }
  byId('retention').textContent = result.retentionDays + '-day reporting window';
  byId('privacy-retention').textContent = `The configured reporting window is ${result.retentionDays} days. Expired reports are removed by the backend.`;
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
  renderReporting(result);
  byId('snapshot').hidden = false;
  byId('load-state').hidden = true;
  byId('report-placeholder').hidden = true;
  if (!entranceShown && !reducedMotion()) {
    document.querySelectorAll('.metric').forEach((card, index) => {
      card.animate([{opacity: .62, transform: 'translateY(6px)'}, {opacity: 1, transform: 'none'}],
        {duration: 265, delay: index * 32, easing: 'ease-out', fill: 'backwards'});
    });
  }
  entranceShown = true;
}

function statusRows(id, fields) {
  byId(id).replaceChildren(...fields.map(([key, value]) => {
    const row = document.createElement('div');
    row.append(plain('dt', key), plain('dd', value));
    return row;
  }));
}

function renderReporting(result) {
  const contact = result?.lastContact ? date.format(new Date(result.lastContact)) : 'No heartbeat received';
  const available = result?.clientStatus.REPUTATION_AVAILABLE;
  const unavailable = result?.clientStatus.REPUTATION_UNAVAILABLE;
  const unknown = 'Unavailable';
  const fields = [
    ['Fresh browser heartbeats', result ? number.format(available + unavailable) : unknown],
    ['Reputation available', result ? number.format(available) : unknown],
    ['Reputation unavailable', result ? number.format(unavailable) : unknown],
    ['Last successful heartbeat', result ? contact : unknown]
  ];
  statusRows('browser-report', fields);
  statusRows('health-report', fields);
}

function authenticatedGet(path, request) {
  return fetch(path, {
    headers: { Authorization: 'Bearer ' + token, Accept: 'application/json' },
    credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer', cache: 'no-store',
    signal: AbortSignal.any([request.signal, AbortSignal.timeout(5000)])
  });
}

function setFeedStatus(label, fields = []) {
  byId('health-feed').textContent = label;
  byId('feed-message').textContent = label;
  statusRows('feed-details', fields);
}

function comparisonRow(label, detail, value, maximum) {
  const row = plain('div', '', 'source-row comparison-row');
  const head = plain('div', '', 'section-heading');
  head.append(plain('span', label), plain('strong', detail));
  row.append(head);
  if (Number.isFinite(value)) {
    const bar = document.createElement('progress');
    bar.max = maximum;
    bar.value = value;
    bar.setAttribute('aria-hidden', 'true');
    row.append(bar);
  }
  return row;
}

function phaseName(phase) {
  return phase.replace(/^phase(\d)(\w)$/, (_, year, step) => 'Phase ' + year + step.toUpperCase());
}

function selectExperiment() {
  const cohort = comparisons.find(entry => entry.id === byId('ml-experiment').value);
  if (!cohort) return;
  const cutoffs = Object.entries(cutoffNames).filter(([id]) => cohort.models.some(model => model.points[id]));
  byId('ml-cutoff').replaceChildren(...cutoffs.map(([id, label]) => new Option(label, id)));
  compareModels();
}

function compareModels() {
  const cohort = comparisons.find(entry => entry.id === byId('ml-experiment').value);
  if (!cohort) return;
  const cutoff = byId('ml-cutoff').value;
  const values = key => cohort.models.map(model => (thresholdMetrics.has(key) ? model.points[cutoff] : model)?.[key]);
  for (const option of byId('ml-metric').options) option.disabled = !values(option.value).some(Number.isFinite);
  const select = byId('ml-metric');
  if (select.selectedOptions[0]?.disabled) select.value = [...select.options].find(option => !option.disabled).value;
  const metric = select.value;
  const [, format] = metricOptions[metric];
  const observed = values(metric);
  const max = ['computeMs', 'batchMs', 'projectionMs', 'bytes', 'fitSeconds'].includes(metric)
    ? Math.max(0, ...observed.filter(Number.isFinite)) || 1 : 1;
  const context = thresholdMetrics.has(metric) && cutoff !== '0.5' ? ' Cutoffs use ' + cohort.calibration + '.'
    : ['prAuc', 'rocAuc'].includes(metric) ? ' Ranking metrics are threshold-free.' : '';
  byId('ml-cohort').textContent = `${phaseName(cohort.phase)} (${cohort.revision.slice(0, 7)}) · ${cohort.dataset} · ${number.format(cohort.rows)} rows (${number.format(cohort.positive)} phishing). ${cohort.description}${context}`;
  byId('ml-models').replaceChildren(...cohort.models.map((model, index) => {
    const numeric = Number.isFinite(observed[index]);
    const row = comparisonRow(modelNames[model.id] ?? model.id, numeric ? format(observed[index]) : 'Unavailable', observed[index], max);
    row.setAttribute('role', 'listitem');
    const details = model.training ? ['Training source ' + model.training] : [];
    const point = model.points[cutoff];
    if (thresholdMetrics.has(metric) && point) details.push('Score cutoff ' + cutoffNumber.format(point.threshold));
    if (details.length) row.append(plain('small', details.join(' · '), 'muted'));
    return row;
  }));
}

function renderResearch(data) {
  byId('brand-cards').replaceChildren(...data.financial.map(brand => {
    const card = plain('article', '', 'panel brand-card');
    const heading = plain('h2', brand.name);
    const scopes = document.createElement('ul');
    scopes.append(...brand.scopes.map(scope => plain('li', scope)));
    card.append(heading, scopes);
    if (brand.sharedHosts) card.append(plain('p', 'Verified shared host ' + brand.sharedHosts.join(', '), 'muted'));
    return card;
  }));
  const { ml, datasets, visual, revisions } = data;
  const browserResearch = data.browserResearch;
  const securityResearch = data.securityResearch;
  const scalabilityResearch = data.scalabilityResearch;
  if (scalabilityResearch) {
    byId('scalability-research-status').textContent = scalabilityResearch.status;
    byId('scalability-research-result').textContent = scalabilityResearch.result;
    byId('scalability-research-limitations').textContent = scalabilityResearch.limitations;
  }
  if (securityResearch) {
    byId('security-research-status').textContent = securityResearch.status + ' ' + securityResearch.scope;
    byId('security-research-categories').textContent = securityResearch.categories.join(' · ');
    byId('security-research-limitations').textContent = securityResearch.limitations;
  }
  if (browserResearch) {
    byId('browser-research-scope').textContent = browserResearch.scope + ' ' + browserResearch.readiness;
    statusRows('browser-research-models', browserResearch.models.map(model => [model.name,
      `${number.format(model.bytes)} B · ${milli(model.p95Ms)} p95 · max error ${model.maxError.toExponential(2)} (${model.fixtures} fixtures) · ${model.runtime}`]));
    byId('browser-research-memory').textContent = `${number.format(browserResearch.jobPeakBytes)} B peak. ${browserResearch.jobPeakScope}`;
  }
  const lead = ml.models.find(model => model.id === 'fixed');
  byId('ml-lead').textContent = 'Retrospective Phase 5F PhreshPhish v1.0.1 development results. Calibrated score cutoff ' + cutoffNumber.format(lead.threshold) + '.';
  statusRows('ml-metrics', ['recall', 'precision', 'f1', 'domainFpr', 'prAuc'].map(key => {
    const [label, format] = metricOptions[key];
    return [label, format(lead[key])];
  }));
  byId('ml-ready').textContent = `Phase 5G (${revisions.phase5g}) froze ${ml.frozen.length} candidates. Independent URL rows scored ${ml.fresh}. Independent paired rows scored ${ml.paired}. Verified financial positives ${ml.financialIndia} in India and ${ml.financialOther} elsewhere.`;
  byId('ml-frozen').textContent = ml.frozen.map(id => modelNames[id]).join(' · ');
  const { seconds, peakBytes, logicalCpus } = ml.trainingResources;
  byId('ml-resources').textContent = `Phase 5F guarded run used ${logicalCpus} logical CPUs, ${seconds.toFixed(2)} s wall time and ${(peakBytes / 2 ** 30).toFixed(2)} GiB peak committed memory.`;
  comparisons = [{
    id: 'grouped-5f', phase: 'phase5f', revision: revisions.phase5f, dataset: 'PhreshPhish v1.0.1',
    name: 'Domain- and template-grouped fusion', rows: ml.validationRows, positive: ml.validationPositive,
    description: 'Retrospective grouped PhreshPhish validation on identical rows. Timings cover 200 development rows.',
    calibration: `a separate set of ${number.format(ml.calibrationDomains)} PhreshPhish calibration domains`,
    models: ml.models.map(model => ({...model, points: {'0.01': model}}))
  }, ...ml.cohorts];
  byId('ml-experiment').replaceChildren(...comparisons.map(cohort =>
    new Option(phaseName(cohort.phase) + ' · ' + cohort.name, cohort.id)));
  byId('ml-controls').disabled = false;
  selectExperiment();

  const phish = datasets.phishvn;
  byId('phishvn-summary').textContent = `Version ${phish.release}, ${phish.license}. Latest eligible source observation ${phish.lastObservation}, before the registered forward window starting ${phish.forwardStart}. Rows scored ${phish.scored}.`;
  statusRows('dataset-splits', Object.entries(datasets.splits).map(([key, count]) => {
    const [negative, positive] = datasets.classCounts[key].kept;
    const removed = datasets.classCounts[key].removed.reduce((sum, value) => sum + value, 0);
    const label = key[0].toUpperCase() + key.slice(1);
    return [label, `${number.format(count)} used · ${number.format(removed)} grouped exclusions · ${number.format(negative)} benign and ${number.format(positive)} phishing eligible before balancing`];
  }));
  byId('dataset-caveat').textContent = `Phase 5E matched ${number.format(datasets.matchedRows)} publisher records and retained ${number.format(datasets.usableRows)} usable rows across partitions. Phase 5F audited ${number.format(datasets.exactCollisionRows)} validation records with an identical training DOM vector. The structural proxy produced ${number.format(datasets.components)} components. Its largest grouped ${number.format(datasets.largestComponent)} rows and can span unrelated pages.`;

  const methodNames = { phash: 'Perceptual hashing', orb: 'ORB matching', mobilenet: 'MobileNetV3 embeddings' };
  byId('visual-scope').textContent = `Three original crops (${visual.references.join(', ')}) with ${visual.transformed} same-family transforms and ${visual.unrelated} unrelated invented crops. Phase 6A (${revisions.phase6a}).`;
  byId('visual-methods').replaceChildren(...visual.methods.map(method => {
    const row = comparisonRow(methodNames[method.id], `${method.correct}/${visual.transformed} correct`, method.correct, visual.transformed);
    row.append(plain('small', `${method.falseMatches}/${visual.unrelated} false matches · ${milli(method.medianMs)} median · ${milli(method.p95Ms)} p95 · ${number.format(method.referenceBytes)} B reference data`, 'muted'));
    return row;
  }));
  byId('visual-ready').textContent = `Independent evaluation scored ${visual.independentRows} visual and ${visual.paired} paired cases. Native-canvas preprocessing ${visual.canvasParity ? 'passed' : 'failed'} the 0.97 parity gate with a minimum cosine of ${visual.canvasMinimum.toFixed(5)}.`;
}

async function loadResearch() {
  if (!token || research || researchPending) return;
  const request = new AbortController();
  const state = byId('research-state');
  researchPending = request;
  state.textContent = 'Loading versioned research summary…';
  state.hidden = false;
  try {
    const response = await authenticatedGet('/api/threat/monitoring/research-summary', request);
    if (request.signal.aborted) return;
    if (response.status === 401 || response.status === 403) {
      signOut('Access denied. Enter a valid admin token for this backend.');
      return;
    }
    if (!response.ok) throw new Error('Research summary unavailable');
    const summary = await response.json();
    if (request.signal.aborted) return;
    research = summary;
    renderResearch(summary);
    state.hidden = true;
  } catch {
    if (!request.signal.aborted) {
      research = undefined;
      state.textContent = 'Research summary unavailable. Use Refresh to retry.';
      state.hidden = !researchViews.has(activeView);
    }
  } finally {
    if (researchPending === request) researchPending = undefined;
  }
}

async function refreshFeed() {
  if (!token || !feedViews.has(activeView)) return;
  feedPending?.abort();
  const request = new AbortController();
  feedPending = request;
  setFeedStatus('Checking the managed feed…');
  try {
    const response = await authenticatedGet('/api/threat/reputation/feed-status', request);
    if (request.signal.aborted) return;
    if (response.status === 401 || response.status === 403) {
      signOut('Access denied. Enter a valid admin token for this backend.');
      return;
    }
    if (!response.ok) throw new Error('Feed status request failed');
    const result = await response.json();
    if (request.signal.aborted) return;
    if (result.pollState === 'DISABLED') {
      setFeedStatus('Managed feed disabled');
      return;
    }
    const snapshots = { CURRENT: 'Current snapshot', STALE: 'Snapshot expired', MISSING: 'Snapshot unavailable' };
    const polls = { WAITING: 'Waiting for first poll', AVAILABLE: 'Latest poll succeeded', FEED_FAILED: 'Feed request failed', PUBLISH_FAILED: 'Snapshot publication failed' };
    setFeedStatus(snapshots[result.dataState] ?? 'Snapshot status unknown', [
      ['Provider', result.provider === 'CERT_POLSKA' ? 'CERT Polska' : 'Unknown'],
      ['Poll status', polls[result.pollState] ?? 'Unknown'],
      ['Last successful update', result.lastSuccessAt ? date.format(new Date(result.lastSuccessAt)) : 'No successful update'],
      ['Snapshot expires', result.expiresAt ? date.format(new Date(result.expiresAt)) : 'Unavailable'],
      ['Browser distribution', result.browserDistributionApproved ? 'Approved' : 'Disabled']
    ]);
  } catch {
    if (!request.signal.aborted) setFeedStatus('Feed status unavailable');
  } finally {
    if (feedPending === request) feedPending = undefined;
  }
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
    byId('report-placeholder').hidden = initial;
    status('Connecting…');
    health('Checking…', 'Checking…', initial ? 'Checking…' : 'Previously verified');
  }
  byId('scope-notice').hidden = requestedScope !== 'SYNTHETIC';
  try {
    const response = await authenticatedGet('/api/threat/monitoring/dashboard?scope=' + requestedScope, request);
    if (request.signal.aborted) return;
    if (response.status === 401 || response.status === 403) {
      signOut('Access denied. Enter a valid admin token for this backend.');
      return;
    }
    if (response.status === 503 && response.headers.get('X-Threat-Monitoring-Status') === 'storage-unavailable') {
      clearData();
      byId('sign-in').hidden = true;
      byId('dashboard').hidden = false;
      byId('skip-content').href = '#page-title';
      status('Backend reachable', 'error');
      health('Reachable', 'Unavailable', 'Verified');
      byId('load-state').textContent = 'Monitoring storage unavailable. Try refreshing after the database recovers.';
      byId('load-state').hidden = false;
      if (initial) byId('page-title').focus();
      return;
    }
    if (!response.ok) throw new Error('Dashboard request failed');
    const result = await response.json();
    if (request.signal.aborted) return;
    if (result.synthetic !== (requestedScope === 'SYNTHETIC')) throw new Error('Unexpected data scope');
    render(result);
    byId('sign-in').hidden = true;
    byId('dashboard').hidden = false;
    byId('skip-content').href = '#page-title';
    status('Backend connected', 'ok');
    health('Reachable', 'Dashboard query succeeded', 'Verified');
    if (initial) byId('page-title').focus();
  } catch {
    if (request.signal.aborted) return;
    const message = 'Backend unavailable. Reports and browser protection status could not be refreshed.';
    if (initial) {
      signOut(message);
    } else {
      clearData();
      status('Backend unavailable', 'error');
      health('Unavailable', 'Unknown', 'Unable to recheck');
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
  navigate('overview', false);
  byId('sign-in-error').hidden = true;
  byId('sign-in-button').disabled = true;
  void refresh(true);
});
byId('show-token').addEventListener('click', () => showToken(byId('token').type === 'password'));
function setTheme(light) {
  document.documentElement.dataset.theme = light ? 'light' : 'dark';
  byId('appearance').value = light ? 'light' : 'dark';
  byId('theme').setAttribute('aria-pressed', String(light));
  byId('theme').setAttribute('aria-label', light ? 'Use dark appearance' : 'Use light appearance');
}
byId('theme').addEventListener('click', () => setTheme(document.documentElement.dataset.theme !== 'light'));
byId('appearance').addEventListener('change', event => setTheme(event.target.value === 'light'));
byId('rail-density').addEventListener('click', event => {
  const compact = byId('dashboard').toggleAttribute('data-compact');
  event.currentTarget.setAttribute('aria-pressed', String(compact));
});
function showArchitecture() {
  renderDiagram('architecture-steps', 'architecture-detail', architecture[byId('architecture-model').value]);
}
byId('architecture-model').addEventListener('change', showArchitecture);
showArchitecture();
renderDiagram('dataset-steps', 'dataset-detail', datasetSteps);
renderDiagram('visual-steps', 'visual-detail', visualSteps);
for (const [id, [label]] of Object.entries(metricOptions)) {
  const option = plain('option', label);
  option.value = id;
  byId('ml-metric').append(option);
}
byId('ml-metric').addEventListener('change', compareModels);
byId('ml-cutoff').addEventListener('change', compareModels);
byId('ml-experiment').addEventListener('change', selectExperiment);
for (const frame of document.querySelectorAll('.chart-frame')) {
  const tooltip = frame.querySelector('.chart-tooltip');
  frame.addEventListener('pointerleave', () => {
    if (!activeCharts.get(tooltip)?.includes(document.activeElement)) resetChartTooltip(tooltip);
  });
}
document.addEventListener('keydown', event => {
  if (event.key !== 'Escape') return;
  resetChartTooltip(byId('activity-tooltip'));
  resetChartTooltip(byId('category-tooltip'));
});
for (const id of Object.keys(views)) byId('nav-' + id).addEventListener('click', () => navigate(id));
for (const [id, value] of [['real', 'REAL'], ['synthetic', 'SYNTHETIC']]) {
  byId(id).addEventListener('click', () => {
    if (scope === value) return;
    selectScope(value);
    resetFilters();
    void refresh();
  });
}
function refreshConsole() {
  void refresh(false, true);
  if (feedViews.has(activeView)) void refreshFeed();
  if (researchViews.has(activeView)) void loadResearch();
}
byId('refresh').addEventListener('click', refreshConsole);
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
function applyMotionPreference() {
  document.documentElement.toggleAttribute('data-reduced-motion', reducedMotion());
  if (!reducedMotion()) return;
  viewMotion?.cancel();
  arrivalMotion?.cancel();
  for (const [name, state] of counts) {
    state.roll?.cancel();
    metricValue(name, state.target, false);
  }
  document.querySelectorAll('.metric').forEach(card => card.getAnimations().forEach(animation => animation.cancel()));
  document.querySelectorAll('.diagram-detail').forEach(detail => detail.getAnimations().forEach(animation => animation.cancel()));
}
motion.addEventListener('change', applyMotionPreference);
byId('reduce-motion').addEventListener('change', applyMotionPreference);
byId('sign-out').addEventListener('click', () => {
  signOut();
  byId('token').focus();
});
window.addEventListener('pagehide', () => signOut());
setInterval(() => {
  if (!pending && !byId('dashboard').hidden && document.visibilityState === 'visible') refreshConsole();
}, 30000);

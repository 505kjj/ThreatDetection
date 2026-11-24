(() => {
  const clickTimes = [];
  const navigationTimes = [];
  let tabSwitchCount = 0;
  let copyPasteCount = 0;
  let formSubmitCount = 0;
  let config = null;
  let revision = 0;
  let pending = null;
  let lastPath = '';
  let heartbeat;
  let banner;
  let bannerState;
  let warningExpiry;
  let scanId;
  let scanRetry;
  let lastScanAt = 0;
  let currentVerdict;
  let loginReasons = null;

  function sensitivePage() {
    const path = location.pathname.toLowerCase();
    return config.sensitivePaths.some(value => {
      const prefix = value.toLowerCase().replace(/\/$/, '');
      return path === prefix || path.startsWith(prefix + '/');
    });
  }

  function recent(values, duration, now) {
    while (values.length && values[0] < now - duration) values.shift();
    return values;
  }

  function telemetry(eventType) {
    const now = Date.now();
    const clicks = recent(clickTimes, 10000, now);
    const sample = clicks.slice(-10);
    return {
      type: 'TELEMETRY',
      eventType,
      sensitivePage: sensitivePage(),
      averageClickGapMs: sample.length < 2 ? -1
        : Math.round((sample.at(-1) - sample[0]) / (sample.length - 1)),
      clicksLast10Sec: clicks.length,
      pagesVisitedLast30Sec: recent(navigationTimes, 30000, now).length,
      tabSwitchCount,
      copyPasteCount,
      formSubmitCount
    };
  }

  async function send(eventType) {
    if (!config || pending === revision) return;
    const sendingRevision = revision;
    pending = sendingRevision;
    try {
      const verdict = await chrome.runtime.sendMessage(telemetry(eventType));
      if (revision !== sendingRevision) return;
      if (verdict?.state === 'confirmed' || verdict?.cause === 'reputation') config = null;
      renderVerdict(verdict);
    } catch {
      if (revision === sendingRevision) clearWarning();
    } finally {
      if (pending === sendingRevision) pending = null;
    }
  }

  function clearWarning() {
    clearTimeout(warningExpiry);
    banner?.remove();
    banner = null;
    bannerState = null;
  }

  function renderVerdict(verdict) {
    currentVerdict = verdict;
    if (verdict?.impersonation?.length && verdict.state !== 'confirmed' && loginReasons) {
      const domainReasons = verdict.impersonation.filter(item => !item.kind.startsWith('financial_'));
      verdict = { ...verdict, impersonation: [...domainReasons, ...loginReasons] };
    }
    if (verdict?.state === 'confirmed' || verdict?.state === 'warning' || verdict?.impersonation?.length) {
      showWarning(verdict);
    } else if (verdict?.state !== 'waiting') {
      clearWarning();
    }
  }

  function declaredDestination(form, controls) {
    // A submitter override makes the destination ambiguous without observing a submission.
    if (controls.some(control => control.hasAttribute('formaction'))) return null;
    const action = form.getAttribute('action')?.trim();
    if (!action) return location.origin;
    if (action.length > 4096) return null;
    try {
      const url = new URL(action, document.baseURI);
      return ['http:', 'https:'].includes(url.protocol) ? url.origin : null;
    } catch {
      return null;
    }
  }

  function credentialForms() {
    const observations = [];
    const forms = document.forms;
    for (let i = 0; i < Math.min(forms.length, 20) && observations.length < 4; i++) {
      const form = forms[i];
      const elements = form.elements;
      if (!(elements instanceof HTMLFormControlsCollection) || elements.length > 32) continue;
      const controls = Array.from(elements);
      let password = false;
      let cardNumber = false;
      let cardDetail = false;
      for (const field of controls) {
        if (!(field instanceof HTMLInputElement) || !field.hasAttribute('name') ||
            field.matches(':disabled') || field.readOnly || field.type === 'hidden') continue;
        const autocomplete = field.autocomplete.toLowerCase().split(/\s+/).at(-1);
        if (field.type !== 'password' && !['cc-number', 'cc-csc', 'cc-exp', 'cc-exp-month', 'cc-exp-year'].includes(autocomplete)) continue;
        if (!(field.checkVisibility?.({ visibilityProperty: true, opacityProperty: true }) ?? field.getClientRects().length)) continue;
        if (field.type === 'password' && autocomplete !== 'new-password') password = true;
        if (autocomplete === 'cc-number') cardNumber = true;
        if (['cc-csc', 'cc-exp', 'cc-exp-month', 'cc-exp-year'].includes(autocomplete)) cardDetail = true;
      }
      const kind = password ? 'password' : cardNumber && cardDetail ? 'payment' : null;
      if (kind) observations.push({ kind, destination: declaredDestination(form, controls) });
    }
    return observations;
  }

  async function scanLogin() {
    if (!scanId || document.hidden || Date.now() - lastScanAt < 750) return;
    const checking = revision;
    lastScanAt = Date.now();
    try {
      const result = await chrome.runtime.sendMessage({ type: 'LOGIN_STRUCTURE', id: scanId, forms: credentialForms() });
      if (checking !== revision || !result?.inspected) return;
      loginReasons = result.evidence.filter(item => item.kind.startsWith('financial_'));
      if (currentVerdict) renderVerdict(currentVerdict);
    } catch {
      // Address evidence is still present when the structural check cannot complete.
    }
  }

  function showWarning(verdict) {
    const confirmed = verdict.state === 'confirmed';
    const timeout = confirmed ? Math.min(verdict.expires - Date.now(), 45000) : 45000;
    if (timeout <= 0) {
      clearWarning();
      return;
    }
    const reasons = verdict.impersonation?.map(item => item.reason) ?? [];
    const warning = confirmed
      ? 'ThreatDetection found a known phishing or malware match. Leave this page without entering information.'
      : reasons.length
        ? 'Possible financial website impersonation. Verify the address before entering information.' +
          (verdict.state === 'unavailable' ? ' The protection service is unavailable.' : '')
        : 'ThreatDetection observed unusual activity. The site has not been confirmed malicious.';
    const presentation = JSON.stringify([warning, reasons]);
    if (bannerState !== presentation) clearWarning();
    clearTimeout(warningExpiry);
    warningExpiry = setTimeout(clearWarning, timeout);
    if (banner?.isConnected) return;
    banner = document.createElement('div');
    bannerState = presentation;
    const shadow = banner.attachShadow({ mode: 'closed' });
    const style = document.createElement('style');
    style.textContent = `
      :host{all:initial;position:fixed;top:12px;left:50%;transform:translateX(-50%);
        z-index:2147483647;width:min(580px,calc(100vw - 24px));color:#f5f5f5;font:14px/1.5 "Segoe UI",system-ui,sans-serif}
      div{display:flex;align-items:flex-start;gap:12px;background:#211a11;border:1px solid #ab7014;
        border-radius:14px;padding:14px;box-shadow:0 12px 32px #0009}
      span{flex:1;min-width:0;overflow-wrap:anywhere}
      button{background:#ffb020;color:#221507;border:0;border-radius:8px;padding:6px 10px;min-height:36px;font:inherit;font-weight:650;cursor:pointer}
      button:focus-visible{outline:2px solid #f5f5f5;outline-offset:3px}
      div.confirmed{background:#2a1218;border-color:#f04465}
      div.confirmed button{background:#ff93a9;color:#310c15}
    `;
    const alert = document.createElement('div');
    alert.setAttribute('role', confirmed ? 'alert' : 'status');
    if (confirmed) alert.className = 'confirmed';
    const description = document.createElement('span');
    description.textContent = [warning, ...reasons].join(' ');
    const dismiss = document.createElement('button');
    dismiss.textContent = 'Dismiss';
    dismiss.type = 'button';
    dismiss.addEventListener('click', clearWarning);
    alert.append(description, dismiss);
    shadow.append(style, alert);
    document.documentElement.append(banner);
  }

  function heartbeatCheck() {
    if (!config || document.hidden) return;
    if (location.pathname !== lastPath) {
      lastPath = location.pathname;
      navigationTimes.push(Date.now());
      void send('navigation_change');
    } else {
      void send('heartbeat');
    }
  }

  async function refresh() {
    const refreshingRevision = ++revision;
    config = null;
    scanId = null;
    loginReasons = null;
    currentVerdict = null;
    clearTimeout(scanRetry);
    clearInterval(heartbeat);
    clearWarning();
    clickTimes.length = navigationTimes.length = 0;
    tabSwitchCount = copyPasteCount = formSubmitCount = 0;
    try {
      const next = await chrome.runtime.sendMessage({ type: 'PAGE_CONFIGURATION' });
      if (revision !== refreshingRevision || !next) return;
      renderVerdict(next.verdict);
      if (next.scan) {
        scanId = next.scan;
        void scanLogin();
        // Cover a common delayed render without observing or polling the whole page.
        scanRetry = setTimeout(() => void scanLogin(), 1200);
      }
      if (!next.active) {
        if (next.recheck) {
          heartbeat = setInterval(() => { if (!document.hidden) void refresh(); }, 15000);
        }
        return;
      }
      config = next;
      lastPath = location.pathname;
      navigationTimes.push(Date.now());
      heartbeat = setInterval(() => {
        if (config) heartbeatCheck();
        else if (!document.hidden) void refresh();
      }, 15000);
      if (!document.hidden) void send('page_view');
    } catch {
      // An unloaded or unavailable worker supplies no verdict.
    }
  }

  document.addEventListener('click', event => {
    if (!config || !event.isTrusted) return;
    const now = Date.now();
    recent(clickTimes, 10000, now);
    clickTimes.push(now);
    if (clickTimes.length > 10 || (clickTimes.length > 1 && now - clickTimes.at(-2) < 300)) {
      void send('rapid_clicking');
    }
  }, true);

  document.addEventListener('focusin', event => {
    const field = event.target;
    if (scanId && event.isTrusted && field instanceof HTMLInputElement) void scanLogin();
    if (!config || !event.isTrusted || !field?.matches?.('input, textarea, select')) return;
    const attrs = [field.type, field.name, field.autocomplete, field.id].join(' ').toLowerCase();
    if (config.sensitiveFields.some(name => attrs.includes(name.toLowerCase()))) {
      void send(field.type === 'password' ? 'password_focus' : 'form_focus');
    }
  }, true);

  document.addEventListener('submit', event => {
    if (!config || !event.isTrusted) return;
    formSubmitCount = Math.min(formSubmitCount + 1, 1000);
    void send('form_submit');
  }, true);

  for (const type of ['copy', 'paste']) {
    document.addEventListener(type, event => {
      if (!config || !event.isTrusted || !sensitivePage()) return;
      copyPasteCount = Math.min(copyPasteCount + 1, 1000);
      void send('copy_paste');
    }, true);
  }

  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) void scanLogin();
    if (!config) {
      if (!document.hidden) void refresh();
      return;
    }
    if (document.hidden) {
      tabSwitchCount = Math.min(tabSwitchCount + 1, 1000);
      if (sensitivePage()) void send('tab_blur');
    } else {
      heartbeatCheck();
    }
  });
  window.addEventListener('pageshow', event => {
    if (event.persisted) void refresh();
  });
  chrome.runtime.onMessage.addListener((message, sender) => {
    if (sender.id === chrome.runtime.id && message?.type === 'REFRESH_CONFIGURATION') void refresh();
  });
  void refresh();
})();

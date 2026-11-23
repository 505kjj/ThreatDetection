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
    if (verdict?.state === 'confirmed' || verdict?.state === 'warning' || verdict?.impersonation?.length) {
      showWarning(verdict);
    } else if (verdict?.state !== 'waiting') {
      clearWarning();
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
      ? 'Threat Monitor found a known phishing or malware match. Leave this page without entering information.'
      : reasons.length
        ? 'Possible financial website impersonation. Verify the address before entering information.' +
          (verdict.state === 'unavailable' ? ' The protection service is unavailable.' : '')
        : 'Threat Monitor observed unusual activity. The site has not been confirmed malicious.';
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
        z-index:2147483647;width:min(540px,calc(100vw - 24px));color:#fef3c7;font:14px system-ui,sans-serif}
      div{display:flex;align-items:center;gap:12px;background:#422006;border:1px solid #f59e0b;
        border-radius:10px;padding:12px;box-shadow:0 4px 18px #0005}
      span{flex:1}
      button{background:#fef3c7;color:#422006;border:0;border-radius:5px;padding:6px 10px;cursor:pointer}
      div.confirmed{background:#450a0a;border-color:#ef4444;color:#fef2f2}
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
    clearInterval(heartbeat);
    clearWarning();
    clickTimes.length = navigationTimes.length = 0;
    tabSwitchCount = copyPasteCount = formSubmitCount = 0;
    try {
      const next = await chrome.runtime.sendMessage({ type: 'PAGE_CONFIGURATION' });
      if (revision !== refreshingRevision || !next) return;
      renderVerdict(next.verdict);
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

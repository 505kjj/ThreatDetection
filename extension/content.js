/**
 * Content Script — Threat Detection System
 * Runs in content script context (has chrome.storage.local, chrome.runtime access).
 * NEVER uses chrome.storage.session (not available in content scripts).
 */
(async function () {
  'use strict';

  console.log("[ThreatDetection] Content script started");

  const BACKEND_URL = "http://localhost:8081";

  // ============ UTILS ============
  function normalizeDomain(input) {
    return input.replace(/^https?:\/\//, "").replace(/^www\./, "").replace(/\/.*$/, "").trim().toLowerCase();
  }
  function getMatchingSiteConfig(hostname, monitoredSites) {
    if (!monitoredSites || !Array.isArray(monitoredSites)) return null;
    const h = normalizeDomain(hostname);
    return monitoredSites.find(s => {
      const d = normalizeDomain(s.domain);
      return s.enabled !== false && (h === d || h.endsWith("." + d));
    });
  }

  // ============ STATE ============
  let siteConfig = null, isMonitored = false, sessionId = null, backendUrl = BACKEND_URL;
  const clickTimestamps = [], pageVisitTimestamps = [];
  let tabSwitchCount = 0, copyPasteCount = 0, formSubmitCount = 0, redirectCount = 0, lastFieldType = '';
  const currentDomain = window.location.hostname;
  const referrer = document.referrer;

  // ============ CHROME STORAGE HELPERS (content script safe) ============
  function storageGet(keys) {
    return new Promise(resolve => {
      try {
        chrome.storage.local.get(keys, data => {
          if (chrome.runtime.lastError) { console.warn("[ThreatDetection] storage.get error:", chrome.runtime.lastError.message); resolve({}); return; }
          resolve(data || {});
        });
      } catch (e) { console.warn("[ThreatDetection] storage.get exception:", e.message); resolve({}); }
    });
  }
  function storageSet(obj) {
    return new Promise(resolve => {
      try {
        chrome.storage.local.set(obj, () => {
          if (chrome.runtime.lastError) console.warn("[ThreatDetection] storage.set error:", chrome.runtime.lastError.message);
          resolve();
        });
      } catch (e) { console.warn("[ThreatDetection] storage.set exception:", e.message); resolve(); }
    });
  }
  function sendMsg(msg) {
    try { chrome.runtime.sendMessage(msg); } catch (e) { /* popup may not be open */ }
  }

  // ============ FETCH WITH RETRY ============
  async function fetchRetry(url, opts, retries) {
    retries = retries || 1;
    for (let i = 0; i <= retries; i++) {
      try {
        const r = await fetch(url, Object.assign({}, opts, { signal: AbortSignal.timeout(5000) }));
        if (r.ok) return r;
        console.warn("[ThreatDetection] HTTP " + r.status + " (attempt " + (i + 1) + ")");
      } catch (e) { console.warn("[ThreatDetection] fetch error (attempt " + (i + 1) + "):", e.message); }
      if (i < retries) await new Promise(r => setTimeout(r, 500));
    }
    return null;
  }

  // ============ HEALTH CHECK ============
  async function checkHealth() {
    try {
      const r = await fetch(backendUrl + "/api/health", { signal: AbortSignal.timeout(3000) });
      if (r.ok) { console.log("[ThreatDetection] Backend is UP"); return true; }
    } catch (_) {}
    console.warn("[ThreatDetection] Backend is DOWN at " + backendUrl);
    return false;
  }

  // ============ HASH ============
  async function hashStr(s) {
    try {
      const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
      return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
    } catch (_) {
      let h = 0; for (let i = 0; i < s.length; i++) { h = ((h << 5) - h) + s.charCodeAt(i); h = h & h; }
      return 'fb-' + Math.abs(h).toString(16);
    }
  }

  // ============ SESSION ============
  async function ensureSession(cfg) {
    const dk = "session_" + normalizeDomain(currentDomain);
    const existing = cfg[dk];
    if (existing) { console.log("[ThreatDetection] Existing session:", existing); return existing; }
    const newId = "S-" + Date.now() + "-" + Math.random().toString(36).substring(2, 8);
    try {
      const uah = await hashStr(navigator.userAgent);
      await fetchRetry(backendUrl + "/api/threat/session/start", {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionId: newId, domain: normalizeDomain(currentDomain), userAgentHash: uah })
      });
    } catch (e) { console.warn("[ThreatDetection] Session registration failed:", e.message); }
    await storageSet({ [dk]: newId });
    console.log("[ThreatDetection] Session created:", newId);
    return newId;
  }

  // ============ PAGE HELPERS ============
  function getPageCategory() {
    if (!siteConfig || !siteConfig.sensitivePaths) return 'normal_page';
    const p = window.location.pathname.toLowerCase();
    for (const sp of siteConfig.sensitivePaths) { if (p.startsWith(sp.toLowerCase())) return 'sensitive_page'; }
    return 'normal_page';
  }
  function detectFieldType(el) {
    if (!el || !el.tagName) return '';
    var tag = el.tagName.toLowerCase();
    if (tag !== 'input' && tag !== 'textarea' && tag !== 'select') return '';
    var t = (el.type || '').toLowerCase();
    var all = t + " " + (el.name || '') + " " + (el.autocomplete || '') + " " + (el.placeholder || '') + " " + (el.id || '');
    all = all.toLowerCase();
    if (!siteConfig || !siteConfig.sensitiveFields) return t || 'text';
    for (var f of siteConfig.sensitiveFields) { if (all.includes(f.toLowerCase())) return f; }
    return t || 'text';
  }
  function getClicksLast10() {
    var cut = Date.now() - 10000;
    while (clickTimestamps.length && clickTimestamps[0] < cut) clickTimestamps.shift();
    return clickTimestamps.length;
  }
  function getAvgClickGap() {
    if (clickTimestamps.length < 2) return -1;
    var r = clickTimestamps.slice(-10), g = 0;
    for (var i = 1; i < r.length; i++) g += r[i] - r[i - 1];
    return g / (r.length - 1);
  }
  function getPagesLast30() {
    var cut = Date.now() - 30000;
    while (pageVisitTimestamps.length && pageVisitTimestamps[0] < cut) pageVisitTimestamps.shift();
    return pageVisitTimestamps.length;
  }

  // ============ PACKET ============
  function buildPacket(evt, act) {
    return {
      sessionId: sessionId, domain: normalizeDomain(currentDomain), url: window.location.href,
      path: window.location.pathname, referrer: referrer, redirectCount: redirectCount, eventType: evt,
      actionType: act || 'normal_action', pageCategory: getPageCategory(), fieldType: lastFieldType,
      averageClickGapMs: Math.round(getAvgClickGap()), clicksLast10Sec: getClicksLast10(),
      pagesVisitedLast30Sec: getPagesLast30(), tabSwitchCount: tabSwitchCount,
      copyPasteCount: copyPasteCount, formSubmitCount: formSubmitCount, timestamp: new Date().toISOString()
    };
  }

  async function sendPacket(evt, act) {
    if (!isMonitored || !sessionId) return;
    console.log("[ThreatDetection] Sending analyze request:", evt);
    var pkt = buildPacket(evt, act);
    var res = await fetchRetry(backendUrl + "/api/threat/analyze", {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(pkt)
    });
    if (res) {
      try {
        var result = await res.json();
        if (!result || !result.riskLevel) { console.warn("[ThreatDetection] Invalid response"); return; }
        console.log("[ThreatDetection] Risk:", result.riskLevel, "Score:", result.riskScore);
        handleResult(result);
      } catch (e) { console.error("[ThreatDetection] Parse error:", e.message); }
    } else {
      console.warn("[ThreatDetection] Backend unavailable, fallback HIGH");
      handleResult({ riskLevel: "High Risk", riskScore: 75, trustScore: 25, action: "FORCE_RELOGIN", reasons: ["Backend unavailable - fallback"], tags: ["fallback"], confidence: 0.5 });
    }
  }

  // ============ RESULT HANDLER ============
  async function handleResult(result) {
    if (!result || !result.riskLevel) return;
    // Send to background for popup (uses chrome.storage.session there, not here)
    sendMsg({ type: 'RISK_RESULT', data: result, domain: normalizeDomain(currentDomain) });
    // Also store in local for popup fallback
    await storageSet({ _latestRisk: result, _latestDomain: normalizeDomain(currentDomain), _latestTime: Date.now() });

    var demoData = await storageGet('demoMode');
    var demoMode = demoData.demoMode !== false;

    try {
      if (result.riskLevel === 'Safe' || result.action === 'ALLOW') removeOverlay();
      else if (result.riskLevel === 'Critical' || result.action === 'ADMIN_ALERT') showOverlay('critical', result, demoMode);
      else if (result.riskLevel === 'High Risk' || result.action === 'FORCE_RELOGIN') showOverlay('high-risk', result, demoMode);
      else if (result.riskLevel === 'Suspicious' || result.action === 'SHOW_WARNING') showOverlay('warning', result, false);
    } catch (e) { console.error("[ThreatDetection] Overlay error:", e); }
  }

  // ============ OVERLAY ============
  var activeOverlay = null;
  function removeOverlay() {
    if (activeOverlay) { try { activeOverlay.remove(); } catch (_) {} activeOverlay = null; document.body.style.overflow = ''; }
  }
  function showOverlay(type, result, demoMode) {
    removeOverlay();
    var blocking = type === 'high-risk' || type === 'critical';
    var cfg = type === 'critical'
      ? { bg: 'rgba(220,38,38,.15)', border: '#dc2626', icon: '\u{1F6A8}', title: 'Critical Threat Detected', sub: 'Access blocked. Logged for admin review.' }
      : type === 'high-risk'
      ? { bg: 'rgba(239,68,68,.12)', border: '#ef4444', icon: '\u{1F6E1}\uFE0F', title: 'High Risk Activity', sub: 'Access restricted. Please re-login.' }
      : { bg: 'rgba(245,158,11,.12)', border: '#f59e0b', icon: '\u26A0\uFE0F', title: 'Suspicious Behavior', sub: 'Please continue carefully.' };
    var grad = type === 'critical' ? 'linear-gradient(135deg,rgba(220,38,38,.15),rgba(153,27,27,.08))'
      : type === 'high-risk' ? 'linear-gradient(135deg,rgba(239,68,68,.1),rgba(185,28,28,.05))'
      : 'linear-gradient(135deg,rgba(245,158,11,.1),rgba(217,119,6,.05))';
    var reasons = (result.reasons || []).map(function (r) { return '<li>' + r + '</li>'; }).join('');
    var tags = (result.tags || []).map(function (t) { return '<span class="tg">#' + t + '</span>'; }).join(' ');
    var btns = type === 'warning'
      ? '<button class="b bs" id="bu">I Understand</button><button class="b bp" id="br">Re-check</button>'
      : '<button class="b bp" id="br">Re-check</button>' + (demoMode ? '<button class="b bs" id="bd">Close for Demo</button>' : '');

    var host = document.createElement('div');
    host.id = 'td-overlay';
    host.style.cssText = 'position:fixed;top:0;left:0;width:100vw;height:100vh;z-index:2147483647;pointer-events:' + (blocking ? 'auto' : 'none') + ';';
    if (blocking) document.body.style.overflow = 'hidden';
    var sh = host.attachShadow({ mode: 'closed' });
    sh.innerHTML = '<style>.bk{position:fixed;top:0;left:0;width:100vw;height:100vh;background:' + (blocking ? 'rgba(15,23,42,.85)' : 'rgba(0,0,0,.3)') + ';backdrop-filter:blur(' + (blocking ? 8 : 2) + 'px);display:flex;justify-content:center;align-items:' + (blocking ? 'center' : 'flex-start') + ';padding-top:' + (blocking ? 0 : 60) + 'px;pointer-events:auto;animation:fi .3s;font-family:system-ui,sans-serif}@keyframes fi{from{opacity:0}to{opacity:1}}@keyframes sd{from{transform:translateY(-20px);opacity:0}to{transform:translateY(0);opacity:1}}.cd{background:#1e293b;border:1px solid ' + cfg.border + ';border-radius:16px;max-width:500px;width:90%;padding:32px;box-shadow:0 25px 60px rgba(0,0,0,.5);color:#f8fafc;animation:sd .4s}.hd{display:flex;align-items:center;gap:16px;margin-bottom:16px}.ic{font-size:36px}.tt{font-size:22px;font-weight:700;color:' + cfg.border + '}.st{font-size:14px;color:#cbd5e1;line-height:1.6;margin-bottom:24px}.sr{display:flex;justify-content:space-between;background:' + grad + ';border-radius:12px;padding:16px 20px;margin-bottom:20px;border:1px solid rgba(255,255,255,.05)}.sc{text-align:center}.sl{font-size:12px;color:#cbd5e1;text-transform:uppercase;letter-spacing:.5px}.sv{font-size:24px;font-weight:800;color:' + cfg.border + '}.rs{list-style:none;padding:12px;margin:0 0 20px;background:rgba(0,0,0,.2);border-radius:8px}.rs li{font-size:13px;color:#cbd5e1;padding:4px 0}.rs li::before{content:"\\2192 ";color:' + cfg.border + ';font-weight:600}.tc{margin-bottom:24px}.tg{display:inline-block;padding:4px 8px;background:rgba(255,255,255,.1);border-radius:4px;font-size:11px;color:#94a3b8;margin:0 6px 6px 0}.br{display:flex;gap:12px;margin-top:24px}.b{flex:1;padding:12px;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;border:none;font-family:inherit}.bp{background:' + cfg.border + ';color:#fff}.bs{background:rgba(255,255,255,.1);color:#cbd5e1;border:1px solid rgba(255,255,255,.2)}</style>'
      + '<div class="bk"><div class="cd"><div class="hd"><span class="ic">' + cfg.icon + '</span><span class="tt">' + cfg.title + '</span></div><div class="st">' + cfg.sub + '</div>'
      + '<div class="sr"><div class="sc"><div class="sl">Risk</div><div class="sv">' + (result.riskScore || 0) + '</div></div><div class="sc"><div class="sl">Trust</div><div class="sv" style="color:#4ade80">' + (result.trustScore || 0) + '</div></div><div class="sc"><div class="sl">Level</div><div class="sv" style="font-size:16px">' + (result.riskLevel || '?') + '</div></div></div>'
      + '<ul class="rs">' + (reasons || '<li>No details</li>') + '</ul>'
      + (tags ? '<div class="tc">' + tags + '</div>' : '')
      + '<div class="br">' + btns + '</div></div></div>';
    document.documentElement.appendChild(host);
    activeOverlay = host;
    var bu = sh.getElementById('bu'); if (bu) bu.onclick = removeOverlay;
    var bd = sh.getElementById('bd'); if (bd) bd.onclick = removeOverlay;
    var br = sh.getElementById('br'); if (br) br.onclick = function () { br.textContent = 'Checking...'; sendPacket('recheck_risk', 'normal_action'); };
  }

  // ============ LISTENERS ============
  function startMonitoring() {
    console.log("[ThreatDetection] Monitoring listeners attached");
    document.addEventListener('click', function () {
      try { clickTimestamps.push(Date.now()); if (getClicksLast10() > 10 || (getAvgClickGap() > 0 && getAvgClickGap() < 300)) sendPacket('rapid_clicking', 'behavior_anomaly'); } catch (e) { console.error("[ThreatDetection]", e); }
    }, true);
    document.addEventListener('focusin', function (e) {
      try { var ft = detectFieldType(e.target); if (!ft) return; lastFieldType = ft; if (ft === 'password') sendPacket('password_focus', 'sensitive_action'); else if (siteConfig && siteConfig.sensitiveFields && siteConfig.sensitiveFields.includes(ft)) sendPacket('form_focus', 'sensitive_action'); } catch (e2) { console.error("[ThreatDetection]", e2); }
    }, true);
    document.addEventListener('submit', function () { try { formSubmitCount++; sendPacket('form_submit', 'sensitive_action'); } catch (e) { console.error("[ThreatDetection]", e); } }, true);
    document.addEventListener('copy', function () { try { copyPasteCount++; if (getPageCategory() === 'sensitive_page') sendPacket('copy_paste', 'behavior_anomaly'); } catch (e) { console.error("[ThreatDetection]", e); } }, true);
    document.addEventListener('paste', function () { try { copyPasteCount++; if (getPageCategory() === 'sensitive_page') sendPacket('copy_paste', 'behavior_anomaly'); } catch (e) { console.error("[ThreatDetection]", e); } }, true);
    document.addEventListener('visibilitychange', function () {
      try { if (document.hidden) { tabSwitchCount++; if (getPageCategory() === 'sensitive_page') sendPacket('tab_blur', 'session_anomaly'); } else { if (getPageCategory() === 'sensitive_page') sendPacket('tab_focus', 'navigation'); } } catch (e) { console.error("[ThreatDetection]", e); }
    });
    var lastPath = window.location.pathname;
    new MutationObserver(function () {
      try { if (window.location.pathname !== lastPath) { lastPath = window.location.pathname; pageVisitTimestamps.push(Date.now()); sendPacket('navigation_change', 'navigation'); } } catch (e) { console.error("[ThreatDetection]", e); }
    }).observe(document.body, { childList: true, subtree: true });
    // Redirect info from background
    try { chrome.runtime.onMessage.addListener(function (m) { if (m.type === 'REDIRECT_INFO') redirectCount = m.redirectCount || 0; }); } catch (_) {}
    // Heartbeat
    setInterval(function () { if (isMonitored && !document.hidden) sendPacket('heartbeat', 'normal_action'); }, 15000);
    // Initial page view
    pageVisitTimestamps.push(Date.now());
    sendPacket('page_view', 'navigation');
    if (getPageCategory() === 'sensitive_page') sendPacket('sensitive_page_visit', 'navigation');
  }

  // ============ MAIN INIT ============
  try {
    var config = await storageGet(null);
    if (!config) { console.log("[ThreatDetection] No config"); return; }
    console.log("[ThreatDetection] Config loaded");
    if (config.monitoringEnabled === false) { console.log("[ThreatDetection] Monitoring disabled"); return; }
    backendUrl = config.backendUrl || BACKEND_URL;
    siteConfig = getMatchingSiteConfig(currentDomain, config.monitoredSites);
    if (!siteConfig) return;
    isMonitored = true;
    console.log("[ThreatDetection] Domain monitored:", currentDomain);
    await checkHealth();
    sessionId = await ensureSession(config);
    if (!sessionId) { console.warn("[ThreatDetection] No session"); return; }
    console.log("[ThreatDetection] Session ready:", sessionId);
    try { var ri = await chrome.runtime.sendMessage({ type: 'GET_REDIRECT_COUNT' }); if (ri) redirectCount = ri.redirectCount || 0; } catch (_) {}
    startMonitoring();
  } catch (e) {
    console.error("[ThreatDetection] Fatal init error:", e);
  }
})();

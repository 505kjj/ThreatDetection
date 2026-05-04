/**
 * Background Service Worker — Generic Threat Detection Extension
 * 
 * Handles:
 * - Extension installation (default settings)
 * - Tab navigation tracking for redirect detection
 * - Message relay between content scripts and popup
 * - Generic domain matching helpers
 */

// ============================================
// DOMAIN MATCHING UTILITIES
// ============================================

function normalizeDomain(input) {
  return input
    .replace(/^https?:\/\//, "")
    .replace(/^www\./, "")
    .replace(/\/.*$/, "")
    .trim()
    .toLowerCase();
}

function getMatchingSiteConfig(hostname, monitoredSites) {
  if (!monitoredSites || !Array.isArray(monitoredSites)) return null;
  const normalizedHost = normalizeDomain(hostname);

  return monitoredSites.find(site => {
    const normalizedSite = normalizeDomain(site.domain);
    return site.enabled !== false && (
      normalizedHost === normalizedSite ||
      normalizedHost.endsWith("." + normalizedSite)
    );
  });
}

// ============================================
// DEFAULT CONFIGURATION
// ============================================

const DEFAULT_SENSITIVE_PATHS = [
  '/login', '/signin', '/signup', '/register',
  '/dashboard', '/admin', '/profile', '/account', '/settings',
  '/payment', '/checkout',
  '/patient', '/emergency', '/hospital', '/ambulance', '/records'
];

const DEFAULT_SENSITIVE_FIELDS = [
  'password', 'otp', 'email', 'phone', 'card', 'cvv', 'token', 'pin'
];

const DEFAULT_HIGH_RISK_ACTIONS = [
  'form_submit', 'password_focus', 'copy_paste', 'rapid_clicking', 'tab_blur'
];

const DEFAULT_CONFIG = {
  backendUrl: 'http://localhost:8081',
  monitoringEnabled: true,
  monitoredSites: [
    {
      domain: 'example.com',
      enabled: true,
      sensitivePaths: DEFAULT_SENSITIVE_PATHS,
      sensitiveFields: DEFAULT_SENSITIVE_FIELDS,
      highRiskActions: DEFAULT_HIGH_RISK_ACTIONS
    }
  ]
};

// ============================================
// INSTALLATION HANDLER
// ============================================

chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    chrome.storage.local.set({
      backendUrl: DEFAULT_CONFIG.backendUrl,
      monitoringEnabled: DEFAULT_CONFIG.monitoringEnabled,
      monitoredSites: DEFAULT_CONFIG.monitoredSites
    }, () => {
      console.log('[ThreatDetection] Extension installed with default config');
    });
  }
});

// ============================================
// TAB NAVIGATION TRACKING (redirect detection)
// ============================================

// Track redirect counts per tab
const tabRedirects = {};

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return; // Only main frame
  const tabId = details.tabId;

  if (!tabRedirects[tabId]) {
    tabRedirects[tabId] = { count: 0, lastUrl: '', timestamp: Date.now() };
  }

  const entry = tabRedirects[tabId];
  const now = Date.now();

  // If navigation happens within 3 seconds of last, count as redirect chain
  if (now - entry.timestamp < 3000 && entry.lastUrl !== details.url) {
    entry.count++;
  } else {
    entry.count = 0; // Reset if enough time has passed
  }

  entry.lastUrl = details.url;
  entry.timestamp = now;
});

chrome.webNavigation.onCompleted.addListener((details) => {
  if (details.frameId !== 0) return;
  const tabId = details.tabId;
  const redirectInfo = tabRedirects[tabId] || { count: 0 };

  // Send redirect count to content script
  try {
    chrome.tabs.sendMessage(tabId, {
      type: 'REDIRECT_INFO',
      redirectCount: redirectInfo.count
    }).catch(() => { /* content script may not be ready */ });
  } catch (e) { /* ignore */ }
});

// Clean up on tab close
chrome.tabs.onRemoved.addListener((tabId) => {
  delete tabRedirects[tabId];
});

// ============================================
// MESSAGE HANDLER
// ============================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'GET_CONFIG') {
    chrome.storage.local.get(['backendUrl', 'monitoringEnabled', 'monitoredSites'], (data) => {
      sendResponse({
        backendUrl: data.backendUrl || DEFAULT_CONFIG.backendUrl,
        monitoringEnabled: data.monitoringEnabled !== false,
        monitoredSites: data.monitoredSites || DEFAULT_CONFIG.monitoredSites
      });
    });
    return true; // Async response
  }

  if (message.type === 'GET_REDIRECT_COUNT') {
    const tabId = sender.tab?.id;
    const info = tabRedirects[tabId] || { count: 0 };
    sendResponse({ redirectCount: info.count });
    return true;
  }

  if (message.type === 'CHECK_DOMAIN') {
    // Generic domain matching check for popup/content
    chrome.storage.local.get(['monitoringEnabled', 'monitoredSites'], (data) => {
      const monitoringEnabled = data.monitoringEnabled !== false;
      const sites = data.monitoredSites || DEFAULT_CONFIG.monitoredSites;
      const match = getMatchingSiteConfig(message.hostname || '', sites);
      sendResponse({
        isMonitored: monitoringEnabled && !!match,
        siteConfig: match || null,
        monitoringEnabled: monitoringEnabled
      });
    });
    return true;
  }

  if (message.type === 'RISK_RESULT') {
    // Store latest risk result for the popup
    chrome.storage.session.set({
      latestRisk: message.data,
      latestRiskDomain: message.domain,
      latestRiskTimestamp: Date.now()
    });
    return false;
  }

  if (message.type === 'GET_DEFAULTS') {
    sendResponse({
      sensitivePaths: DEFAULT_SENSITIVE_PATHS,
      sensitiveFields: DEFAULT_SENSITIVE_FIELDS,
      highRiskActions: DEFAULT_HIGH_RISK_ACTIONS
    });
    return true;
  }
});

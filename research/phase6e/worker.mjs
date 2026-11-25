import { assessFixture } from './assess.mjs';

// At most eight transition categories per tab, expiring after 30 seconds. No URLs are retained.
const transitions = new Map();
chrome.webNavigation.onCommitted.addListener(details => {
  if (details.frameId !== 0 || !details.url.startsWith('http://127.0.0.1:')) return;
  const now = Date.now();
  const old = transitions.get(details.tabId);
  const prior = old && now - old.updated < 30000 ? old : { redirects: 0, commits: 0, events: [] };
  prior.commits++;
  const redirect = details.transitionQualifiers.some(value => value === 'server_redirect' || value === 'client_redirect');
  if (redirect) prior.redirects++;
  prior.events.push(redirect ? 'redirect' : 'commit');
  if (prior.events.length > 8) prior.events.shift();
  prior.updated = now;
  transitions.set(details.tabId, prior);
  setTimeout(() => {
    if (transitions.get(details.tabId)?.updated === now) transitions.delete(details.tabId);
  }, 30000);
});
chrome.tabs.onRemoved.addListener(tabId => transitions.delete(tabId));
chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (sender.id !== chrome.runtime.id || message?.type !== 'read-fixture' || !Number.isInteger(message.tabId)) return false;
  (async () => {
    const observation = await chrome.tabs.sendMessage(message.tabId, { type: 'inspect-fixture' });
    const tab = await chrome.tabs.get(message.tabId);
    const address = new URL(tab.url);
    if (address.hostname !== '127.0.0.1' || address.protocol !== 'http:') throw new Error('Fixture origin required');
    const cookieObjects = await chrome.cookies.getAll({ url: address.origin });
    // Do not copy cookie values, names, paths, domains or URLs into observations.
    const cookie = { count: cookieObjects.length, missingSecure: cookieObjects.filter(item => !item.secure).length,
      missingHttpOnly: cookieObjects.filter(item => !item.httpOnly).length,
      broadScope: cookieObjects.filter(item => !item.hostOnly).length,
      sameSiteNone: cookieObjects.filter(item => item.sameSite === 'no_restriction').length };
    const permission = {};
    for (const name of ['camera', 'microphone', 'location', 'notifications']) {
      permission[name] = (await chrome.contentSettings[name].get({ primaryUrl: address.origin })).setting;
    }
    const stored = transitions.get(message.tabId);
    const navigation = stored && Date.now() - stored.updated < 30000
      ? { redirects: stored.redirects, commits: stored.commits, events: [...stored.events] } : null;
    const input = { form: observation.form, reputation: 'unavailable',
      cookie: cookie.count && cookie.missingSecure ? 'missing-secure' : 'unknown',
      permission: Object.values(permission).includes('allow') ? 'granted' : 'unknown', behavior: observation.behavior };
    // A redirect alone has no interpretation without a reviewed context.
    return { navigation, form: observation.form, behavior: observation.behavior, cookie, permission, evidence: assessFixture(input) };
  })().then(reply).catch(() => reply({ navigation: null, form: 'unavailable',
    evidence: [{ category: 'credential', state: 'unavailable', reason: 'fixture-inaccessible' }] }));
  return true;
});

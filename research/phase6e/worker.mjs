import { assessFixture } from './assess.mjs';

// Only aggregate transition categories per tab. No URLs or histories are retained.
const transitions = new Map();
chrome.webNavigation.onCommitted.addListener(details => {
  if (details.frameId !== 0 || !details.url.startsWith('http://127.0.0.1:')) return;
  const prior = transitions.get(details.tabId) || { redirects: 0, commits: 0 };
  prior.commits++;
  if (details.transitionQualifiers.some(value => value === 'server_redirect' || value === 'client_redirect')) prior.redirects++;
  transitions.set(details.tabId, prior);
});
chrome.tabs.onRemoved.addListener(tabId => transitions.delete(tabId));
chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (sender.id !== chrome.runtime.id || message?.type !== 'read-fixture' || !Number.isInteger(message.tabId)) return false;
  chrome.tabs.sendMessage(message.tabId, { type: 'inspect-fixture' }).then(observation => {
    const navigation = transitions.get(message.tabId) || { redirects: 0, commits: 0 };
    const input = { form: observation.form, reputation: 'unavailable' };
    // A redirect alone has no interpretation without a reviewed context.
    reply({ navigation, form: observation.form, evidence: assessFixture(input) });
  }).catch(() => reply({ navigation: transitions.get(message.tabId) || null, form: 'unavailable',
    evidence: [{ category: 'credential', state: 'unavailable', reason: 'fixture-inaccessible' }] }));
  return true;
});

// Synthetic loopback documents only. Inspect form structure, never field values.
chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (sender.id !== chrome.runtime.id || message?.type !== 'inspect-fixture') return false;
  const forms = [...document.forms];
  if (forms.length > 20) { reply({ form: 'unavailable' }); return false; }
  let form = 'none';
  for (const element of forms) {
    if (!element.querySelector('input[type="password"]')) continue;
    let action;
    try { action = new URL(element.getAttribute('action') || location.href, document.baseURI); }
    catch { form = 'unavailable'; break; }
    if (!['http:', 'https:'].includes(action.protocol)) { form = 'unavailable'; break; }
    if (action.protocol === 'http:' && action.hostname !== '127.0.0.1') form = 'insecure';
    else if (action.origin !== location.origin) form = 'external';
    else form = 'local';
  }
  reply({ form });
  return false;
});

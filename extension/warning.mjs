const byId = id => document.getElementById(id);
const token = location.hash.slice(1);
let latest;

function render(record) {
  latest = record;
  const active = record?.active === true && record.until > Date.now();
  document.body.classList.toggle('confirmed', active);
  byId('headline').textContent = active
    ? record.phase === 'before_request' ? 'Known threat blocked' : 'Known threat detected'
    : 'Protection unavailable';
  byId('destination').hidden = !active;
  byId('destination').textContent = active ? record.host : '';
  byId('guidance').hidden = !active;
  byId('review').hidden = !active || !record.canProceed;
  if (!active || !record.canProceed) byId('exception').hidden = true;
  byId('detail').textContent = active
    ? record.phase === 'before_request' ? 'Chrome blocked the destination before it loaded.'
      : 'This tab was moved away after navigation began. The destination may have already loaded.'
    : 'The extension could not verify a current threat match for this warning.';
  const reasons = active ? [record.kind === 'HOST' ? 'The hostname matched current threat intelligence.'
    : record.kind === 'URL_SHA256' ? 'The address matched a fingerprint in the active reputation snapshot.'
      : 'The exact URL path matched current threat intelligence.',
  record.threat === 'PHISHING' ? 'Reported threat: phishing.' : 'Reported threat: malware.',
  ...record.impersonation.map(item => item.reason)] : [];
  byId('evidence').hidden = reasons.length === 0;
  byId('evidence').replaceChildren(...reasons.map(reason => {
    const item = document.createElement('li');
    item.textContent = reason;
    return item;
  }));
}

async function refresh() {
  try {
    render(await chrome.runtime.sendMessage({ type: 'GET_NETWORK_WARNING', token }));
  } catch {
    render(null);
  }
}

byId('leave').addEventListener('click', () => {
  void chrome.runtime.sendMessage({ type: 'LEAVE_NETWORK_WARNING', token }).catch(() => {});
  location.replace('about:blank');
});
byId('review').addEventListener('click', () => {
  if (latest?.canProceed && latest.until > Date.now()) {
    byId('exception').hidden = false;
    byId('proceed').focus();
  }
});
byId('proceed').addEventListener('click', async event => {
  if (!event.isTrusted || byId('exception').hidden || !latest?.canProceed || latest.until <= Date.now()) return;
  byId('proceed').disabled = true;
  try {
    const result = await chrome.runtime.sendMessage({ type: 'PROCEED_ONCE', token });
    if (result?.active && result.deadline > Date.now() && /^https?:\/\//.test(result.destination)) {
      location.replace(result.destination);
      return;
    }
  } catch {
    // A revoked or expired exception leaves this safe page in place.
  }
  byId('exception').hidden = true;
  byId('proceed').disabled = false;
  await refresh();
});

void refresh();
setInterval(refresh, 2000);

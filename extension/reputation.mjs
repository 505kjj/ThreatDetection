import { siteHostname } from './settings.mjs';

const STORAGE_KEY = 'reputationSnapshot';
const MINUTE = 60000;
const MAX_AGE = 24 * 60 * MINUTE;
const HASH = /^[0-9a-f]{64}$/;
const THREATS = new Set(['PHISHING', 'MALWARE']);
const PATH_INDICATOR = /^https?:\/\/[a-z0-9.-]+(?::[0-9]+)?\/[A-Za-z0-9._~/-]*$/;

export function destinationFor(value) {
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
    const host = siteHostname(url.hostname);
    if (!host) return null;
    const authority = host + (url.port ? ':' + url.port : '');
    return {
      host,
      key: url.protocol + '//' + authority + url.pathname.replace(/%[0-9a-f]{2}/gi, escape => escape.toUpperCase())
    };
  } catch {
    return null;
  }
}

export function parseSnapshot(raw, now = Date.now()) {
  if (!raw || typeof raw.generatedAt !== 'string' || typeof raw.expiresAt !== 'string' ||
      Object.keys(raw).length !== 3) return null;
  const generated = Date.parse(raw?.generatedAt);
  const expires = Date.parse(raw?.expiresAt);
  if (!Number.isFinite(generated) || !Number.isFinite(expires) || generated > now + MINUTE ||
      expires <= Math.max(now, generated) || expires - generated > MAX_AGE ||
      !Array.isArray(raw.entries) || raw.entries.length > 20000) return null;
  const hosts = new Map();
  const paths = new Map();
  const urlPaths = new Map();
  for (const entry of raw.entries) {
    if (typeof entry?.value !== 'string' || !THREATS.has(entry.threat) || Object.keys(entry).length !== 3) return null;
    const { kind, value, threat } = entry;
    const map = kind === 'HOST' && siteHostname(value) === value ? hosts
      : kind === 'URL_SHA256' && HASH.test(value) ? paths
        : kind === 'URL_PATH' && value.length <= 512 && PATH_INDICATOR.test(value) &&
          destinationFor(value)?.key === value ? urlPaths : null;
    if (!map || map.has(value)) return null;
    map.set(value, threat);
  }
  return { expires, hosts, paths, urlPaths };
}

export async function checkDestination(snapshot, destination, now = Date.now) {
  if (!snapshot || snapshot.expires <= now()) return { state: 'unavailable', cause: 'reputation' };
  let evidence;
  if (snapshot.hosts.has(destination.host)) evidence = { kind: 'HOST', value: destination.host };
  else if (snapshot.urlPaths.has(destination.key)) evidence = { kind: 'URL_PATH', value: destination.key };
  else if (snapshot.paths.size) {
    const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(destination.key));
    const hash = Array.from(new Uint8Array(bytes), byte => byte.toString(16).padStart(2, '0')).join('');
    if (snapshot.paths.has(hash)) evidence = { kind: 'URL_SHA256', value: hash };
  }
  if (snapshot.expires <= now()) return { state: 'unavailable', cause: 'reputation' };
  return evidence ? { state: 'confirmed', threat: threatFor(snapshot, evidence), evidence, expires: snapshot.expires }
    : { state: 'no_match', expires: snapshot.expires };
}

export function threatFor(snapshot, { kind, value }) {
  switch (kind) {
    case 'HOST': return snapshot.hosts.get(value);
    case 'URL_PATH': return snapshot.urlPaths.get(value);
    case 'URL_SHA256': return snapshot.paths.get(value);
    default: return undefined;
  }
}

export function createSnapshotCache(storage, download, now = Date.now) {
  let active;

  async function update(entry, credential) {
    const { [STORAGE_KEY]: stored } = await storage.get(STORAGE_KEY);
    if (stored?.credentialId === credential.id) {
      entry.raw = stored.raw;
      entry.snapshot = parseSnapshot(stored.raw, now());
      entry.next = Math.min(stored.next, now() + MINUTE);
      if (entry.snapshot && entry.next > now()) return;
    }
    let raw;
    try {
      raw = await download(credential);
    } catch {
      raw = entry.raw;
    }
    entry.snapshot = parseSnapshot(raw, now());
    entry.raw = entry.snapshot ? raw : null;
    entry.next = entry.snapshot ? Math.min(now() + MINUTE, entry.snapshot.expires) : now() + 15000;
    if (active === entry) {
      await storage.set({
        [STORAGE_KEY]: { credentialId: credential.id, raw: entry.raw, next: entry.next }
      }).catch(() => {});
    }
  }

  return {
    async cached(credential) {
      if (active?.id === credential.id && active.snapshot) {
        return active.snapshot.expires > now() ? active.snapshot : null;
      }
      const { [STORAGE_KEY]: stored } = await storage.get(STORAGE_KEY);
      return stored?.credentialId === credential.id ? parseSnapshot(stored.raw, now()) : null;
    },
    async current(credential) {
      if (active?.id !== credential.id) active = { id: credential.id, next: 0 };
      const entry = active;
      if (entry.next <= now()) {
        entry.pending ??= update(entry, credential).finally(() => { entry.pending = null; });
        await entry.pending;
      }
      return active === entry && entry.snapshot?.expires > now() ? entry.snapshot : null;
    },
    async clear() {
      active = null;
      await storage.remove(STORAGE_KEY);
    }
  };
}

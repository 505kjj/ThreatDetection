export const DEFAULT_ORIGIN = 'http://127.0.0.1:8081';
const LOOPBACK = new Set(['127.0.0.1', 'localhost']);
const HOST_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export function backendOrigin(value) {
  if (typeof value !== 'string') return null;
  try {
    const url = new URL(value.trim());
    const allowed = url.protocol === 'https:' || (url.protocol === 'http:' && LOOPBACK.has(url.hostname));
    return allowed && url.href === url.origin + '/' ? url.origin : null;
  } catch {
    return null;
  }
}

export function backendPermission(origin) {
  const { protocol, hostname } = new URL(origin);
  return { origins: [`${protocol}//${hostname}/*`] };
}

export function siteHostname(value) {
  if (typeof value !== 'string' || /[\s/\\?#@:]/.test(value)) return null;
  try {
    const host = new URL('https://' + value).hostname.replace(/\.$/, '');
    return host.length <= 253 && host.split('.').every(label => HOST_LABEL.test(label)) ? host : null;
  } catch {
    return null;
  }
}

export function pageHostname(value) {
  try {
    const url = new URL(value);
    return ['http:', 'https:'].includes(url.protocol) ? siteHostname(url.hostname) : null;
  } catch {
    return null;
  }
}

function cleanList(value, pattern) {
  return Array.isArray(value) ? [...new Set(value.filter(item => typeof item === 'string' && pattern.test(item)))]
    .slice(0, 50) : [];
}

export function readSites(value) {
  if (!Array.isArray(value)) return [];
  return value.flatMap(site => {
    const domain = siteHostname(site?.domain);
    return domain ? [{
      domain,
      enabled: site.enabled !== false,
      sensitivePaths: cleanList(site.sensitivePaths, /^\/[a-z0-9_./-]{0,100}$/i),
      sensitiveFields: cleanList(site.sensitiveFields, /^[a-z0-9_-]{1,40}$/i)
    }] : [];
  });
}

export function matchingSite(sites, host) {
  if (!host) return null;
  const matches = sites.filter(site => host === site.domain || host.endsWith('.' + site.domain));
  return matches.sort((a, b) => b.domain.length - a.domain.length)[0] ?? null;
}

export function newSite(domain) {
  return {
    domain,
    enabled: true,
    sensitivePaths: ['/login', '/signin', '/account', '/payment', '/checkout'],
    sensitiveFields: ['password', 'otp', 'email', 'card', 'cvv', 'pin']
  };
}

import { createHash } from 'node:crypto';
import { destinationFor } from '../extension/reputation.mjs';
import { parse } from '../extension/vendor/tldts.mjs';

export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
export const featureVersion = 'url-lexical-v1';
export const featureColumns = [
  'https', 'nondefault_port', 'ip_host', 'idn_labels', 'hostname_length', 'host_labels',
  'host_digits', 'host_hyphens', 'registrant_length', 'subdomain_labels',
  'path_length', 'path_depth', 'path_digits', 'path_percent_escapes'
];

const count = (value, pattern) => value.match(pattern)?.length ?? 0;

export function extractUrl(raw, kind) {
  if (typeof raw !== 'string' || raw.length > 8192 || /[\u0000-\u001f\u007f]/u.test(raw) ||
      !/^https?:\/\//i.test(raw)) return null;
  const destination = destinationFor(raw);
  if (!destination) return null;
  const { host, key } = destination;
  const address = new URL(key);
  const parsed = parse(host, { allowPrivateDomains: true, extractHostname: false });
  // Reserved synthetic .test domains can be grouped without pretending they are publicly registered.
  const eligible = parsed.isIp || parsed.isIcann || parsed.isPrivate ||
    (kind === 'synthetic' && parsed.publicSuffix === 'test');
  if (!eligible || (!parsed.isIp && !parsed.domain)) return null;
  const labels = host.split('.');
  const pathname = address.pathname;
  return {
    host,
    group: parsed.isIp ? host : parsed.domain,
    keyHash: sha256(key),
    features: [
      Number(address.protocol === 'https:'), Number(address.port !== ''), Number(parsed.isIp),
      labels.filter(label => label.startsWith('xn--')).length, host.length, labels.length,
      count(host, /[0-9]/g), count(host, /-/g), parsed.domainWithoutSuffix?.length ?? 0,
      parsed.subdomain ? parsed.subdomain.split('.').length : 0, pathname === '/' ? 0 : pathname.length,
      pathname.split('/').filter(Boolean).length, count(pathname.replace(/%[0-9A-F]{2}/g, ''), /[0-9]/g),
      count(pathname, /%[0-9A-F]{2}/g)
    ]
  };
}

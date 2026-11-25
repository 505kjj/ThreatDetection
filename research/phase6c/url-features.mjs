// Mirrors the frozen url-lexical-v1 numerical features without retaining a URL hash.
export function extractBrowserUrl(raw, kind, destinationFor, parse) {
  if (typeof raw !== 'string' || raw.length > 8192 || /[\u0000-\u001f\u007f]/u.test(raw) ||
      !/^https?:\/\//i.test(raw)) return null;
  const destination = destinationFor(raw);
  if (!destination) return null;
  const { host, key } = destination;
  const address = new URL(key);
  const parsed = parse(host, { allowPrivateDomains: true, extractHostname: false });
  const eligible = parsed.isIp || parsed.isIcann || parsed.isPrivate ||
    (kind === 'synthetic' && parsed.publicSuffix === 'test');
  if (!eligible || (!parsed.isIp && !parsed.domain)) return null;
  const count = (value, pattern) => value.match(pattern)?.length ?? 0;
  const labels = host.split('.');
  const pathname = address.pathname;
  return {
    normalizedUrl: key,
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

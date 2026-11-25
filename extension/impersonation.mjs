import { financialBrands } from './financial-domains.mjs';
import { siteHostname } from './settings.mjs';
import { confusables } from './vendor/confusables.mjs';
import { toUnicode } from './vendor/punycode.mjs';
import { parse } from './vendor/tldts.mjs';

const scopeMatches = (host, scope) => host === scope || host.endsWith('.' + scope);
const options = { allowPrivateDomains: true, extractHostname: false };
const financialTerms = new Set(['account', 'banking', 'checkout', 'kyc', 'login', 'netbanking',
  'otp', 'payment', 'secure', 'signin', 'verify']);

function skeleton(label) {
  return Array.from(label.toLowerCase().normalize('NFD'), character => confusables[character] ?? character)
    .join('').normalize('NFD');
}

const brands = financialBrands.map(brand => ({
  ...brand,
  skeletons: new Set(brand.aliases.map(skeleton))
}));

export function verifiedFinancialHost(host) {
  return brands.some(brand => brand.scopes.some(scope => scopeMatches(host, scope)) || brand.sharedHosts?.includes(host));
}

function singleTypo(label, alias) {
  // Short initialisms overlap too many ordinary domains for fuzzy matching.
  if (alias.length < 7 || Math.abs(alias.length - label.length) > 1) return false;
  const [longer, shorter] = label.length > alias.length ? [label, alias] : [alias, label];
  let i = 0;
  while (i < shorter.length && longer[i] === shorter[i]) i++;
  if (longer.length !== shorter.length) return longer.slice(i + 1) === shorter.slice(i);
  if (i === shorter.length) return false;
  if (longer.slice(i + 1) === shorter.slice(i + 1)) return true;
  return longer[i] === shorter[i + 1] && longer[i + 1] === shorter[i] &&
    longer.slice(i + 2) === shorter.slice(i + 2);
}

function labelsFor(label) {
  const decoded = toUnicode(label);
  const parts = decoded.split('-').filter(Boolean);
  return parts.length < 2 ? parts : [...parts, parts.join('')];
}

function nameSignal(tokens, brand, registered, financialContext) {
  if (tokens.some(token => /[^\x00-\x7f]/.test(token) && brand.skeletons.has(skeleton(token)))) {
    return registered ? 'registered_homograph' : 'subdomain_homograph';
  }
  if (tokens.some(token => brand.aliases.includes(token) && (token.length > 4 || financialContext))) {
    return registered ? 'registered_brand' : 'subdomain_brand';
  }
  // Restrict fuzzy matches to the full registrant label, without fuzzy matching
  // arbitrary tokens or the labels of third-party tenants' subdomains.
  if (registered && /^[a-z0-9]+$/.test(tokens.at(-1) ?? '') &&
      brand.aliases.some(alias => singleTypo(tokens.at(-1), alias))) return 'registered_typo';
  return null;
}

function evidenceFor(brand, labelsBeforeSuffix, registrant, subdomainLabels, financialContext) {
  if (brand.scopes.some(scope => labelsBeforeSuffix.includes('.' + scope + '.'))) {
    return 'embedded_official_domain';
  }
  return nameSignal(registrant, brand, true, financialContext) ??
    nameSignal(subdomainLabels, brand, false, financialContext) ??
    (financialContext && subdomainLabels.some(token =>
      /^[a-z0-9]+$/.test(token) && brand.aliases.some(alias => alias.length >= 8 && singleTypo(token, alias)))
      ? 'subdomain_typo' : null);
}

const descriptions = {
  embedded_official_domain: brand => `An official ${brand} address is embedded in a hostname controlled by another domain.`,
  registered_brand: brand => `The registered domain uses the ${brand} name outside its verified domains.`,
  registered_typo: brand => `The registered domain differs from the ${brand} name by one typing change.`,
  registered_homograph: brand => `The registered domain uses Unicode characters that resemble the ${brand} name.`,
  subdomain_brand: brand => `A subdomain uses the ${brand} name under a different registered domain.`,
  subdomain_typo: brand => `A subdomain with a sign-in or payment term resembles the ${brand} name with one typing change.`,
  subdomain_homograph: brand => `A subdomain uses Unicode characters that resemble the ${brand} name.`
};

export function detectImpersonation(hostname) {
  const host = siteHostname(hostname);
  if (!host) return [];
  const { domainWithoutSuffix, publicSuffix, subdomain, isIcann, isPrivate } = parse(host, options);
  if (!domainWithoutSuffix || (!isIcann && !isPrivate)) return [];
  const registrant = labelsFor(domainWithoutSuffix);
  const subdomainLabels = subdomain ? subdomain.split('.').flatMap(labelsFor) : [];
  const labelsBeforeSuffix = '.' + host.slice(0, -(publicSuffix.length + 1)) + '.';
  const financialContext = [...registrant, ...subdomainLabels].some(token => financialTerms.has(token));
  return brands.flatMap(brand => {
    if (brand.scopes.some(scope => scopeMatches(host, scope)) || brand.sharedHosts?.includes(host)) return [];
    const kind = evidenceFor(brand, labelsBeforeSuffix, registrant, subdomainLabels, financialContext);
    return kind ? [{ kind, reason: descriptions[kind](brand.name) }] : [];
  });
}

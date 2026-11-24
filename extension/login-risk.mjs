import { verifiedFinancialHost } from './impersonation.mjs';
import { parse } from './vendor/tldts.mjs';

const authenticationHosts = new Set(['accounts.google.com', 'login.microsoftonline.com']);
const structuralKinds = new Set(['embedded_official_domain', 'registered_brand',
  'registered_homograph', 'subdomain_homograph']);
const credentialKinds = new Set(['password', 'payment']);
const parseDomain = host => parse(host, { allowPrivateDomains: true, extractHostname: false }).domain;

function classifyDestination(value, pageOrigin) {
  if (value === null) return 'unknown';
  if (typeof value !== 'string' || value.length > 300) return null;
  let destination;
  try { destination = new URL(value); } catch { return null; }
  if (destination.origin !== value || !['http:', 'https:'].includes(destination.protocol)) return null;
  if (pageOrigin === value) return 'same';
  if (destination.protocol === 'https:' && !destination.port &&
      (authenticationHosts.has(destination.hostname) || verifiedFinancialHost(destination.hostname))) return 'recognized';
  const targetDomain = parseDomain(destination.hostname);
  const pageDomain = parseDomain(new URL(pageOrigin).hostname);
  return targetDomain && pageDomain && targetDomain !== pageDomain ? 'external' : 'unknown';
}

// An observation describes available HTML controls and declared form targets. It never proves submission.
export function loginEvidence(forms, pageOrigin, brandEvidence, redirected = false) {
  if (!brandEvidence.length || !Array.isArray(forms) || forms.length > 4) return [];
  const pageHost = new URL(pageOrigin).hostname;
  if (authenticationHosts.has(pageHost) || verifiedFinancialHost(pageHost)) return [];
  const observed = [];
  for (const form of forms) {
    if (!form || !credentialKinds.has(form.kind) ||
        Object.keys(form).length !== 2 || !Object.hasOwn(form, 'destination')) return [];
    const destination = classifyDestination(form.destination, pageOrigin);
    if (destination === null) return [];
    if (destination !== 'recognized') observed.push({ kind: form.kind, destination });
  }
  if (!observed.length) return [];
  const reasons = [];
  if (observed.some(form => form.kind === 'password')) reasons.push({
    kind: 'financial_password_form', reason: 'A visible password field was found on this unverified financial lookalike.'
  });
  if (observed.some(form => form.kind === 'payment')) reasons.push({
    kind: 'financial_payment_form', reason: 'A visible payment form asks for card details on this unverified financial lookalike.'
  });
  if (brandEvidence.some(item => structuralKinds.has(item.kind)) && observed.some(form => form.destination === 'external')) {
    reasons.push({ kind: 'financial_external_form',
      reason: 'A credential form points to an unrelated origin outside the recognized banking, payment, and sign-in hosts.' });
  }
  if (redirected) reasons.push({ kind: 'financial_redirect_context',
    reason: 'The browser observed a redirect before arriving at this financial lookalike with a credential form.' });
  return reasons;
}

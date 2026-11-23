import assert from 'node:assert/strict';
import test from 'node:test';
import { detectImpersonation } from '../impersonation.mjs';
import { financialBrands } from '../financial-domains.mjs';
import { parse } from '../vendor/tldts.mjs';
import { ambiguousBenign, benignSynthetic, official, suspicious } from './impersonation-fixtures.mjs';

test('registered domain respects bank.in, multi-label and private public suffixes', () => {
  const parsed = host => parse(host, { allowPrivateDomains: true });
  assert.equal(parsed('now.hdfc.bank.in').domain, 'hdfc.bank.in');
  assert.equal(parsed('sbi.bank.in.example.co.in').domain, 'example.co.in');
  assert.equal(parsed('account.hdfcbank.pages.dev').domain, 'hdfcbank.pages.dev');
  assert.equal(parsed('login.sbi.bank.in.github.io').domain, 'in.github.io');
  for (const brand of financialBrands) {
    for (const scope of brand.scopes) assert.equal(parsed(scope).domain, scope);
  }
});

test('looks for DNS labels and Unicode confusables in the relevant domain component', () => {
  for (const [host, kind] of suspicious) {
    assert.equal(detectImpersonation(host)[0]?.kind, kind, host);
  }
  const unicode = 'rаzorpay.github.io';
  assert.deepEqual(detectImpersonation(new URL('https://' + unicode).hostname), detectImpersonation(unicode));
  for (const input of ['https://hdfcbank.github.io', 'sbi.bank.in@example.org', 'sbi..example.org', 'x'.repeat(254)]) {
    assert.deepEqual(detectImpersonation(input), []);
  }
});

test('a co-branded payment host only suppresses its explicitly verified brand evidence', () => {
  assert.deepEqual(detectImpersonation('hdfcbank-collectnow-docs.razorpay.com'), []);
  // A reserved brand address embedded under an unrelated operator may still be spoofing.
  assert.equal(detectImpersonation('sbi.bank.in.razorpay.com')[0]?.kind, 'embedded_official_domain');
});

test('measures false cautions on labeled official, benign and ambiguous fixtures', t => {
  const warned = hosts => hosts.filter(host => detectImpersonation(host).length);
  const falsePositives = warned([...official, ...benignSynthetic, ...ambiguousBenign]);
  t.diagnostic(`Official ${warned(official).length}/${official.length} false cautions. ` +
    `All benign ${falsePositives.length}/${official.length + benignSynthetic.length + ambiguousBenign.length}. ` +
    `Suspicious hostname fixtures detected ${warned(suspicious.map(([host]) => host)).length}/${suspicious.length}.`);
  assert.deepEqual(warned(official), []);
  assert.deepEqual(warned(benignSynthetic), []);
  assert.deepEqual(falsePositives, ambiguousBenign);
});

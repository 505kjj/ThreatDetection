import assert from 'node:assert/strict';
import test from 'node:test';
import { detectImpersonation } from '../impersonation.mjs';
import { loginEvidence } from '../login-risk.mjs';

const lookalike = 'https://axis.bank.in.example.org';
const unrelated = 'https://forms.example.net';
const password = destination => ({ kind: 'password', destination });
const payment = destination => ({ kind: 'payment', destination });

const controls = [
  ['https://axis.bank.in', [password('https://accounts.google.com')], true],
  ['https://www.axisbank.com', [password('https://axis.bank.in')], true],
  ['https://bobworld.bankofbaroda.bank.in', [password('https://www.bobibanking.com')], true],
  ['https://merchant.example.org', [payment('https://api.razorpay.com')], true],
  ['https://merchant.example.org', [password('https://login.microsoftonline.com')], true],
  ['https://www.phonepe.com', [payment('https://merchant.example.org')], true],
  ['https://sbi.bank.in.razorpay.com', [password(unrelated)], true],
  ['https://ordinary.example.org', [password(unrelated)], true],
  [lookalike, [password('https://accounts.google.com')], true],
  [lookalike, [password('https://login.microsoftonline.com')], true],
  [lookalike, [payment('https://api.razorpay.com')], true],
  [lookalike, [], true]
];

const labeledSynthetic = [
  [lookalike, [password(lookalike)], false, ['financial_password_form']],
  [lookalike, [password(unrelated)], false, ['financial_password_form', 'financial_external_form']],
  [lookalike, [payment(unrelated)], true, ['financial_payment_form', 'financial_external_form', 'financial_redirect_context']],
  ['https://phonepe-payment.example.org', [payment(null)], false, ['financial_payment_form']],
  ['https://axisbnak-login.example.org', [password(unrelated)], false, ['financial_password_form']],
  [lookalike, [password('https://other.example.org')], true, ['financial_password_form', 'financial_redirect_context']],
  [lookalike, [password('https://accounts.google.com.example.net')], false, ['financial_password_form', 'financial_external_form']],
  ['https://pһonepe.example.org', [password(null)], false, ['financial_password_form']]
];

function evaluate(page, forms, redirected) {
  const url = new URL(page);
  return loginEvidence(forms, url.origin, detectImpersonation(url.hostname), redirected).map(item => item.kind);
}

test('measures structural advisories against labeled benign scenarios and synthetic lookalike forms', t => {
  const falseCautions = controls.filter(([page, forms, redirected]) => evaluate(page, forms, redirected).length);
  let detected = 0;
  for (const [page, forms, redirected, expected] of labeledSynthetic) {
    const result = evaluate(page, forms, redirected);
    assert.deepEqual(result, expected, page);
    detected += Number(result.length > 0);
  }
  t.diagnostic(`Structured evidence on ${detected}/${labeledSynthetic.length} synthetic positives. ` +
    `Added false cautions on ${falseCautions.length}/${controls.length} benign or baseline-only controls.`);
  assert.deepEqual(falseCautions, []);
});

test('requires canonical origins and a bounded, fixed message shape', () => {
  for (const forms of [
    Array(5).fill(password(null)), [{ ...password(null), secret: 'example' }],
    [password('https://forms.example.net/anything')], [password('https://forms.example.net?secret=1')],
    [password('https://name@forms.example.net')], [password('javascript:')], [{ kind: 'not-supported' }], [null]
  ]) assert.deepEqual(evaluate(lookalike, forms, true), []);
});

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { FEATURE_GROUPS } from './dom.mjs';
import { FIXTURES, ORIGIN } from './fixtures.mjs';
import { inspectHtml, MAX_BYTES } from './parse.mjs';

test('synthetic credential and payment controls expose metadata without raw values', () => {
  const login = inspectHtml(FIXTURES['banking-login'], ORIGIN).features;
  const checkout = inspectHtml(FIXTURES['payment-gateway'], ORIGIN).features;
  const identity = inspectHtml(FIXTURES['cross-origin-form'], ORIGIN).features;
  assert.deepEqual(Object.keys(login).sort(), Object.values(FEATURE_GROUPS).flat().sort());
  assert.equal(login.password_forms, 1);
  assert.equal(login.actions_local, 1);
  assert.equal(checkout.payment_forms, 1);
  assert.equal(checkout.actions_external, 1);
  assert.equal(identity.password_forms, 1);
  assert.equal(identity.actions_external, 1);
  assert.equal(inspectHtml(FIXTURES['embedded-payment-auth'], ORIGIN).features.iframe_external, 2);
});

test('HTML inspection drops literal values and avoids callbacks or resource requests', () => {
  const marker = 'fixture-secret-sentinel';
  const parsed = inspectHtml('<!doctype html><title>Sign in</title>\n<p>Hello world</p>' +
    '<form action="https://identity.fixture.test/session?token=' + marker + '">' +
    '<input value="' + marker + '" type=password><textarea>' + marker + '</textarea></form>' +
    '<script src="https://identity.fixture.test/script" onload="throw 1"></script>' +
    '<script>throw "execution sentinel"</script><iframe srcdoc="' + marker + '"></iframe>', ORIGIN);
  assert.equal(parsed.status, 'usable');
  assert.equal(parsed.features.scripts, 2);
  assert.equal(parsed.features.iframe_srcdoc, 1);
  assert.equal(parsed.features.title_login, 1);
  assert.equal(JSON.stringify(parsed).includes(marker), false);
});

test('document and parser limits yield explicit rejection categories', () => {
  assert.equal(inspectHtml(null, ORIGIN).status, 'missing');
  assert.equal(inspectHtml(' ', ORIGIN).status, 'missing');
  assert.equal(inspectHtml('p'.repeat(MAX_BYTES + 1), ORIGIN).status, 'oversized');
  assert.equal(inspectHtml('<!doctype html><input type="pass', ORIGIN).status, 'truncated');
  assert.equal(inspectHtml('<main>'.repeat(140) + '</main>'.repeat(140), ORIGIN).status, 'structure-limit');
  assert.equal(inspectHtml('<!doctype html><p id=x id=y>hello</p>', ORIGIN).malformed, true);
});

test('declared origins account for base URLs, special schemes and refresh metadata', () => {
  const parsed = inspectHtml('<!doctype html><base href=https://origin.fixture.test/>' +
    '<meta http-equiv=refresh content="1;url=/next"><a href=/continue>Continue</a>' +
    '<a href="mailto:contact@fixture.test">Contact</a><form></form><form action="/post"></form>', ORIGIN);
  assert.equal(parsed.features.actions_local, 1);
  assert.equal(parsed.features.actions_external, 1);
  assert.equal(parsed.features.links_external_ratio, 1);
  assert.equal(parsed.features.links_other, 1);
  assert.equal(parsed.features.refresh_external, 1);
});

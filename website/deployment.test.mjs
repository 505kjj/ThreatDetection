import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { pages } from './pages.mjs';

const config = JSON.parse(readFileSync(new URL('../vercel.json', import.meta.url), 'utf8'));
const build = fileURLToPath(new URL('./build.mjs', import.meta.url));
const monitor = 'https://phase-8a-fixture.onrender.com/monitor';
const email = 'operator@example.invalid';
const buildSite = (target, url, operator) => spawnSync(process.execPath, [build, '--vercel', target], {
  encoding: 'utf8', env: { ...process.env, THREAT_PUBLIC_MONITOR_URL: url, THREAT_PUBLIC_OPERATOR_EMAIL: operator }
});

test('Vercel builds require an HTTPS dashboard and approved contact and emit a static allowlist', t => {
  const folder = mkdtempSync(join(tmpdir(), 'td-vercel-config-'));
  t.after(() => rmSync(folder, { recursive: true, force: true }));
  assert.notEqual(buildSite(folder, monitor, '').status, 0);
  assert.notEqual(buildSite(folder, 'http://127.0.0.1:8081/monitor', email).status, 0);
  assert.notEqual(buildSite(folder, monitor, 'x@example.invalid"><img>').status, 0);
  assert.deepEqual(readdirSync(folder), []);
  const result = buildSite(folder, monitor, email);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(readdirSync(folder).sort(), ['404.html', 'assets', 'index.html', ...Object.keys(pages).filter(Boolean)].sort());
  const assets = readdirSync(join(folder, 'assets')).sort();
  assert.deepEqual(assets, ['Inter-OFL.txt', 'console.webp', 'extension.webp', 'inter-latin.woff2',
    'mark.svg', 'site.css', 'site.js', 'warning.webp']);
  for (const page of Object.keys(pages)) {
    const content = readFileSync(join(folder, page, 'index.html'), 'utf8');
    assert.match(content, /<main id="main"/);
    if (page !== 'privacy') assert(!content.includes(email));
  }
  assert(readFileSync(join(folder, 'administrator/index.html'), 'utf8').includes(monitor));
  assert(readFileSync(join(folder, 'privacy/index.html'), 'utf8').includes('mailto:' + email));
  assert.notEqual(buildSite(folder, monitor, email).status, 0);
});

test('Vercel routes map clean directory URLs and retain a real 404 fallback', () => {
  assert.equal(config.buildCommand, 'node website/build.mjs --vercel');
  assert.equal(config.outputDirectory, 'website/dist');
  assert.equal(config.git.deploymentEnabled, false);
  const [headers, home, directories, filesystem, fallback] = config.routes;
  assert.equal(headers.continue, true);
  assert.match(headers.headers['Content-Security-Policy'], /connect-src 'none'/);
  assert.equal(headers.headers['Referrer-Policy'], 'no-referrer');
  assert.equal(home.dest, '/index.html');
  const route = new RegExp(directories.src);
  for (const page of Object.keys(pages).filter(Boolean)) {
    for (const path of ['/' + page, '/' + page + '/']) {
      assert.equal(path.replace(route, directories.dest), '/' + page + '/index.html');
    }
  }
  for (const path of ['/monitor', '/api/health', '/api/threat/monitoring/dashboard', '/.git/config', '/docs/unlisted']) {
    assert.equal(route.test(path), false);
  }
  assert.equal(filesystem.handle, 'filesystem');
  assert.equal(fallback.status, 404);
  assert.equal(fallback.dest, '/404.html');
});

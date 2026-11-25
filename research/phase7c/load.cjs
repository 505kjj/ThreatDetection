// Bounded loopback-only load fixture. No real records or credentials are used.
const assert = require('node:assert/strict');
const { randomBytes, randomUUID, createHash } = require('node:crypto');
const { spawn, spawnSync } = require('node:child_process');
const { once } = require('node:events');
const { mkdtempSync, realpathSync, rmSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { basename, dirname, join, resolve, sep } = require('node:path');

async function main() {
  const output = resolve(process.argv[2] || '');
  const root = resolve(__dirname, '../..');
  if (!process.argv[2] || output === root || output.startsWith(root + sep)) throw new Error('Private output path required');
  const storage = process.argv[3] ?? 'memory';
  if (!['memory', 'file'].includes(storage)) throw new Error('Use memory or file storage');
  const parent = realpathSync(tmpdir());
  const profile = storage === 'file' ? mkdtempSync(join(parent, 'td-load-')) : null;
  const token = () => randomBytes(32).toString('base64url');
  const digest = value => createHash('sha256').update(value).digest('hex');
  const browserTokens = Array.from({ length: 9 }, token);
  const admin = token();
  const clients = Object.fromEntries(browserTokens.map((value, index) => [`fixture-${index}`,
    { role: 'BROWSER', 'token-sha256': digest(value) }]));
  clients.admin = { role: 'ADMIN', 'token-sha256': digest(admin) };
  const config = { threat: { monitoring: { 'synthetic-clients': browserTokens.map((_, i) => `fixture-${i}`) },
    security: { clients, 'allowed-origins': [] } } };
  if (profile) config.threat.monitoring['store-path'] = join(profile, 'monitoring');
  const java = /^\s*java\.home = (.+)$/m.exec(spawnSync('java', ['-XshowSettings:properties', '-version'],
    { encoding: 'utf8' }).stderr)[1].trim();
  const server = spawn(java + '/bin/java.exe', ['-jar', resolve(root, 'backend/target/threat-detection-0.0.1-SNAPSHOT.jar'),
    '--server.address=127.0.0.1', '--server.port=0'],
  { env: { ...globalThis.process.env, SPRING_APPLICATION_JSON: JSON.stringify(config) } });
  let logs = '';
  for (const stream of [server.stdout, server.stderr]) stream.on('data', part => { logs = (logs + part).slice(-8000); });
  try {
    let origin;
    const deadline = Date.now() + 120000;
    while (Date.now() < deadline && server.exitCode === null) {
      const port = /Tomcat started on port (\d+)/.exec(logs)?.[1];
      if (port) {
        const address = `http://127.0.0.1:${port}`;
        if ((await fetch(address + '/api/health', { signal: AbortSignal.timeout(1500) }).catch(() => null))?.ok) {
          origin = address; break;
        }
      }
      await new Promise(resolve => setTimeout(resolve, 350));
    }
    assert.ok(origin, 'Backend did not become healthy');
    async function send(endpoint, credential, body) {
      const start = performance.now();
      const response = await fetch(origin + '/api/threat/monitoring/' + endpoint, { method: 'POST',
        headers: { Authorization: 'Bearer ' + credential, 'Content-Type': 'application/json' },
        body: JSON.stringify(body), signal: AbortSignal.timeout(8000) });
      return { status: response.status, ms: performance.now() - start };
    }
    for (const credential of browserTokens) assert.equal((await send('heartbeat', credential, { protection: 'REPUTATION_AVAILABLE' })).status, 204);
    function submit(credential) {
      return send('events', credential, { id: randomUUID(), signal: 'PHISHING', action: 'BLOCKED',
        detectedAt: new Date().toISOString() });
    }
    const stages = [];
    let accepted = 0;
    for (const concurrency of [1, 4, 8]) {
      const started = performance.now();
      const results = [];
      for (let round = 0; round < 16; round++) {
        results.push(...await Promise.all(browserTokens.slice(0, concurrency).map(submit)));
        const delay = started + (round + 1) * 500 - performance.now();
        if (delay > 0) await new Promise(resolve => setTimeout(resolve, delay));
      }
      const wallMs = performance.now() - started;
      const successful = results.filter(item => item.status === 204).length;
      accepted += successful;
      const times = results.map(item => item.ms).sort((a, b) => a - b);
      const percentile = p => times[Math.ceil(p * times.length) - 1];
      stages.push({ concurrency, attempts: results.length, successful, errors: results.length - successful,
        wallMs, eventsPerSecond: successful * 1000 / wallMs,
        medianMs: percentile(0.5), p95Ms: percentile(0.95), p99Ms: percentile(0.99) });
    }
    assert.equal(accepted, 208);
    const dashboard = await fetch(origin + '/api/threat/monitoring/dashboard?scope=SYNTHETIC',
      { headers: { Authorization: 'Bearer ' + admin } });
    assert.equal(dashboard.status, 200);
    const data = await dashboard.json();
    assert.equal(data.total, accepted);
    const limitClient = browserTokens.at(-1);
    const quotaResults = [];
    for (let index = 0; index < 61; index++) quotaResults.push((await submit(limitClient)).status);
    assert.ok(quotaResults.slice(0, 60).every(status => status === 204));
    assert.equal(quotaResults[60], 429);
    const report = { storage, stages, syntheticDashboardTotal: data.total,
      rateLimit: { accepted: 60, rejected: 1, rejectionStatus: 429 },
      scope: 'Paced loopback stages with a separate rate-limit client, no capacity extrapolation' };
    writeFileSync(output, JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
    console.log(JSON.stringify(report));
  } finally {
    if (server.exitCode === null && server.signalCode === null) {
      const exited = once(server, 'exit'); server.kill(); await exited;
    }
    if (profile) {
      const target = realpathSync(profile);
      if (dirname(target) !== parent || !basename(target).startsWith('td-load-')) throw new Error('Unexpected profile path');
      rmSync(target, { recursive: true });
    }
  }
}
main().catch(error => { console.error(error.stack); process.exitCode = 1; });

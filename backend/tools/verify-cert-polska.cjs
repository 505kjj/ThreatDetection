// Opt-in, loopback-only verification. Contacts the official feed, never a listed host.
const assert = require('node:assert/strict');
const { spawn, spawnSync } = require('node:child_process');
const { createHash, createHmac, randomBytes } = require('node:crypto');
const { once } = require('node:events');
const { mkdtempSync, readFileSync, rmSync, rmdirSync } = require('node:fs');
const { tmpdir } = require('node:os');
const path = require('node:path');
const { setTimeout: sleep } = require('node:timers/promises');

const digest = input => createHash('sha256').update(input).digest('hex');

function javaExecutable() {
  const result = spawnSync('java', ['-XshowSettings:properties', '-version'], { encoding: 'utf8' });
  const home = /^\s*java\.home = (.+)$/m.exec(result.stderr ?? '')?.[1]?.trim();
  if (result.status !== 0 || !home) throw new Error('Java 21 is required');
  return path.join(home, 'bin', process.platform === 'win32' ? 'java.exe' : 'java');
}

async function main() {
  if (process.env.THREAT_RUN_LIVE_FEED_TEST !== '1') {
    throw new Error('Set THREAT_RUN_LIVE_FEED_TEST=1 to enable the one-time official feed test');
  }
  const java = javaExecutable();
  const directory = mkdtempSync(path.join(tmpdir(), 'threat-cert-polska-'));
  const snapshot = path.join(directory, 'snapshot.json');
  const key = randomBytes(32);
  const admin = randomBytes(32).toString('base64url');
  const browser = randomBytes(32).toString('base64url');
  const clients = {
    'live-test-admin': { role: 'ADMIN', 'token-sha256': digest(admin) },
    'live-test-browser': { role: 'BROWSER', 'token-sha256': digest(browser) }
  };
  const jar = path.resolve(__dirname, '../target/threat-detection-0.0.1-SNAPSHOT.jar');
  const child = spawn(java, ['-jar', jar, '--server.address=127.0.0.1', '--server.port=0'], {
    env: { ...process.env,
      SPRING_APPLICATION_JSON: JSON.stringify({ threat: { security: { clients }, reputation: {
        'snapshot-path': snapshot, ingestion: { enabled: true, 'browser-distribution-approved': false,
          'signing-key': key.toString('hex'), 'poll-interval': 'PT5M', 'initial-delay': 'PT0S' }
      } } })
    }
  });
  let logs = '';
  child.stdout.on('data', chunk => { logs = (logs + chunk).slice(-16000); });
  child.stderr.on('data', chunk => { logs = (logs + chunk).slice(-16000); });
  child.on('error', error => { logs += error.message; });
  const endpoint = '/api/threat/reputation/feed-status';
  let origin;
  const request = (route, token, body) => fetch(origin + route, {
    method: body ? 'POST' : 'GET',
    headers: { ...(token ? { Authorization: 'Bearer ' + token } : {}),
      ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(3000)
  });
  try {
    const deadline = Date.now() + 150000;
    let status;
    while (Date.now() < deadline) {
      const port = /Tomcat started on port (\d+)/.exec(logs)?.[1];
      if (port) {
        origin = 'http://127.0.0.1:' + port;
        const response = await request(endpoint, admin).catch(() => null);
        if (response?.ok) {
          status = await response.json();
          if (status.failedPolls > 0) throw new Error('Official feed pipeline reported ' + status.pollState);
          if (status.successfulPolls === 1) break;
        }
      }
      if (child.exitCode !== null) break;
      await sleep(500);
    }
    if (!status || status.successfulPolls !== 1) {
      throw new Error('Live ingestion did not complete within the readiness window\n' + logs);
    }
    assert.equal(status.provider, 'CERT_POLSKA');
    assert.equal(status.dataState, 'CURRENT');
    assert.equal(status.providerAvailable, true);
    assert.equal(status.browserDistributionApproved, false);
    assert.equal((await request(endpoint)).status, 401);
    assert.equal((await request(endpoint, browser)).status, 403);
    assert.equal((await request('/api/threat/reputation/snapshot', browser)).status, 503);
    const artifact = JSON.parse(readFileSync(snapshot, 'utf8'));
    const payload = Buffer.from(artifact.payload, 'base64');
    assert.equal(artifact.formatVersion, 1);
    assert.equal(artifact.source, 'CERT_POLSKA');
    assert.equal(digest(payload), artifact.version);
    assert.equal(artifact.version, status.version);
    assert.equal(createHmac('sha256', key).update('threat-detection:reputation:1:CERT_POLSKA\n')
      .update(payload).digest('hex'), artifact.hmacSha256);
    const feed = JSON.parse(payload);
    assert.equal(feed.entries.length, status.publishedIndicators);
    assert.ok(feed.entries.length > 0 && feed.entries.length <= 20000);
    assert.ok(Date.parse(feed.expiresAt) - Date.parse(feed.generatedAt) <= 15 * 60000);
    const { value: domain } = feed.entries[0];
    const session = await request('/api/threat/session/start', browser, { domain });
    assert.equal(session.status, 200);
    const risk = await request('/api/threat/analyze', browser, {
      sessionId: (await session.json()).sessionId, eventType: 'page_view'
    });
    assert.equal(risk.status, 200);
    assert.equal((await risk.json()).reputationStatus, 'CONFIRMED_MALICIOUS');
    assert.ok(!logs.includes(domain));
    console.log(JSON.stringify({
      result: 'PASS', source: status.provider, version: status.version,
      sourceModifiedAt: status.sourceModifiedAt, expiresAt: status.expiresAt,
      sourceActiveIndicators: status.sourceActiveIndicators, publishedIndicators: status.publishedIndicators,
      rejectedIndicators: status.rejectedIndicators, confirmedServerMatch: true, browserDistributionApproved: false
    }));
  } finally {
    if (child.pid && child.exitCode === null && child.signalCode === null) {
      const exited = once(child, 'exit');
      child.kill();
      await exited;
    }
    rmSync(snapshot, { force: true });
    rmdirSync(directory);
  }
}

main().catch(error => {
  console.error(error.message);
  process.exitCode = 1;
});

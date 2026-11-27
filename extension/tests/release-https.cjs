// Test-only HTTPS termination and separate website origin on IPv4 loopback.
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { createHash, X509Certificate } = require('node:crypto');
const { once } = require('node:events');
const { readFileSync } = require('node:fs');
const { request } = require('node:http');
const { createServer } = require('node:https');
const { join, resolve } = require('node:path');
const { pathToFileURL } = require('node:url');

function tlsConfiguration(directory) {
  const cert = readFileSync(join(directory, 'server.pem'));
  const key = readFileSync(join(directory, 'server.key'));
  const spki = new X509Certificate(cert).publicKey.export({ type: 'spki', format: 'der' });
  const pin = createHash('sha256').update(spki).digest('base64');
  return { cert, key, pin };
}

async function openReleaseEndpoints(tls, upstreamPort, folder) {
  const server = createServer(tls, (incoming, outgoing) => {
    const forward = request({
      hostname: '127.0.0.1', port: upstreamPort, method: incoming.method, path: incoming.url,
      headers: incoming.headers, timeout: 8000
    }, upstream => {
      outgoing.writeHead(upstream.statusCode, upstream.headers);
      upstream.pipe(outgoing);
    });
    forward.on('error', () => outgoing.destroy());
    forward.on('timeout', () => forward.destroy());
    incoming.on('error', () => forward.destroy());
    incoming.pipe(forward);
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const origin = 'https://localhost:' + server.address().port;
  let website;
  try {
    const healthy = await fetch(origin + '/api/health', { signal: AbortSignal.timeout(5000) });
    assert.equal(healthy.status, 200);
    const build = resolve(__dirname, '../../website/build.mjs');
    const output = join(folder, 'release-website');
    const result = spawnSync(process.execPath, [build, output], {
      env: { ...process.env, THREAT_PUBLIC_MONITOR_URL: origin + '/monitor' }, encoding: 'utf8'
    });
    assert.equal(result.status, 0, result.stderr);
    const { servePreview } = await import('../../website/preview.mjs');
    website = await servePreview(0, pathToFileURL(output + '/'));
    return { origin, website: website.url, close: () => {
      website.server.close();
      server.close();
    } };
  } catch (error) {
    website?.server.close();
    server.close();
    throw error;
  }
}

module.exports = { tlsConfiguration, openReleaseEndpoints };

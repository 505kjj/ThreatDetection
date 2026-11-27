// Disposable loopback-only PostgreSQL exercise. It never accepts an existing database endpoint.
const assert = require('node:assert/strict');
const { spawn, spawnSync } = require('node:child_process');
const { createHash, randomBytes, randomUUID } = require('node:crypto');
const { once } = require('node:events');
const { mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } = require('node:fs');
const { createServer } = require('node:net');
const { tmpdir } = require('node:os');
const { basename, dirname, join, resolve } = require('node:path');
const { setTimeout: wait } = require('node:timers/promises');

const [reportFile, pgServer, pgClients, openssl] = process.argv.slice(2);
const repo = resolve(__dirname, '..');
const executable = process.platform === 'win32' ? '.exe' : '';
const renderProfile = process.env.THREAT_RELEASE_RENDER_PROFILE === '1';
const credential = () => randomBytes(32).toString('base64url');
const digest = text => createHash('sha256').update(text).digest('hex');
const cleanEnv = Object.fromEntries(Object.entries(process.env)
  .filter(([name]) => !/^(PG|SPRING_|THREAT_|SERVER_)/i.test(name)));

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { timeout: 180000, encoding: 'utf8', windowsHide: true, ...options });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, `${basename(command)} failed with status ${result.status}`);
  return result.stdout?.trim() ?? '';
}

async function freePort() {
  const listener = createServer().listen(0, '127.0.0.1');
  await once(listener, 'listening');
  const { port } = listener.address();
  await new Promise(resolve => listener.close(resolve));
  return port;
}

function startBackend(configuration, env = {}) {
  const javaInfo = spawnSync('java', ['-XshowSettings:properties', '-version'], { encoding: 'utf8' });
  const javaHome = /^\s*java\.home = (.+)$/m.exec(javaInfo.stderr)?.[1]?.trim();
  assert(javaHome, 'Java 21 is required');
  const jar = join(repo, 'backend', 'target', 'threat-detection-0.0.1-SNAPSHOT.jar');
  const postgres = configuration.threat.monitoring.postgres;
  const deploymentEnv = renderProfile ? {
    SPRING_PROFILES_ACTIVE: 'render', PORT: '0',
    TD_RENDER_NEON_JDBC_URL: postgres['jdbc-url'],
    TD_RENDER_NEON_USER: postgres.username, TD_RENDER_NEON_PASSWORD: postgres.password,
    TD_RENDER_EXTENSION_ORIGIN: 'chrome-extension://' + 'a'.repeat(32),
    TD_RENDER_BROWSER_DIGEST: digest(credential()), TD_RENDER_ADMIN_DIGEST: digest(credential())
  } : {};
  const jvm = renderProfile ? ['@' + join(repo, 'deploy', 'render-jvm.options'),
    '-XX:NativeMemoryTracking=summary', '-Xlog:gc'] : ['-Xmx256m'];
  const started = performance.now();
  const child = spawn(join(javaHome, 'bin', 'java' + executable),
    [...jvm, '-jar', jar, '--server.address=127.0.0.1', ...(renderProfile ? [] : ['--server.port=0'])], {
      env: { ...cleanEnv, ...env, ...deploymentEnv, SPRING_APPLICATION_JSON: JSON.stringify(configuration) },
      windowsHide: true
    });
  let logs = '';
  for (const stream of [child.stdout, child.stderr]) {
    stream.on('data', data => { logs = (logs + data).slice(-16000); });
  }
  return {
    child,
    async ready() {
      for (let attempt = 0; attempt < 180 && child.exitCode === null; attempt++) {
        const port = /Tomcat started on port (\d+)/.exec(logs)?.[1];
        if (port) {
          const origin = 'http://127.0.0.1:' + port;
          if ((await fetch(origin + '/api/health', { signal: AbortSignal.timeout(1500) }).catch(() => null))?.ok) {
            this.startupMs = performance.now() - started;
            return origin;
          }
        }
        await wait(500);
      }
      throw new Error('Disposable backend did not start');
    },
    logs: () => logs,
    memory() {
      const jcmd = join(javaHome, 'bin', 'jcmd' + executable);
      const sample = (...args) => run(jcmd, [String(child.pid), ...args]);
      const nmt = sample('VM.native_memory', 'summary', 'scale=KB');
      const committed = /Total:.*committed=(\d+)KB/.exec(nmt);
      const heap = /Java Heap.*committed=(\d+)KB/.exec(nmt);
      const vmFlags = sample('VM.flags');
      const maximumHeap = /MaxHeapSize=(\d+)/.exec(vmFlags);
      const heapGroups = [...sample('GC.heap_info').matchAll(/total (\d+)K, used (\d+)K/g)];
      assert(committed && heap && maximumHeap && heapGroups.length, 'Missing JVM resource counters');
      let processMemory;
      if (process.platform === 'win32') {
        processMemory = JSON.parse(run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command',
          `Get-Process -Id ${child.pid} | Select-Object WorkingSet64,PeakWorkingSet64,PrivateMemorySize64,@{n='Threads';e={$_.Threads.Count}} | ConvertTo-Json -Compress`]));
      } else {
        const status = readFileSync(`/proc/${child.pid}/status`, 'utf8');
        const field = name => Number(new RegExp('^' + name + ':\\s+(\\d+)', 'm').exec(status)?.[1]);
        processMemory = { WorkingSet64: 1024 * field('VmRSS'), PeakWorkingSet64: 1024 * field('VmHWM'), Threads: field('Threads') };
      }
      return { ...processMemory, maximumHeapBytes: Number(maximumHeap[1]),
        heapUsedBytes: 1024 * heapGroups.reduce((sum, match) => sum + Number(match[2]), 0),
        jvmCommittedBytes: 1024 * Number(committed[1]),
        jvmNativeCommittedBytes: 1024 * (Number(committed[1]) - Number(heap[1])) };
    }
  };
}

async function stop(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const exited = once(child, 'exit');
  child.kill();
  await exited;
}

function latency(values) {
  const sorted = [...values].sort((a, b) => a - b);
  return { samples: sorted.length, medianMs: sorted[Math.ceil(sorted.length * .5) - 1],
    p95Ms: sorted[Math.ceil(sorted.length * .95) - 1], p99Ms: sorted[Math.ceil(sorted.length * .99) - 1] };
}

async function main() {
  if (!reportFile || !pgServer || !pgClients || !openssl) {
    throw new Error('Usage: node scripts/verify-release-storage.cjs <private-report.json> <PG server bin> <PG client bin> <OpenSSL>');
  }
  const parent = realpathSync(tmpdir());
  const folder = mkdtempSync(join(parent, 'td-release-db-'));
  const cluster = join(folder, 'cluster');
  const ca = join(folder, 'ca.pem');
  const dump = join(folder, 'monitoring.dump');
  const ownerPassword = credential();
  const appPassword = credential();
  const port = await freePort();
  const pg = (tool, args, options) => run(join(pgServer, tool + executable), args, options);
  const opt = { cwd: folder };
  const ssl = (...args) => run(openssl, args, opt);
  const admin = credential();
  const browsers = Array.from({ length: 8 }, credential);
  const clients = Object.fromEntries(browsers.map((token, index) => [`fixture-${index}`,
    { role: 'BROWSER', 'token-sha256': digest(token) }]));
  const base = {
    threat: {
      security: { clients: { ...clients, owner: { role: 'ADMIN', 'token-sha256': digest(admin) } } },
      monitoring: {
        'synthetic-clients': Object.keys(clients), 'retention-days': 1,
        postgres: {
          'jdbc-url': `jdbc:postgresql://localhost:${port}/monitoring`,
          username: 'monitoring_app', password: appPassword, 'root-certificate': ca, 'pool-size': renderProfile ? 2 : 3
        }
      }
    }
  };
  let pgRunning = false;
  let backend;
  let stage = 'certificate setup';
  function startDatabase() {
    // The Windows server can inherit pg_ctl's handles. Redirect to a file and
    // do not create a pipe that waits for the running database to close it.
    pg('pg_ctl', ['-D', cluster, '-l', join(folder, 'postgres.log'), '-w', 'start'], { stdio: 'ignore' });
    pgRunning = true;
  }
  function stopDatabase() {
    if (pgRunning) {
      pg('pg_ctl', ['-D', cluster, '-m', 'fast', '-w', 'stop']);
      pgRunning = false;
    }
  }
  function sqlTool(name, args, input, database = 'postgres', user = 'fixture_owner', password = ownerPassword) {
    return run(join(pgClients, name + executable), ['-d', database, '-U', user, '--no-password', ...args], {
      input,
      env: { ...cleanEnv, PATH: pgServer + (process.platform === 'win32' ? ';' : ':') + process.env.PATH,
        PGHOST: 'localhost', PGHOSTADDR: '127.0.0.1', PGPORT: String(port), PGSSLMODE: 'verify-full', PGSSLROOTCERT: ca,
        PGPASSWORD: password, PGGSSENCMODE: 'disable' }
    });
  }
  const sql = (statement, database, user, password) =>
    sqlTool('psql', ['-X', '-Aqt', '-v', 'ON_ERROR_STOP=1'], statement + '\n', database, user, password);

  try {
    ssl('req', '-new', '-x509', '-newkey', 'rsa:2048', '-noenc', '-days', '2', '-subj', '/CN=ThreatDetection Lab CA',
      '-addext', 'basicConstraints=critical,CA:TRUE', '-keyout', 'ca.key', '-out', 'ca.pem');
    ssl('req', '-new', '-newkey', 'rsa:2048', '-noenc', '-subj', '/CN=localhost', '-keyout', 'server.key', '-out', 'server.csr');
    writeFileSync(join(folder, 'server.ext'), 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n');
    ssl('x509', '-req', '-in', 'server.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial',
      '-days', '2', '-extfile', 'server.ext', '-out', 'server.pem');
    ssl('req', '-new', '-x509', '-newkey', 'rsa:2048', '-noenc', '-days', '2', '-subj', '/CN=Different Lab CA',
      '-keyout', 'untrusted.key', '-out', 'untrusted.pem');
    const pwFile = join(folder, 'init-password');
    writeFileSync(pwFile, ownerPassword + '\n', { mode: 0o600 });
    pg('initdb', ['-D', cluster, '-U', 'fixture_owner', '--pwfile=' + pwFile, '--auth=scram-sha-256',
      '--data-checksums', '--encoding=UTF8', '--locale=C']);
    rmSync(pwFile);
    // Use absolute filenames with a controlled temporary directory and accept TLS only.
    const confPath = name => join(folder, name).replaceAll('\\', '/').replaceAll("'", "''");
    writeFileSync(join(cluster, 'postgresql.auto.conf'), `listen_addresses = '127.0.0.1'
port = ${port}
ssl = on
ssl_cert_file = '${confPath('server.pem')}'
ssl_key_file = '${confPath('server.key')}'
password_encryption = 'scram-sha-256'
shared_buffers = '32MB'
max_connections = 25
`);
    writeFileSync(join(cluster, 'pg_hba.conf'), 'hostssl all all 127.0.0.1/32 scram-sha-256\n');
    startDatabase();
    stage = 'initial TLS connection';
    sql(`CREATE ROLE monitoring_app LOGIN PASSWORD '${appPassword}';
CREATE DATABASE monitoring OWNER monitoring_app;
REVOKE CONNECT ON DATABASE monitoring FROM PUBLIC;
GRANT CONNECT ON DATABASE postgres TO monitoring_app;`);
    sql('GRANT CREATE ON SCHEMA public TO monitoring_app;');
    assert.equal(sql('SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid();',
      'monitoring', 'monitoring_app', appPassword), 't');

    const failedStartup = [];
    stage = 'negative certificate and password checks';
    for (const [name, values, pattern] of [
      ['wrong-hostname', { 'jdbc-url': `jdbc:postgresql://127.0.0.1:${port}/monitoring` }, /hostname|could not be verified/i],
      ['wrong-ca', { 'root-certificate': join(folder, 'untrusted.pem') }, /PKIX|certification path/i],
      ['wrong-password', { password: credential() }, /password authentication failed/i]
    ]) {
      const config = structuredClone(base);
      Object.assign(config.threat.monitoring.postgres, values);
      const trial = startBackend(config);
      try {
        const { child } = trial;
        if (child.exitCode === null) await Promise.race([once(child, 'exit'), wait(45000, undefined, { ref: false })]);
        assert(child.exitCode > 0, name + ' accepted or did not terminate');
        assert(pattern.test(trial.logs()), name + ' failed for an unexpected reason');
        failedStartup.push(name);
      } finally {
        await stop(trial.child);
      }
    }
    console.log('PostgreSQL startup refused a mismatched hostname, untrusted CA and invalid password.');

    stage = 'primary database setup and paced load';
    backend = startBackend(base);
    const address = await backend.ready();
    const coldStartMs = backend.startupMs;
    const idleMemory = renderProfile ? backend.memory() : null;
    assert.equal(sql("SELECT count(*) FROM flyway_schema_history WHERE success AND version = '1';", 'monitoring'), '1');
    async function request(route, token, payload) {
      const start = performance.now();
      const response = await fetch(address + '/api/threat/monitoring/' + route, {
        method: payload ? 'POST' : 'GET',
        headers: { Authorization: 'Bearer ' + token, Connection: 'close',
          ...(payload ? { 'Content-Type': 'application/json' } : {}) },
        body: payload ? JSON.stringify(payload) : undefined,
        signal: AbortSignal.timeout(10000)
      });
      return { response, ms: performance.now() - start };
    }
    const event = () => ({ id: randomUUID(), signal: 'PHISHING', action: 'BLOCKED', detectedAt: new Date().toISOString() });
    const heartbeat = token => request('heartbeat', token, { protection: 'REPUTATION_AVAILABLE' });
    const dashboard = (scope = 'SYNTHETIC') => request('dashboard?scope=' + scope, admin);
    for (const token of browsers) assert.equal((await heartbeat(token)).response.status, 204);
    const writes = [], reads = [];
    let example;
    const start = performance.now();
    for (let round = 0; round < 100; round++) {
      const group = browsers.slice((round % 2) * 4, (round % 2) * 4 + 4);
      const events = group.map(event);
      if (!example) example = events[0];
      const [sent, fetched] = await Promise.all([
        Promise.all(group.map((token, index) => request('events', token, events[index]))),
        Promise.all(group.map(() => dashboard()))
      ]);
      for (const { response, ms } of sent) {
        assert.equal(response.status, 204);
        writes.push(ms);
      }
      for (const { response, ms } of fetched) {
        assert.equal(response.status, 200);
        await response.json();
        reads.push(ms);
      }
      const remaining = start + (round + 1) * 900 - performance.now();
      if (remaining > 0) await wait(remaining);
    }
    const loadWallMs = performance.now() - start;
    const loadedMemory = renderProfile ? backend.memory() : null;
    const gcPauses = [...backend.logs().matchAll(/Pause (Young|Full).* ([\d.]+)ms/g)];
    const synthetic = await (await dashboard()).response.json();
    assert.equal(synthetic.total, writes.length);
    assert.equal((await (await dashboard('REAL')).response.json()).total, 0);
    const sessions = Number(sql("SELECT count(*) FROM pg_stat_activity a JOIN pg_stat_ssl s USING (pid) WHERE datname = 'monitoring' AND a.usename = 'monitoring_app' AND s.ssl;"));
    assert(sessions >= 1 && sessions <= base.threat.monitoring.postgres['pool-size']);
    console.log(`TLS load passed ${writes.length} writes and ${reads.length} dashboard reads.`);
    const load = { concurrency: 8, wallMs: loadWallMs, writes: latency(writes), dashboardReads: latency(reads), errors: 0 };
    console.log(JSON.stringify(load));

    stage = 'logical backup and restore';
    sqlTool('pg_dump', ['-Fc', '-f', dump], undefined, 'monitoring', 'monitoring_app', appPassword);
    sql('CREATE DATABASE restored OWNER monitoring_app;');
    sqlTool('pg_restore', ['--exit-on-error', '--no-owner', dump], undefined, 'restored', 'monitoring_app', appPassword);
    assert.equal(sql('SELECT count(*) FROM monitoring_event;', 'restored'), String(writes.length));
    assert.equal(sql("SELECT count(*) FROM flyway_schema_history WHERE success AND version = '1';", 'restored'), '1');
    sql(`UPDATE monitoring_event SET received_at = current_timestamp - interval '2 days' WHERE id = (SELECT min(id) FROM monitoring_event);`, 'restored');
    console.log('Logical backup restored into a fresh database with its Flyway history.');

    stage = 'outage response';
    stopDatabase();
    const outage = await dashboard();
    assert.equal(outage.response.status, 503);
    assert.equal(outage.response.headers.get('x-threat-monitoring-status'), 'storage-unavailable');
    console.log('A storage outage returned HTTP 503 with the unavailable status.');
    stage = 'running backend recovery';
    const recoveryStart = performance.now();
    startDatabase();
    let recovered = false;
    for (let attempt = 0; attempt < 20; attempt++) {
      const result = await dashboard().catch(error => {
        if (!(error instanceof TypeError)) throw error;
        return null;
      });
      if (result?.response.ok) {
        const { response } = result;
        assert.equal((await response.json()).total, writes.length);
        recovered = true;
        break;
      }
      await wait(500);
    }
    assert(recovered, 'Running app did not recover from PostgreSQL restart');
    const recoveryMs = performance.now() - recoveryStart;
    assert.equal((await request('events', browsers[0], example)).response.status, 204);
    assert.equal((await (await dashboard()).response.json()).total, writes.length);
    console.log('The running backend recovered and deduplicated the replay.');

    stage = 'application reopening restored database';
    await stop(backend.child);
    const restored = structuredClone(base);
    restored.threat.monitoring.postgres['jdbc-url'] = `jdbc:postgresql://localhost:${port}/restored`;
    backend = startBackend(restored);
    const restoredAddress = await backend.ready();
    const restoredDashboard = await fetch(restoredAddress + '/api/threat/monitoring/dashboard?scope=SYNTHETIC',
      { headers: { Authorization: 'Bearer ' + admin }, signal: AbortSignal.timeout(10000) });
    assert.equal((await restoredDashboard.json()).total, writes.length - 1);
    assert.equal(sql('SELECT count(*) FROM monitoring_event;', 'restored'), String(writes.length - 1));
    console.log('The backend reopened the restored database and removed the expired record.');

    const result = { postgres: pg('postgres', ['--version']), failedStartup, observedTlsPoolConnections: sessions,
      load,
      migration: 'version 1', backupRestore: 'pg_dump custom archive and pg_restore into a new database',
      outageStatus: outage.response.status, outageResponseMs: outage.ms, recoveryMs,
      replayTotal: writes.length, restoredTotalAfterExpiry: writes.length - 1, realScopeTotal: 0 };
    if (renderProfile) result.renderProfile = { coldStartMs, idleMemory, loadedMemory,
      youngGcPauses: gcPauses.filter(pause => pause[1] === 'Young').length,
      fullGcPauses: gcPauses.filter(pause => pause[1] === 'Full').length,
      longestGcPauseMs: Math.max(0, ...gcPauses.map(pause => Number(pause[2]))) };
    if (process.env.THREAT_RELEASE_RUN_STORAGE_MAVEN === '1') {
      stage = 'Maven storage tests';
      await stop(backend.child);
      const mvn = process.platform === 'win32' ? 'cmd.exe' : './mvnw';
      const args = process.platform === 'win32' ? ['/d', '/c', 'mvnw.cmd', '-q', '-Dtest=MonitoringStorageTests', 'test']
        : ['-q', '-Dtest=MonitoringStorageTests', 'test'];
      run(mvn, args, { cwd: join(repo, 'backend'), env: { ...cleanEnv,
        THREAT_TEST_POSTGRES_URL: `jdbc:postgresql://localhost:${port}/postgres`,
        THREAT_TEST_POSTGRES_USER: 'monitoring_app', THREAT_TEST_POSTGRES_PASSWORD: appPassword,
        THREAT_TEST_POSTGRES_CA: ca } });
      result.mavenStorageSuite = 'passed';
    }
    writeFileSync(reportFile, JSON.stringify(result, null, 2) + '\n', { flag: 'wx' });
    console.log(JSON.stringify(result));
  } catch (error) {
    throw new Error(`PostgreSQL verification failed during ${stage}`, { cause: error });
  } finally {
    await stop(backend?.child);
    stopDatabase();
    const target = realpathSync(folder);
    if (dirname(target) !== parent || !basename(target).startsWith('td-release-db-')) throw new Error('Unexpected disposable path');
    rmSync(target, { recursive: true, maxRetries: 8, retryDelay: 100 });
  }
}

main().catch(error => {
  console.error(error.stack);
  if (error.cause) console.error(error.cause.stack, error.cause.cause?.code ?? '');
  process.exitCode = 1;
});

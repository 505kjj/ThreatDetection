const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { randomUUID } = require('node:crypto');
const { readFileSync, renameSync, rmSync, writeFileSync } = require('node:fs');
const { createServer } = require('node:net');
const path = require('node:path');
const script = path.resolve(__dirname, '../../scripts/local.ps1');
const powershell = ['-NoLogo', '-NoProfile', '-NonInteractive'];
function run(host, command, args = [], env = {}) {
  const childEnv = { ...process.env, ...env };
  // Let each PowerShell host supply its own module directories.
  for (const name of Object.keys(childEnv)) {
    if (name.toLowerCase() === 'psmodulepath') delete childEnv[name];
  }
  return new Promise((resolve, reject) => {
    const child = spawn(host, [...powershell, ...command, ...args], {
      env: childEnv, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe']
    });
    let stdout = '';
    let stderr = '';
    let drain;
    const timeout = setTimeout(() => {
      child.kill();
      reject(new Error('Timed out waiting for ' + host));
    }, 110000);
    child.stdout.setEncoding('utf8').on('data', data => { stdout += data; });
    child.stderr.setEncoding('utf8').on('data', data => { stderr += data; });
    child.once('error', error => {
      clearTimeout(timeout);
      reject(error);
    });
    function finish(code) {
      clearTimeout(timeout);
      clearTimeout(drain);
      child.stdout.destroy();
      child.stderr.destroy();
      if (code === 0) resolve({ stdout });
      else reject(new Error(stderr.trim() || host + ' exited unsuccessfully'));
    }
    // A background JVM or Windows compatibility host can outlive the script's pipe handles.
    child.once('exit', code => { drain = setTimeout(() => finish(code), 250); });
    child.once('close', finish);
  });
}

async function freePort() {
  const probe = createServer();
  await new Promise((resolve, reject) => {
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', resolve);
  });
  const { port } = probe.address();
  await new Promise(resolve => probe.close(resolve));
  return port;
}

async function createRuntime(extensionId, snapshotPath) {
  const profile = 'smoke-' + randomUUID();
  const directory = (await run('powershell.exe', ['-Command',
    "[Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)"])).stdout.trim();
  const profilesRoot = path.resolve(directory, 'ThreatDetection-local');
  const state = path.join(profilesRoot, profile);
  const port = await freePort();
  const invoke = (action, args = [], host = 'powershell.exe') =>
    run(host, ['-File', script, '-Action', action, '-Profile', profile], args);

  async function dispose() {
    if (!profile.startsWith('smoke-') || path.dirname(state) !== profilesRoot) throw new Error('Invalid smoke profile directory');
    await invoke('Stop');
    rmSync(state, { recursive: true, force: true, maxRetries: 8, retryDelay: 50 });
  }

  try {
    await assert.rejects(invoke('Setup', ['-ExtensionId', 'invalid']), /Enter the 32-character extension ID/);
    const configured = await invoke('Setup', ['-ExtensionId', extensionId, '-Port', String(port),
      '-Synthetic', '-SnapshotPath', snapshotPath]);
    assert.match(configured.stdout, /is ready/);
    assert.match((await invoke('Status', [], 'pwsh.exe')).stdout, /Backend stopped/);
  } catch (error) {
    await dispose().catch(() => {});
    throw error;
  }

  async function tokens() {
    // Pipe disposable DPAPI credentials directly to the test. Do not use the Windows clipboard or print this output.
    const transfer = [
      "$ErrorActionPreference = 'Stop'",
      "$file = Join-Path $env:THREAT_SMOKE_PROFILE 'configuration.json'",
      "$config = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json",
      "foreach ($entry in @($config.browser, $config.admin)) {",
      "  $secret = ConvertTo-SecureString -String $entry.encrypted",
      "  $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)",
      "  try { Write-Output ([Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)) }",
      "  finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr); $secret.Dispose() }",
      "}"
    ].join('\n');
    let output;
    try {
      output = (await run('powershell.exe', ['-Command', transfer], [], { THREAT_SMOKE_PROFILE: state })).stdout;
    } catch {
      throw new Error('Could not read the disposable DPAPI test credentials');
    }
    const values = output.trim().split(/\r?\n/);
    if (values.length !== 2 || values.some(value => !/^[A-Za-z0-9_-]{43}$/.test(value)) || values[0] === values[1]) {
      throw new Error('Expected distinct disposable credentials');
    }
    const config = readFileSync(path.join(state, 'configuration.json'), 'utf8');
    if (values.some(value => config.includes(value))) throw new Error('Private file contained a plaintext test credential');
    return values;
  }

  async function start(host) {
    const result = await invoke('Start', [], host);
    assert.match(result.stdout, /Reporting scope is synthetic/);
    assert.match((await invoke('Status', [], host)).stdout, /Backend running/);
    return {
      port,
      stop: () => invoke('Stop', [], host),
      logs: () => readFileSync(path.join(state, 'backend.log'), 'utf8')
    };
  }

  async function checkStartupFailure() {
    const database = path.join(state, 'monitoring.mv.db');
    const backup = database + '.smoke-backup';
    renameSync(database, backup);
    try {
      writeFileSync(database, 'disposable invalid H2 test data');
      await assert.rejects(invoke('Start', [], 'pwsh.exe'), /Backend startup failed/);
      assert.match((await invoke('Status', [], 'pwsh.exe')).stdout, /Backend stopped/);
    } finally {
      rmSync(database, { force: true });
      renameSync(backup, database);
    }
  }

  return { start, tokens, dispose, checkStartupFailure,
    rotateAdmin: () => invoke('Rotate', ['-Role', 'Admin'], 'pwsh.exe') };
}

module.exports = { createRuntime };

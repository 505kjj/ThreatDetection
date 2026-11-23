// Real Chromium baseline and local synthetic DOM probe. Product files stay unchanged.
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { createServer } = require('node:http');
const { mkdtemp, writeFile, rm } = require('node:fs/promises');
const { tmpdir } = require('node:os');
const { join, resolve, relative } = require('node:path');
const { performance } = require('node:perf_hooks');
const { chromium } = require('playwright');

const extension = resolve(__dirname, '../../extension');
const fixtures = ['https://merchant.example.org/', 'https://sbi.bank.in.example.org/account',
  'https://merchant-portal.example.net/p/customer-012', 'https://razorpay.com/',
  'https://example.com/checkout', 'https://café.example.org/signin'];

function processTree(profile) {
  if (process.platform !== 'win32') return null;
  const script = `
    $chrome = @(Get-CimInstance Win32_Process -Filter "Name='chrome.exe' OR Name='chromium.exe'")
    $root = $chrome | Where-Object { $_.CommandLine -like ('*' + $env:THREAT_BENCHMARK_PROFILE + '*') -and $_.CommandLine -notlike '*--type=*' } | Select-Object -First 1
    if (-not $root) { Write-Output 'null'; exit }
    $ids = @($root.ProcessId)
    do {
      $previous = $ids.Count
      $ids += @($chrome | Where-Object { $_.ParentProcessId -in $ids -and $_.ProcessId -notin $ids } | ForEach-Object ProcessId)
    } while ($ids.Count -gt $previous)
    $procs = @(Get-Process -Id $ids -ErrorAction SilentlyContinue)
    [pscustomobject]@{ processCount=$procs.Count; privateBytes=($procs | Measure-Object PrivateMemorySize64 -Sum).Sum; cumulativeCpuSeconds=($procs | Measure-Object CPU -Sum).Sum } | ConvertTo-Json -Compress
  `;
  return JSON.parse(execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], {
    encoding: 'utf8', env: { ...process.env, THREAT_BENCHMARK_PROFILE: profile }, windowsHide: true, timeout: 20000
  }));
}

async function launch(useExtension, origin, probe) {
  const profile = await mkdtemp(join(tmpdir(), 'threat-perf-'));
  let context;
  try {
    const start = performance.now();
    context = await chromium.launchPersistentContext(profile, {
      channel: 'chromium',
      args: useExtension ? ['--disable-extensions-except=' + extension, '--load-extension=' + extension]
        : ['--disable-extensions'],
    });
    const ready = performance.now() - start;
    const worker = useExtension ? context.serviceWorkers()[0] ??
      await context.waitForEvent('serviceworker', { timeout: 10000 }) : null;
    const workerReady = worker ? performance.now() - start : null;
    const page = context.pages()[0] ?? await context.newPage();
    await page.goto(origin);
    await new Promise(done => setTimeout(done, 250));
    const beforeProbe = processTree(profile);
    let advisory = null;
    if (worker && probe) {
      const site = await context.newPage();
      await site.goto(new URL(worker.url()).origin.replace(/^null$/, 'chrome-extension://' + new URL(worker.url()).hostname) + '/popup.html');
      advisory = await site.evaluate(async hosts => {
        const started = performance.now();
        const { destinationFor } = await import(chrome.runtime.getURL('reputation.mjs'));
        const { detectImpersonation } = await import(chrome.runtime.getURL('impersonation.mjs'));
        const moduleMs = performance.now() - started;
        const cached = new Map();
        const raw = input => detectImpersonation(destinationFor(input).host);
        const timings = fn => {
          const t = performance.now();
          for (let i = 0; i < 4000; i++) fn(hosts[i % hosts.length]);
          return (performance.now() - t) * 1000 / 4000;
        };
        const uncachedUs = timings(raw);
        const memoizedUs = timings(input => {
          const { host } = destinationFor(input);
          if (!cached.has(host)) cached.set(host, detectImpersonation(host));
          return cached.get(host);
        });
        return { moduleMs, uncachedUs, memoizedUs, repeatedFixtureInputs: hosts.length };
      }, fixtures);
    }
    const dom = probe ? await page.evaluate(() => {
      const t = performance.now();
      let evidence;
      for (let i = 0; i < 2000; i++) {
        const forms = Array.from(document.querySelectorAll('form')).slice(0, 64);
        evidence = {
          passwordFieldPresent: !!document.querySelector('input[type=password]'),
          crossOriginForm: forms.some(form => new URL(form.action, location.href).origin !== location.origin),
        };
      }
      return { evidence, usPerProbe: (performance.now() - t) / 2 };
    }) : null;
    return { launchMs: ready, launchToWorkerMs: workerReady, processTreeAfterLocalNavigation: beforeProbe,
      advisoryExtensionPageMicrobenchmark: advisory, syntheticDomProbe: dom };
  } finally {
    if (context) await context.close();
    assert.match(relative(resolve(tmpdir()), resolve(profile)), /^threat-perf-[a-zA-Z0-9]+$/);
    await rm(profile, { recursive: true, force: true, maxRetries: 4, retryDelay: 250 });
  }
}

async function main() {
  const file = resolve(process.argv[2]);
  assert.ok(relative(resolve(__dirname, '../..'), file).startsWith('..'), 'Write measurements outside Git');
  const fixture = createServer((request, response) => {
    response.setHeader('Content-Type', 'text/html');
    response.end('<title>Local fixture</title><form action="https://merchant.example.org/"><input type="password"></form>');
  });
  await new Promise(done => fixture.listen(0, '127.0.0.1', done));
  const address = 'http://127.0.0.1:' + fixture.address().port + '/';
  const runs = [];
  try {
    for (let run = 0; run < 3; run++) {
      for (const installed of [false, true]) {
        runs.push({ installed, run: run + 1, ...await launch(installed, address, run === 2) });
      }
    }
    const { extractUrl } = await import('../../evaluation/features.mjs');
    const start = performance.now();
    for (let i = 0; i < 12000; i++) extractUrl(fixtures[i % fixtures.length], 'real');
    const nodeFeatureExtractionUs = (performance.now() - start) / 12;
    await writeFile(file, JSON.stringify({ runs, nodeFeatureExtractionUs, playwrightVersion: require('playwright/package.json').version }, null, 2) + '\n',
      { flag: 'wx' });
  } finally {
    fixture.closeAllConnections();
    await new Promise(done => fixture.close(done));
  }
}

main().catch(error => { console.error(error.message); process.exitCode = 1; });

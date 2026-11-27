import { cp, mkdir, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { pages } from './pages.mjs';

const here = fileURLToPath(new URL('.', import.meta.url));
const repo = join(here, '..');
const output = resolve(process.argv[2] ?? join(here, 'dist'));
const checkout = 'https://github.com/505kjj/ThreatDetection';
const navigation = [
  ['features', 'Features'], ['how-it-works', 'How it works'], ['research', 'Research'],
  ['extension', 'Extension'], ['demo', 'Security demo'], ['docs', 'Documentation']
];

function monitorHref(value) {
  const url = new URL(value);
  const local = url.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(url.hostname);
  if (!(local || url.protocol === 'https:') || !/^[a-z\d.-]+$/.test(url.hostname)
      || url.href !== url.origin + '/monitor') {
    throw new Error('THREAT_PUBLIC_MONITOR_URL must be an HTTPS /monitor URL or a loopback HTTP /monitor URL');
  }
  return url.href;
}

const monitor = monitorHref(process.env.THREAT_PUBLIC_MONITOR_URL ?? 'http://127.0.0.1:8081/monitor');
const link = ([slug, label], current) => `<a href="/${slug}/"${slug === current ? ' aria-current="page"' : ''}>${label}</a>`;
const mark = '<img src="/assets/mark.svg" width="32" height="32" alt="">';

function render(slug, { title, description, body }) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="${description}">
  <meta name="theme-color" content="#0a090d">
  <title>${title} | ThreatDetection</title>
  <link rel="icon" href="/assets/mark.svg" type="image/svg+xml">
  <link rel="preload" href="/assets/inter-latin.woff2" as="font" type="font/woff2" crossorigin>
  <link rel="stylesheet" href="/assets/site.css">
  <script src="/assets/site.js" defer></script>
</head>
<body>
  <a class="skip" href="#main">Skip to content</a>
  <header class="mast">
    <div class="shell header-inner">
      <a class="brand" href="/"${slug ? '' : ' aria-current="page"'}>${mark}<span>ThreatDetection</span></a>
      <nav class="primary" aria-label="Main navigation">${navigation.map(item => link(item, slug)).join('')}</nav>
      <a class="button button-small button-outline admin-link" href="/administrator/">Admin login</a>
      <details class="mobile-nav">
        <summary>Menu</summary>
        <nav aria-label="Mobile navigation">${[...navigation, ['administrator', 'Admin login']].map(item => link(item, slug)).join('')}</nav>
      </details>
    </div>
  </header>
  <main id="main" class="shell" tabindex="-1">${body({ monitor })}</main>
  <footer class="footer">
    <div class="shell footer-inner">
      <a class="brand" href="/">${mark}<span>ThreatDetection</span></a>
      <nav aria-label="Footer navigation">${[['docs', 'Documentation'], ['privacy', 'Privacy policy'], ['faq', 'FAQ'], ['administrator', 'Admin login']].map(item => link(item, slug)).join('')}
        <a href="${checkout}">GitHub</a>
      </nav>
    </div>
  </footer>
</body>
</html>
`;
}

await mkdir(join(output, 'assets'), { recursive: true });
await cp(join(here, 'assets'), join(output, 'assets'), { recursive: true });
for (const [source, name] of [
  ['extension/fonts/inter-latin.woff2', 'inter-latin.woff2'],
  ['extension/fonts/Inter-OFL.txt', 'Inter-OFL.txt'],
  ['extension/icons/mark.svg', 'mark.svg']
]) {
  await cp(join(repo, source), join(output, 'assets', name));
}
for (const [slug, page] of Object.entries(pages)) {
  const directory = join(output, slug);
  await mkdir(directory, { recursive: true });
  await writeFile(join(directory, 'index.html'), render(slug, page));
}
await writeFile(join(output, '404.html'), render('missing', {
  title: 'Page unavailable', description: 'Return to ThreatDetection.',
  body: () => '<section class="page-intro"><h1>Page unavailable</h1><p>The address may have moved.</p><a class="button button-solid" href="/">Back to home</a></section>'
}));
await cp(join(here, '_headers'), join(output, '_headers'));
console.log(`Built ${Object.keys(pages).length} pages in ${output}`);

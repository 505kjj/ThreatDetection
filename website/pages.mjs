const repo = 'https://github.com/505kjj/ThreatDetection';
const source = (file, text) => `<a href="${repo}/blob/feature/phase-7c-security-scalability/${file}">${text}</a>`;
const button = (url, text, kind = 'solid') => `<a class="button button-${kind}" href="${url}">${text}</a>`;
const intro = (title, description) => `<section class="page-intro"><h1>${title}</h1><p>${description}</p></section>`;
const page = (title, description, content) => ({ title, description, body: () => intro(title, description) + content });
const card = (label, title, text) => `<article class="card" data-reveal><span class="card-label">${label}</span><h3>${title}</h3><p>${text}</p></article>`;
const logo = '<img src="/assets/mark.svg" width="27" height="27" alt="">';

const protection = [
  ['REPUTATION', 'Block confirmed threats', 'Chrome applies local blocking rules built from the configured reputation snapshot. Confirmed malware has no bypass.'],
  ['FINANCIAL PROTECTION', 'Review suspicious sign-ins', 'Local domain checks and credential-form metadata can show a caution when the evidence warrants a closer look.'],
  ['MONITORING', 'Report by choice', 'Opted-in browsers send bounded event codes to your backend. The authenticated console separates live and synthetic reports.']
];

const architecture = `<div class="diagram" data-choice>
  <div class="diagram-nodes" role="group" aria-label="Protection layers">
    <button type="button" data-target="browser" aria-controls="browser" aria-pressed="true">01 <span>Browser</span></button>
    <button type="button" data-target="backend" aria-controls="backend" aria-pressed="false">02 <span>Backend</span></button>
    <button type="button" data-target="console" aria-controls="console" aria-pressed="false">03 <span>Console</span></button>
  </div>
  <div class="diagram-output" aria-live="polite">
    <div id="browser" data-panel><h3>Check locally at navigation</h3><p>Chrome applies current reputation rules. Financial checks use domain and form structure to surface a separate advisory.</p></div>
    <div id="backend" data-panel hidden><h3>Refresh the snapshot securely</h3><p>The configured backend serves the active snapshot to a browser client. Optional monitoring uses a separate consent setting.</p></div>
    <div id="console" data-panel hidden><h3>Review with administrator access</h3><p>The console reads authorized aggregates and evidence codes. Browser credentials cannot open those data endpoints.</p></div>
  </div>
</div>`;

const metrics = `<div class="metrics">
  <a href="/research/" class="metric"><strong>35</strong><span>Phase 6E synthetic browser trials</span></a>
  <a href="/research/" class="metric"><strong>160</strong><span>Phase 6C URL parity fixtures</span></a>
  <a href="/research/" class="metric"><strong>54</strong><span>Frozen receipt checks passed at Phase 7</span></a>
</div>`;

function preview(filename, title, caption) {
  const [width, height] = { console: [1440, 835], warning: [1280, 720], extension: [360, 631] }[filename];
  return `<figure class="preview${filename === 'extension' ? ' preview-popup' : ''}">
    <div class="preview-bar">${logo}<span>${title}</span><span class="preview-tag">Synthetic data</span></div>
    <img class="product-shot" src="/assets/${filename}.webp" alt="${caption}" width="${width}" height="${height}"${filename === 'console' ? '' : ' loading="lazy"'}>
  </figure>`;
}

const demos = [
  ['reputation', 'Confirmed block', 'Blocked', 'A fictional navigation matches an indicator in a current reputation snapshot.',
    'The known-threat warning interrupts navigation. Confirmed malware has no bypass. Eligible phishing bypass is scoped to one navigation.',
    'Confirmed reputation match'],
  ['financial', 'Financial advisory', 'Advisory', 'A fictional domain resembles a protected financial brand.',
    'The browser presents a caution and explains the domain evidence. It does not classify the domain as a confirmed threat.',
    'Financial domain resemblance'],
  ['form', 'Credential-form evidence', 'Advisory', 'On a fictional eligible financial lookalike, a password form declares a different submission origin.',
    'The browser can explain the structural evidence. This scenario contains no live form or credential fields.',
    'Unrelated declared form destination'],
  ['report', 'Dashboard report', 'Opt-in report', 'A configured synthetic browser has explicitly enabled monitoring.',
    'An authorized administrator can inspect a classified detection in the synthetic dashboard scope. Opt-out leaves browser protection in place.',
    'Evidence code, action and time']
];

function demoPanel([id, label, outcome, evidence, explanation, reason], index) {
  return `<article id="case-${id}" class="case-panel" data-panel${index ? ' hidden' : ''}>
    <div class="result-heading">${logo}<span class="status status-${id}">${outcome}</span></div>
    <h2>${label}</h2><p>${evidence}</p>
    <dl class="result-detail"><dt>Evidence</dt><dd>${reason}</dd><dt>What happens</dt><dd>${explanation}</dd></dl>
  </article>`;
}

export const pages = {
  '': {
    title: 'Browser security with evidence', description: 'ThreatDetection blocks known threats and explains suspicious financial sign-ins.',
    body: () => `<section class="hero">
      <div class="hero-copy">
        <span class="eyebrow"><span></span> Browser security with evidence</span>
        <h1><span>Detect. Defend.</span><span class="violet">Protect.</span></h1>
        <p>Block known threats. Get clear warnings about suspicious financial sign-ins. Keep reporting in your control.</p>
        <div class="actions">${button('/extension/', 'Install locally')}${button('/demo/', 'Try the security demo', 'outline')}</div>
      </div>
      <div class="hero-visual">${preview('console', 'Administrator console', 'ThreatDetection administrator console with a synthetic warning and block summary')}</div>
    </section>
    <section class="band">
      <div class="section-heading"><h2>What runs in your browser</h2>${button('/features/', 'Explore features', 'outline')}</div>
      <div class="cards three">${protection.map(row => card(...row)).join('')}</div>
    </section>
    <section class="band split">
      <div><span class="eyebrow">EXTENSION</span><h2>See the reason before you continue.</h2><p>ThreatDetection shows whether it matched a known threat or found a reason to be cautious. The explanation stays visible when it matters.</p>
      ${button('/extension/', 'Extension setup', 'outline')}</div>
      ${preview('warning', 'Chrome extension', 'ThreatDetection known-threat warning on a synthetic page')}
    </section>
    <section class="band">
      <div class="section-heading"><h2>From navigation to explanation</h2>${button('/how-it-works/', 'How it works', 'outline')}</div>
      ${architecture}
    </section>
    <section class="band evidence"><h2>Research in the open</h2><p>Controlled checks of experimental behavior and artifact integrity. Independent validation is pending.</p>${metrics}</section>`
  },
  features: page('Browser protection', 'Protection and reporting use separate browser and administrator controls.',
    `<div class="cards three">${protection.map(row => card(...row)).join('')}</div>
    <section class="band split"><div><h2>Evidence with a clear outcome</h2><p>Reputation matches interrupt navigation when supported by current evidence. Financial and configured activity signals can produce advisories that explain why a page warrants review.</p>
    <p>If the backend is unavailable, fresh cached reputation remains usable until expiry. A missing or expired snapshot makes reputation unavailable.</p></div>
    <div class="card"><h3>Review from the console</h3><p>Inspect the reason, action and reporting window. The console distinguishes a confirmed block, an advisory and an eligible bypass.</p>${button('/demo/', 'See the outcomes', 'outline')}</div></section>`),
  'how-it-works': page('How it works', 'Follow the evidence through the extension, configured backend and administrator console.',
    `${architecture}<section class="band"><h2>What happens when evidence is missing?</h2><p>The extension distinguishes unavailable reputation from a completed check with no match. Local financial rules can still run during a backend outage.</p>
    <h2>What gets sent?</h2><p>A configured connection fetches reputation. The extension sends bounded activity data when that feature is enabled and classification codes when reporting is enabled.</p>${button('/privacy/', 'Read the privacy policy', 'outline')}</section>`),
  research: page('Research and technology', 'Experimental models are isolated from browser decisions. Independent operational validation remains pending.',
    `${metrics}<section class="band"><h2>Research evidence</h2><div class="cards two">
    ${card('URL MODELS · PHASE 6C', 'Browser score agreement', 'Frozen URL preprocessing and scoring were compared with Python across 160 synthetic URL parity fixtures. This informs compatibility and does not establish detection accuracy.')}
    ${card('DOM AND FUSION · PHASE 6C', 'Local structure and fusion', 'Eight inert DOM and fusion scenarios agreed with frozen references. Missing DOM evidence is treated as unavailable.')}
    ${card('VISUAL · PHASE 6D', 'Logo recognition prototype', 'Three fictional logo fixtures cleared the preprocessing cosine-similarity gate. The result is scoped to those fixtures. Independent visual data remains unavailable.')}
    ${card('BROWSER SECURITY · PHASE 6E', 'Bounded signal pilot', 'Seven synthetic scenarios repeated five times checked expected categories. Downloads and tracker identification remain deferred.')}
    </div></section><section class="band"><h2>Methods and limitations</h2><ul class="link-list">
    <li>${source('docs/experiments/phase6c/README.md', 'Browser inference and parity report')}</li>
    <li>${source('docs/experiments/phase6d/README.md', 'Visual recognition and parity report')}</li>
    <li>${source('docs/experiments/phase6e/README.md', 'Extended browser security report')}</li>
    <li>${source('docs/experiments/phase7a/README.md', 'Independent evaluation status')}</li></ul></section>`),
  extension: page('Chrome extension', 'Install the controlled local build for Chrome 120 or later. The extension is awaiting Chrome Web Store publication.',
    `<section class="split"><div class="card"><h2>Install locally</h2><ol class="steps">
    <li>Get the project source from GitHub and use the version your administrator approves.</li>
    <li>Open <code>chrome://extensions</code>, enable Developer mode and select <strong>Load unpacked</strong>.</li>
    <li>Select the project’s <code>extension</code> folder, or the extracted versioned release package supplied by your operator.</li>
    <li>Open ThreatDetection settings. Set the approved backend origin and browser credential, then use <strong>Test connection</strong>.</li>
    </ol><div class="actions">${button(repo, 'Get source')}${button('/docs/', 'Setup documentation', 'outline')}</div></div>
    ${preview('extension', 'Extension popup', 'ThreatDetection browser extension popup during a synthetic protection check')}</section>
    <section class="band"><h2>Permissions at installation</h2><p>Chrome grants the extension access to eligible HTTP and HTTPS pages for on-device navigation and form evidence. Connections to a remote backend require a separate HTTPS host grant. Review the privacy policy before installing.</p>${button('/privacy/', 'Privacy policy', 'outline')}</section>`),
  demo: page('Interactive security demo', 'Synthetic scenarios only. These examples use fictional evidence, accept no input and make no backend requests.',
    `<section class="demo" data-choice>
    <div class="demo-list" role="group" aria-label="Synthetic scenarios">${demos.map(([id, label], index) => `<button type="button" data-target="case-${id}" aria-controls="case-${id}" aria-pressed="${!index}">${label}</button>`).join('')}</div>
    <div class="demo-output" aria-live="polite">${demos.map(demoPanel).join('')}</div></section>`),
  privacy: page('Privacy policy', 'Data practices for the public website, Chrome extension and optional operator-hosted monitoring.',
    `<div class="prose">
    <h2>Public website</h2><p>The site uses no analytics, cookies, sign-in form or embedded tracking. Demo interactions stay in the open page. A hosting provider may keep ordinary request logs such as IP address and requested path. External links and the operator’s console use their own services.</p>
    <h2>Browser processing</h2><p>The extension inspects eligible HTTP and HTTPS navigations for threat reputation and financial impersonation. It processes host and canonical path for local reputation checks and uses bounded credential-form structure for local advisories. It does not read typed values, passwords, one-time codes, raw cookie values, screenshots or file contents. Local settings store the configured connection details, consent settings and reputation state.</p>
    <h2>Backend connection and consent</h2><p>When configured, the extension contacts your operator’s backend for reputation snapshots using a browser-scoped bearer token. With activity analysis enabled, it can send host information for the session and bounded event types and counters. With monitoring enabled separately, it sends an event ID, classification, action, time and protection status. Monitoring excludes browsing URLs, domain names and page content. The configured operator can associate events with the reporting browser client. Network services may receive connection metadata.</p>
    <h2>Access and retention</h2><p>Only authorized administrators can view reports. The default monitoring window is 14 days, subject to the operator’s configuration and backup policy. Turn activity analysis or monitoring off in extension settings. Remove the extension to clear its local extension storage. Contact the operator to ask about server-held records and applicable deletion procedures.</p>
    <h2>Use and sharing</h2><p>Browser data is used to provide security features described here. ThreatDetection does not sell browser data or use it for advertising. Its use of information received from Google APIs adheres to the Chrome Web Store User Data Policy, including the Limited Use requirements.</p>
    <p>For product privacy questions, use the project’s GitHub contact path without posting browsing data, tokens or personal information. For monitoring records, use your administrator’s private channel.</p>${button(repo, 'Project repository', 'outline')}</div>`),
  docs: page('Documentation', 'Set up local protection, configure optional reporting and operate the administrator console.',
    `<div class="cards two">
    <article class="card"><h2>Local setup</h2><p>Launch the backend with the Windows workflow and generate distinct browser and administrator credentials.</p>${source('docs/windows-local-setup.md', 'Windows startup guide')}</article>
    <article class="card"><h2>Browser protection</h2><p>Understand snapshot updates, warning decisions and eligible bypass.</p>${source('docs/browser-protection.md', 'Protection behavior')}</article>
    <article class="card"><h2>Administration</h2><p>Use the operator console to review opt-in monitoring and synthetic checks separately.</p>${source('docs/threat-dashboard.md', 'Administrator console guide')}</article>
    <article class="card"><h2>Storage and recovery</h2><p>Use H2 for local development or configure TLS-verified PostgreSQL for monitoring.</p>${source('docs/postgresql-monitoring.md', 'PostgreSQL configuration')}</article>
    </div>`),
  faq: page('Frequently asked questions', 'Answers about local installation, warnings and optional reporting.',
    `<div class="faq">
    <details><summary>Can I install from the Chrome Web Store?</summary><p>The store listing is pending. Follow the <a href="/extension/">local installation guide</a> for controlled evaluation.</p></details>
    <details><summary>What is the difference between a block and an advisory?</summary><p>A block follows a confirmed reputation match. An advisory points to reasons for caution, such as financial domain resemblance or an unrelated form destination.</p></details>
    <details><summary>What if the backend goes offline?</summary><p>Local financial checks remain available. The browser can continue using a still-valid cached reputation snapshot. When it expires, reputation is unavailable until a refresh succeeds.</p></details>
    <details><summary>Do I have to enable monitoring?</summary><p>No. Monitoring requires an explicit choice in extension settings. Leaving it off keeps browser protection available.</p></details>
    <details><summary>Are the experimental models active?</summary><p>No. URL, DOM and visual ML remain research-only. Controlled results do not establish independent operational accuracy.</p></details>
    </div>`),
  administrator: {
    title: 'Administrator login', description: 'Open the protected ThreatDetection monitoring console.',
    body: ({ monitor }) => `${intro('Administrator login', 'Open the protected monitoring console on your configured backend.')}
    <div class="card admin-card">${logo}<h2>ThreatDetection console</h2>
    <p>Use your administrator credential on the console’s sign-in screen. Your browser extension credential has a separate role.</p>
    <p class="endpoint">${monitor}</p>${button(monitor, 'Open administrator console')}
    <p>${source('docs/windows-local-setup.md', 'Local administrator setup')}</p></div>`
  }
};

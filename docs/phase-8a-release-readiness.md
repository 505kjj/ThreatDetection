# Phase 8A release readiness

## Product scope

Phase 8A starts from [stabilization draft #35](https://github.com/505kjj/ThreatDetection/pull/35) at `17524a9`. The website is a separate static build with ten pages, bundled Inter, actual synthetic product captures, keyboard-operable architecture and scenario demos, and reduced-motion support. Its administrator link targets the existing `/monitor` entry point on the configured backend. The public origin serves only website assets. The release ZIP contains the unchanged deterministic extension runtime. Production security decisions and frozen research are unchanged.

- [Deployment, hosting costs and verification commands](phase-8a-deployment.md)
- [Chrome Web Store listing, disclosures and package instructions](phase-8a-chrome-store.md)
- [Phase 7 acceptance gates and research restrictions](phase-7-release-readiness.md)

## Local evidence

| Check | Result |
| --- | --- |
| Website | 50 layout checks covering all ten pages at 320, 390, 768, 1024 and 1440 CSS px. Twenty axe checks at 390 and 1440 px returned zero violations. Verified keyboard navigation, focused controls, reduced motion, read-only routes and zero external requests during the demo. |
| Packaged extension | Chrome MV3 version 1.4.0, 34 runtime assets, 168,720 bytes. SHA-256 `3e5875fdc548b32c1c49091f0a91c731b883a537687e856bed0b0af94f6a0aaf`. Both existing Chromium modes passed using the extracted ZIP. The secure Windows run exercised DPAPI roles, rotation, corruption handling, deduplication and restart persistence. |
| Local release path | Chromium 159.0.8154.6 followed the website installation instructions and synthetic demo, exercised the loaded extension against the authenticated loopback backend, then followed the website's administrator link to the live console through a disposable HTTPS edge. The edge returned 401 without a credential and 403 with a browser credential on the dashboard data route. The administrator authenticated and inspected opted-in synthetic reports. |
| Regression suites | Maven verified 64 tests with the guarded database case skipped in the default build. Extension unit tests passed 29, research units passed 12, and all 54 frozen receipt checks passed. |
| Security checks | Open Source Vulnerabilities query returned zero advisory matches for 95 Maven runtime coordinates on 2026-11-25. Gitleaks found zero matches in the built website and extracted ZIP. These checks cover the inspected inputs. Container and provider infrastructure require their own scans. |
| Dashboard and extension accessibility | Both smoke modes checked 19 surfaces and zero automated violations. The console's 11 views and detail drawer fit both themes at six sizes. Keyboard focus, charts and reporting interactions passed Chromium assertions. Interactive screen-reader speech and comparison against the original external reference image remain open. |

### Manual contrast review

Calculated WCAG relative-luminance ratios against the strongest sRGB gradient stops and the chart panel background for the text targets flagged by axe. The lowest login copy and accent ratios were 6.90:1 in dark mode and 5.36:1 in light mode. White text against the brightest sign-in button stop measured 6.16:1. The first metric card's muted text measured at least 6.31:1 in dark mode and 5.92:1 in light mode. Chart labels and values measured at least 7.30:1 in dark and 7.61:1 in light against their panel background. Chart meaning is available from text and keyboard-accessible labels. This reviews the steady-state combinations flagged in the captures.

### Local artifacts and reproduction

The verification directory outside Git contains the release ZIP, 20 desktop/mobile website captures, both console and extension capture sets, and four Chrome Store screenshot drafts and the small promo tile. Each product capture uses scoped test data. The report does not distribute browser profiles, credentials or research datasets.

From the repository root, build the backend with `backend/mvnw.cmd verify` from inside `backend`. Set `NODE_PATH` and `PLAYWRIGHT_BROWSERS_PATH` for an installed Playwright Chromium. Set `THREAT_AXE_SOURCE` to the local axe-core JavaScript file. Build the site with `node website/build.mjs` and check it with `node website/browser-check.cjs <capture-directory>`. Build the extension ZIP with `python scripts/package-extension.py <output-directory>`. Set `THREAT_SMOKE_EXTENSION_DIR` to the freshly extracted ZIP and run `node extension/tests/chrome-smoke.cjs` first in direct mode, then with `THREAT_SMOKE_LOCAL_SETUP=1` on Windows. Set `THREAT_UI_MATRIX=1` and `THREAT_MONITOR_CAPTURE_DIR` to retain responsive and accessibility evidence. See the [listing materials](phase-8a-chrome-store.md) for the graphics command.

To reproduce the local HTTPS edge test, create a disposable localhost certificate with a DNS SAN and set `THREAT_SMOKE_TLS_DIR` to its directory containing `server.pem` and `server.key`. Start Node with `NODE_EXTRA_CA_CERTS` pointing at the lab certificate or CA. Run the direct Chromium smoke with these settings. Chromium pins only that generated certificate for the disposable run. Do not use this browser option or a lab private key in deployment. The headless extension cannot answer the native optional-host permission prompt. To check the complete HTTPS extension path, set `THREAT_SMOKE_TLS_EXTENSION=1` and have the operator approve the exact test host in the disposable headed browser. Staging verification still requires the actual edge certificate and approved Chrome extension ID.

## Draft integration

The base stack remains [UI #27](https://github.com/505kjj/ThreatDetection/pull/27) and [6B #29](https://github.com/505kjj/ThreatDetection/pull/29) through [7C #35](https://github.com/505kjj/ThreatDetection/pull/35). The Phase 6C review request [#30](https://github.com/505kjj/ThreatDetection/pull/30) still reports `82825868`. Its source branch is at `3c35fdc9`. The difference is one synthetic near-threshold QA script and its documentation. The verified source commit is an ancestor of #35 and this release branch through the Phase 7 reconciliation. Review the [exact additional Phase 6C commit](https://github.com/505kjj/ThreatDetection/commit/3c35fdc9caccf65f9f0bd41e0615befa196ace61) until GitHub refreshes the review ref. Resolve the upstream draft stack before merging to main.

## Release decisions

| Scope | Decision | Remaining gate |
| --- | --- | --- |
| Controlled local product | GO | Use authorized snapshots, private profiles and synthetic fixtures for acceptance. |
| Public website | Technically prepared. NO-GO for publication. | Approval, chosen host and domain, operator privacy/contact details and target header checks. |
| Cloud backend | NO-GO | Resolve and scan the image, verify container runtime and target edge, verify approved-host permission in Chrome, and run provider recovery and capacity checks. |
| PostgreSQL deployment | NO-GO for target rollout | Run the stage against the chosen provider's CA, network, secrets, backup and outage behavior. |
| Chrome Web Store | NO-GO for publication | Approve publisher submissions and privacy declarations, publish approved URLs, and verify the Store ID with the staging backend. |
| Experimental ML or visual activation | NO-GO | No eligible independent corpus or custodian handoff. Existing research remains isolated. |

Phase 8A did not expose a website or backend, purchase a service, register a domain, submit the extension, merge drafts or start Phase 8B.

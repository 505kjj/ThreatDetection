# UI-1 continuation

Product base is Phase 4C `b9b4add`. The inspected remote main includes Phase 5E but lacks Phase 4C. Phase 6A is on the research line. Leave research branches and frozen evidence untouched.

## Completed

- Replaced the Spring-served `/monitor` design with black-and-violet tokens, a responsive rail, dark and light themes, visible focus, and reduced-motion styling.
- Kept the original same-origin API, administrator bearer token, scope checks, request cancellation and storage/outage handling. Added a token visibility control, sign-in feedback and keyboard focus transitions. Secrets remain in memory.
- Wired Overview and Threat Centre to the existing reports. Added count transitions, an activity plot, category donut, source bars, scoped loading and empty states, latest-event filters, sortable columns and an accessible details dialog.
- Added Threat Intelligence using the administrator feed-status endpoint, Connected Browsers using scoped heartbeat aggregates, and System Health using dashboard and feed outcomes. Added Privacy Centre, working appearance and reduced-motion preferences, and updated Windows startup documentation.
- Added Financial Protection with eight product registry entries, an interactive Phase 5F comparison, Phase 5G readiness, PhreshPhish partition and source summaries, and a Phase 6A controlled-crop benchmark. The admin-only research summary contains whitelisted aggregates and verified brand scopes. It loads only on entry to a financial or research view.
- Counts and the category chart cover the configured retention window. Activity and source charts use only the detections in the API's latest 20-event window. The UI does not send new telemetry or query historical raw records.
- The working frontend is served by Spring Boot without a separate build or dependency install.

## Verification completed

- Maven `verify` passed all 62 tests after the operational views. The dashboard and Threat Centre stage passed all 29 extension unit tests.
- The secure Windows Chromium smoke passed against Spring Boot. It verified authenticated reporting, fixture isolation, dashboard and Threat Centre interactions, feed status, preferences, responsive widths from 390 to 1920 px, and recovery after a backend restart.
- Maven `verify` and the direct Chromium smoke passed for financial and research views, including admin-only summary access, the model metric selector, and mobile navigation.
- Private synthetic screenshots for all implemented console views are in `C:/Users/kj/threat-detection-experiments/ui-1-evidence`. Browser loading and memory measurements remain open.

## Verification commands

1. From the product worktree run `Push-Location backend; .\mvnw.cmd verify; Pop-Location` to verify and package Spring Boot, including `/monitor`.
2. Run `node --test --test-concurrency=1 extension/tests/*.test.mjs`.
3. Use the [secure Windows walkthrough](docs/windows-local-setup.md). Point `NODE_PATH` and `PLAYWRIGHT_BROWSERS_PATH` at the installed Playwright package and Chromium. Set `THREAT_SMOKE_LOCAL_SETUP=1` and optionally `THREAT_MONITOR_CAPTURE_DIR` to a private directory outside Git. Run `node extension/tests/chrome-smoke.cjs`. It creates its own disposable synthetic profile and captures only the opted-in synthetic test console. Do not seed the live scope.

## Continue here

1. Style `extension/popup.html`, `options.html`, `styles.css`, `warning.html`, `warning.css`, and the closed-shadow advisory in `content.js` using the shared design tokens. Keep the existing IDs, scripts, permission model and blocking, advisory, consent and bypass controls. Re-run both Chromium smoke modes and capture the remaining views.
2. Extend the ML comparison across additional Phase 3–5D cohorts. For each added cohort, project only approved fields in `scripts/project-monitor-research.mjs` and run `node scripts/project-monitor-research.mjs` to refresh `backend/src/main/resources/monitoring/research.json`. Add cohort-specific controls and keep thresholds and test populations distinct. The Maven build uses the committed projection and does not need access to research branches.
3. Obtain the missing dashboard reference image for image-to-image visual sign-off. Complete animation recordings, browser performance and accessibility review.

The console uses system typography pending local font review. Do not import research binaries, add production model functionality, or introduce unsupported live statistics.

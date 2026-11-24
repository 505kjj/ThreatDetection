# UI-1 continuation

Product base is Phase 4C `b9b4add`. The inspected remote main includes Phase 5E but lacks Phase 4C. Phase 6A is on the research line. Leave research branches and frozen evidence untouched.

## Completed

- Replaced the Spring-served `/monitor` design with black-and-violet tokens, a responsive rail, dark and light themes, visible focus, and reduced-motion styling.
- Kept the original same-origin API, administrator bearer token, scope checks, request cancellation and storage/outage handling. Added a token visibility control, sign-in feedback and keyboard focus transitions. Secrets remain in memory.
- Wired Overview and Threat Centre to the existing reports. Added count transitions, an activity plot, category donut, source bars, scoped loading and empty states, latest-event filters, sortable columns and an accessible details dialog.
- Added Threat Intelligence using the administrator feed-status endpoint, Connected Browsers using scoped heartbeat aggregates, and System Health using dashboard and feed outcomes. Added Privacy Centre, working appearance and reduced-motion preferences, and updated Windows startup documentation.
- Counts and the category chart cover the configured retention window. Activity and source charts use only the detections in the API's latest 20-event window. The UI does not send new telemetry or query historical raw records.
- The working frontend is served by Spring Boot without a separate build or dependency install.

## Verification completed

- Maven `verify` passed all 62 tests after the operational views. The dashboard and Threat Centre stage passed all 29 extension unit tests.
- The secure Windows Chromium smoke passed against Spring Boot. It verified authenticated reporting, fixture isolation, dashboard and Threat Centre interactions, feed status, preferences, responsive widths from 390 to 1920 px, and recovery after a backend restart.
- Private synthetic screenshots are in `C:/Users/kj/threat-detection-experiments/ui-1-evidence` for login, Overview, Threat Centre, event details, Threat Intelligence, Connected Browsers, System Health, Privacy Centre, Settings, light theme, and mobile. Browser loading and memory measurements remain open.

## Verification commands

1. From the product worktree run `Push-Location backend; .\mvnw.cmd verify; Pop-Location` to verify and package Spring Boot, including `/monitor`.
2. Run `node --test --test-concurrency=1 extension/tests/*.test.mjs`.
3. Use the [secure Windows walkthrough](docs/windows-local-setup.md). Point `NODE_PATH` and `PLAYWRIGHT_BROWSERS_PATH` at the installed Playwright package and Chromium. Set `THREAT_SMOKE_LOCAL_SETUP=1` and optionally `THREAT_MONITOR_CAPTURE_DIR` to a private directory outside Git. Run `node extension/tests/chrome-smoke.cjs`. It creates its own disposable synthetic profile and captures only the opted-in synthetic test console. Do not seed the live scope.

## Continue here

1. Add Financial Protection using the verified product scopes in `extension/financial-domains.mjs`. Extend the `views` map in `backend/src/main/resources/monitoring/monitor.js` and add the matching navigation and view in `index.html`.
2. Build ML, Dataset and Visual Intelligence screens from whitelisted aggregates. Source Phase 5F JSON at `a09394b:docs/experiments/phase5f/results.json`, the Phase 5G registry and preflight at `ebe0f4f`, and Phase 6A results at `9908b49:docs/experiments/phase6a/results.json`. Record the source revisions, cohort and operating points. Copy only the fields needed by the UI. Do not merge the research branches into this product branch.
3. Style `extension/popup.html`, `options.html`, `styles.css`, `warning.html`, `warning.css`, and the closed-shadow advisory in `content.js` using the shared design tokens. Keep the existing IDs, scripts, permission model and blocking, advisory, consent and bypass controls. Re-run both Chromium smoke modes and capture the remaining views.
4. Obtain the missing dashboard reference image for image-to-image visual sign-off. Complete the full screenshot list, animation recordings, browser performance and accessibility review. Current responsive checks cover the implemented console views only.

The console uses system typography pending local font review. Do not import research binaries, add production model functionality, or introduce unsupported live statistics.

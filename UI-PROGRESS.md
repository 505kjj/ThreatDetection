# UI-1 continuation

Product base is Phase 4C `b9b4add`. The inspected remote main includes Phase 5E but lacks Phase 4C. Phase 6A is on the research line. Leave research branches and frozen evidence untouched.

## Completed

- Replaced the Spring-served `/monitor` design with black-and-violet tokens, a responsive rail, dark and light themes, visible focus, and reduced-motion styling.
- Kept the original same-origin API, administrator bearer token, scope checks, request cancellation and storage/outage handling. Added a token visibility control, sign-in feedback and keyboard focus transitions. Secrets remain in memory.
- Wired Overview and Threat Centre to the existing reports. Added count transitions, an activity plot, category donut, source bars, scoped loading and empty states, latest-event filters, sortable columns and an accessible details dialog.
- Added Threat Intelligence using the administrator feed-status endpoint, Connected Browsers using scoped heartbeat aggregates, and System Health using dashboard and feed outcomes. Added Privacy Centre, working appearance and reduced-motion preferences, and updated Windows startup documentation.
- Added Financial Protection with eight product registry entries, an interactive Phase 5F comparison, Phase 5G readiness, PhreshPhish partition and source summaries, and a Phase 6A controlled-crop benchmark. The admin-only research summary contains whitelisted aggregates and verified brand scopes. It loads only on entry to a financial or research view.
- Redesigned the extension popup, settings, confirmed warning page and in-page advisory. The popup shows cached protection and reporting status, opens the configured dashboard, and uses the existing protection preference to pause or resume. No extension permissions were added.
- Counts and the category chart cover the configured retention window. Activity and source charts use only the detections in the API's latest 20-event window. The UI does not send new telemetry or query historical raw records.
- The working frontend is served by Spring Boot without a separate build or dependency install.

## Verification completed

- Maven `verify` passed all 62 tests after the operational views. The dashboard and Threat Centre stage passed all 29 extension unit tests.
- The secure Windows Chromium smoke passed against Spring Boot. It verified authenticated reporting, fixture isolation, dashboard and Threat Centre interactions, feed status, preferences, responsive widths from 390 to 1920 px, and recovery after a backend restart.
- Maven `verify` and the direct Chromium smoke passed for financial and research views, including admin-only summary access, the model metric selector, and mobile navigation.
- Both Chromium smoke modes and all 29 extension unit tests passed for the final extension stage. The browser checks covered popup pause and resume, settings synchronization, warning outcomes, bypass restrictions, opt-in and opt-out, restart persistence, and invalid and expired reputation snapshots.
- Nineteen private screenshots are in `C:/Users/kj/threat-detection-experiments/ui-1-evidence`. They cover all requested console and extension surfaces plus the event dialog. `console-motion.webm` shows login typography, synthetic count-up, chart reveal, event details and research navigation. The recording verified an intermediate count and the final total.

## Performance and accessibility

- One loopback Chromium smoke run recorded 126 ms navigation, 66 ms to DOMContentLoaded, 71,035 decoded bytes across the initial HTML, CSS and JavaScript, and approximately 5.1 MB of Chromium-reported used JavaScript heap in the loaded dashboard. `performance.json` records the sample. Repeat on production hardware and under load before treating these numbers as targets.
- Chromium checked navigation at 1920, 1440, 1366, 1024, 768 and 390 px, accessible names, keyboard dismissal, and reduced motion. Spot checks measured body and secondary text contrast of 16.90 and 7.30 in dark mode and 18.08 and 7.61 in light mode. Confirmed red on the dark card measured 5.02. A full screen-reader and contrast audit remains open.

## Verification commands

1. From the product worktree run `Push-Location backend; .\mvnw.cmd verify; Pop-Location` to verify and package Spring Boot, including `/monitor`.
2. Run `node --test --test-concurrency=1 extension/tests/*.test.mjs`.
3. Use the [secure Windows walkthrough](docs/windows-local-setup.md). Point `NODE_PATH` and `PLAYWRIGHT_BROWSERS_PATH` at the installed Playwright package and Chromium. Set `THREAT_SMOKE_LOCAL_SETUP=1` and optionally `THREAT_MONITOR_CAPTURE_DIR` to a private directory outside Git. Run `node extension/tests/chrome-smoke.cjs` for the disposable Windows profile and evidence capture. Clear `THREAT_SMOKE_LOCAL_SETUP` and `THREAT_MONITOR_CAPTURE_DIR` and rerun for the direct disposable-backend mode, which also tests invalid and expired snapshots. Keep synthetic reports separate from the live scope.

## Continue here

1. Extend the ML comparison across additional Phase 3–5D cohorts. For Phase 5D, inspect `a09394b:docs/experiments/phase5d/results.json` for matched and temporal views. For earlier diagnostics, use the Phase 3 experiment reports at that revision. Project only approved fields in `scripts/project-monitor-research.mjs`, run `node scripts/project-monitor-research.mjs`, and add cohort-specific controls in `backend/src/main/resources/monitoring/monitor.js`. Keep thresholds and test populations distinct. The Maven build uses the committed projection without access to research branches.
2. Obtain the missing dashboard reference image for visual sign-off. Compare it with `overview.png`, `mobile.png` and `light.png`, adjust the console styles in `backend/src/main/resources/monitoring/monitor.css`, then rerun the capture command above. Repeat performance measurements on target hardware and finish the screen-reader audit.

The console uses system typography pending local font review. Do not import research binaries, add production model functionality, or introduce unsupported live statistics.

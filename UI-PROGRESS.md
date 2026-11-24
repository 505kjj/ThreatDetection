# Frontend progress

## UI-2 changes

- Reviewed the 19 UI-1 Chromium captures and its motion recording. The desktop navigation now shows section names on wider screens, and the narrower rail retains the active violet indicator. Rebalanced the Overview grids, strengthened the metric hierarchy and made the recent-event columns fit narrow screens. Full evidence stays available in the event dialog.
- Metric animation now rolls once per changed value with a shorter count-up. Card entrances run on initial load, chart elements animate when their data changes, and navigation, drawer and theme transitions are brief. Reduced-motion settings suppress these effects. Warning evidence and controls remain immediately visible.
- Bundled the same Latin Inter variable font in the console and extension. The WOFF2 is 48,256 bytes and loaded locally with a system fallback. Maven packages the font and its SIL OFL 1.1 notice from `extension/fonts`. [Inter project](https://github.com/rsms/inter) · [Distributor license](https://github.com/google/fonts/blob/main/ofl/inter/OFL.txt)
- Expanded the ML Laboratory to 17 cohort views. The projection includes frozen numerical baselines, cross-source and chronological experiments, controlled retraining, TF-IDF, character CNN and Transformer comparisons, URL ensembles, DOM models and fusion. Cohort, observed class counts, calibration origin and score cutoff accompany point metrics. Ranking metrics are threshold-free. Positive-only and negative-only cohorts omit unsupported values.
- The Phase 5G independent evaluation still shows zero eligible URL and paired records scored. Deployment restrictions for ML and visual recognition continue to apply.

## UI-2 benchmark

Measured on the available Windows 11 26300 workstation, a Core Ultra 7 155H with 32 GB RAM, using headless Chromium 159.0.8154.6 and a loopback Spring Boot backend with 12 synthetic reports. Each version used one warm-up and six measured runs in new browser contexts. Viewport was 1440 × 980. The baseline was UI-1 commit `6fbd6cc`.

| Measurement | UI-1 | UI-2 |
| --- | ---: | ---: |
| Median navigation load | 144.3 ms | 168.6 ms |
| Median DOMContentLoaded | 141.0 ms | 157.5 ms |
| Median synthetic dashboard request | 13.0 ms | 12.8 ms |
| Initial decoded HTML, CSS, JavaScript, font | 71,035 B | 129,700 B |
| Median used JavaScript heap | 3.59 MB | 3.69 MB |
| Median time from scope selection to final count | 722.4 ms | 473.3 ms |
| 95th percentile animation frame interval | 16.8 ms | 16.8 ms |
| Frame intervals over 33.4 ms | 2 of 287 | 1 of 290 |
| Layout shifts observed on initial load | 0 | 0 |

The local font accounts for 48,256 bytes of the increase in initial assets. These are loopback measurements on one machine, taken before the final accessible-name and score-formatting adjustments. The raw runs and the benchmark harness are in `C:/Users/kj/threat-detection-experiments/ui-2-evidence`. The 7.8-second motion capture shows the login, metric count-up, chart reveal, Threat Centre drawer, theme change and temporal comparison.

## UI-2 accessibility checks

- axe-core 4.14.1 reported zero WCAG-tagged violations across 18 console and extension views and dialog states. The only remaining automated review items were contrast over gradients or in SVG. The findings and manually checked colors below are separate from the live screen-reader pass.
- Keyboard checks cover skip targets, workspace navigation, sort and filter controls, native dialog dismissal and focus return, theme changes, and both system and console reduced motion. Responsive checks span 320–1920 px. The compact table keeps the detection, action, source and Details control visible.
- Chromium's accessibility tree exposed the administrator field, workspace landmark, headings, named charts, the table and the event dialog. Animated counter replicas are hidden from assistive technology.
- Manual contrast checks covered gradient and SVG cases that axe cannot fully resolve. The minimum among the checked pairs was 4.64:1 for the dark blocked badge. The active violet text was 6.70:1 in dark mode and 7.43:1 in light mode. Muted text on the tinted metric cards measured at least 5.93:1, chart labels at least 7.30:1, and the confirmed and advisory primary actions at least 7.81:1.

## UI-2 continuation

1. Obtain the dashboard reference image. No image attachment was available in the workspace for this pass. Compare it with the UI-2 Overview, light and mobile captures in `C:/Users/kj/threat-detection-experiments/ui-2-evidence` before changing draft PR #27 to ready for review.
2. Finish the live screen-reader pass on an interactive Windows desktop. Chromium's accessibility tree and keyboard assertions passed. The environment blocked portable NVDA setup, and Windows Narrator launched without exposing a targetable speech or recap window. Use a disposable synthetic profile and check announcements at login, navigation, report scope, sorting, dialogs, research controls and warnings.
3. Regenerate the aggregate bundle with `node scripts/project-monitor-research.mjs`. Phase 5B uses only published rounded metrics at the documented 0.5 threshold. Its private calibrated score cutoffs are absent from the published report. Keep experiment sources frozen and avoid copying raw records, models or identifiers.
4. To repeat the automated WCAG audit, install `axe-core@4.14.1` into a temporary npm prefix and set `THREAT_AXE_SOURCE` to its `axe.min.js` before running the Chromium smoke tests below. The app and normal test paths have no axe dependency.
5. To reproduce the benchmark, package UI-1 commit `6fbd6cc` in a separate worktree and package the current branch. With the Playwright environment below, run `node <evidence-directory>/benchmark.cjs <ui1-jar> <ui2-jar>` from the repository root. Run the harness with other workloads idle.

## UI-2 verification

- Clean Maven verification passed all 62 backend tests. All 29 extension unit tests and both Chromium modes passed. The Chromium flows exercised role boundaries, synthetic scope, consent, confirmed blocking, one-time bypass, advisories, backend outage, secure Windows persistence, credential rotation and stale snapshots.
- A final packaged Chromium check verified that the Phase 5C strict score cutoff displays as 0.9999995232 and the Phase 5F fixed-fusion score cutoff as 0.7963963524.
- Captured all 19 updated interface and dialog screenshots under `C:/Users/kj/threat-detection-experiments/ui-2-evidence`. Use `contact-sheet.jpg` to browse them together.

## UI-1 record

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

The UI-1 baseline used system typography. The Maven build uses the committed sanitized projection without access to research branches.

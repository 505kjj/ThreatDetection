# Frontend progress

## Phase 7C stabilization

- The laboratory presents separate in-memory and file-backed H2 results from the paced synthetic runs, including the isolated rate-limit check. The [release report](docs/phase-7-release-readiness.md) records verification and open acceptance gates. Live screen-reader speech and comparison with the dashboard reference remain open.

## Phase 6B integration verification

- The integrated product runtime matches UI-2 commit `9661a263`. Direct and secure Chromium smoke runs passed with the responsive matrix. The secure run exercised PowerShell 5.1 setup and PowerShell 7 restart, persistence and credential rotation.
- A repeat on the same Windows 11 Core Ultra 7 155H workstation used six cold Chromium contexts with 12 synthetic reports. Median navigation was 97.1 ms, DOMContentLoaded 85.3 ms, count settlement 476.3 ms and chart response to first frame 28.2 ms. Frame interval p95 was 16.8 ms, with zero of 294 intervals above 33.4 ms. Measurements and a fresh animation recording are in `C:/Users/kj/threat-detection-experiments/phase-6b-evidence`.
- The dashboard reference image and live screen-reader speech review remain outstanding. Keep PR #27 in draft until both are completed. See the [integration report](docs/phase-6b-integration.md) for branch dependencies and research verification.

## Expanded UI-2 changes

- Continued from `b02b8e6` on the Phase 4C product line. Draft PR #27 continues to track that branch.
- The console and extension pages now load one shared local theme for typography, colors, surfaces and motion. The console favicon and Chrome toolbar icons use the existing violet shield design. The three PNGs total 11,923 bytes, down from 1,207,548 bytes.
- The wide-screen sidebar can collapse to an icon rail. Mobile keeps pill navigation. Data-backed chart points and category segments can be inspected with focus, pointer or touch. A static skeleton distinguishes a pending scope fetch from empty reports.
- The ML Laboratory adds inspectable diagrams for Phase 5F fixed fusion, the Phase 5C character CNN and the Phase 5D Transformer. Dataset and visual research diagrams explain their processing stages. The diagrams run entirely as illustrations. The 17 published cohort views retain their existing evidence and thresholds.
- Popup explanations use native disclosures and start open. Consent feedback is limited to the local toggle presentation. Protection permissions, reporting data, authentication and threat decisions retain their existing behavior.
- Updated the [secure Windows setup and verification steps](docs/windows-local-setup.md). Runtime assets are served locally by Spring Boot or Chrome. The build adds no frontend framework or dependency.

## Expanded UI-2 measurements

On the same Windows 11 Core Ultra 7 155H machine, the first expanded pass measured six cold Chromium contexts per build with 12 synthetic records. These readings preceded the final change to animate the donut slices together and leave chart labels static during reveal. They are a separate run from the older UI-2 benchmark below.

| Median unless stated | UI-1 | Expanded pass before chart tuning |
| --- | ---: | ---: |
| Navigation load | 321.8 ms | 401.4 ms |
| DOMContentLoaded | 305.8 ms | 380.6 ms |
| Decoded initial HTML, CSS, JS and font | 71,035 B | 143,699 B |
| Used JavaScript heap | 3.60 MB | 3.92 MB |
| Dashboard response to first chart frame | 73.9 ms | 88.6 ms |
| Scope selection to final count | 744.7 ms | 490.1 ms |
| Animation frame interval, p95 | 33.2 ms | 52.1 ms |

One 30-second background poll took 19.5 ms to fetch 2,919 bytes and reused the existing activity chart. The popup's median document load was 169.2 ms, with 166.8 ms to DOMContentLoaded, 250.6 ms to populated reputation status and 3.83 MB of used JavaScript heap. These popup measurements use six tabs in one extension browser process, after one warm-up. Its HTML, CSS, JavaScript modules and font total 66,236 local bytes. Platform timings are loopback observations.

Six final-build cold contexts in a separate run measured 677.7 ms median navigation load, 437.6 ms to DOMContentLoaded, 143,839 decoded initial bytes, 3.90 MB of used JavaScript heap, 24.8 ms for the synthetic dashboard request, 62.3 ms from its response to the first chart frame, and 492.3 ms from selecting the scope to the final count. The frame interval was 36.3 ms at p95, with 16 of 261 intervals above 33.4 ms. Startup times varied across runs. The separate final run cannot isolate the effect of the chart changes.

The raw measurements, scripts and visual evidence are in `C:/Users/kj/threat-detection-experiments/ui-2-final-evidence`. Use the benchmark commands in the earlier continuation notes below with the final evidence directory. The first expanded results are in `benchmarks-before-chart-pass.json` and the final-build measurements are in `benchmarks-final-ui2.json`.

## Expanded UI-2 visual and accessibility checks

- Reviewed the 19 refreshed Chromium screenshots against the written design brief and the prior captures. The final evidence folder contains their `contact-sheet.jpg` and the synthetic `console-motion.webm` walkthrough.
- The secure Chromium layout matrix checked sign-in, all 11 console views and the event drawer at 1920 × 1080, 1440 × 900, 1366 × 768, 1024 × 768, 768 × 900 and 390 × 844 in both themes. The overview test also checked 320 px. The popup uses a 360 px layout.
- axe-core found zero violations across 19 views and dialog states. Its remaining contrast review flags concern the gradients and SVG surfaces covered by the manual checks below. Keyboard checks cover compact navigation, chart inspection and dismissal, research controls, extension disclosures, drawer focus, theme and reduced motion.

## Expanded UI-2 regression results

- Clean Maven verification passed 62 tests. The extension unit suite passed all 29 tests.
- Both direct and secure Windows Chromium modes passed on the final application build. The tests covered authenticated synthetic reporting and its separate scope, content and network warnings, controlled bypass, settings and consent, backend outage, database failure and restoration, report persistence, deduplication, administrator rotation, and invalid or expired snapshots.
- The secure run used real Chromium clicks on a loopback fixture and checked the exact dashboard response used to render the counter. The visual evidence and browser tests used disposable synthetic data.

## Final acceptance gates

- The expanded brief arrived as a text attachment. Final visual comparison still requires the dashboard reference image. Review `overview.png`, `mobile.png`, and `light.png` in the final evidence folder against that image before marking PR #27 ready.
- Live screen-reader speech remains unverified. Portable NVDA setup was blocked by the execution environment, and the prior Narrator run exposed no targetable speech window. Repeat the speech checks on an interactive Windows desktop using a disposable synthetic profile.

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

## Phase 8A website and release checks

The [standalone product site](website/) builds with `node website/build.mjs`. Preview it with `node website/preview.mjs 4173`. Its administrator link opens the existing console on the configured server. The website includes a local synthetic demo and serves no authenticated monitoring data.

The [Phase 8A readiness report](docs/phase-8a-release-readiness.md) records the website and console checks, release package verification and remaining sign-off gates. Updated private captures are in `C:/Users/kj/threat-detection-experiments/phase-8a-release`. For dashboard UI sign-off, open the synthetic console profile, repeat the login, chart and drawer flows with a live screen reader, and compare against the original dashboard reference when it is available.

The final deployment branch uses [Vercel, Render and Neon](docs/phase-8a-deployment.md). The hosted static build requires an approved public privacy contact and the actual HTTPS console URL. The dashboard and extension retain their existing UI and runtime. The [final deployment checks](docs/phase-8a-final-verification.md) record local measurements, hosted follow-up and Git review evidence.

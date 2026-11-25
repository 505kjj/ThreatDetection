# Phase 6E extended security research

Status is an isolated browser research pilot. No new production warnings, blocking, browser permissions, data collection or production telemetry are enabled. The classifier returns bounded reason codes and does not establish maliciousness or operational effectiveness.

The two synthetic tests cover confirmed authorized reputation evidence, financial impersonation, unexplained redirects, credential forms, cookie attributes, permissions, MIME mismatches, tracking, interface behavior, experimental evidence and an OAuth control. Only reputation evidence can receive the confirmed category. Cookie and tracking observations are privacy findings. Missing reputation and experimental evidence can be marked unavailable. A legitimate control creates no finding. These are contract fixtures rather than coverage or false-positive estimates.

## Chrome capability review

- Cookie metadata requires the `cookies` permission and host permissions. Chrome's cookie object includes a value, so a future design must explicitly avoid retaining or exposing that field. HttpOnly cookies are inaccessible to client-side scripts. [Chrome cookies API](https://developer.chrome.com/docs/extensions/reference/api/cookies)
- Navigation events require `webNavigation`. Their relationship to `webRequest` events is not a guaranteed ordering. Neither observation alone establishes intent. [Chrome webNavigation API](https://developer.chrome.com/docs/extensions/reference/api/webNavigation)
- Download metadata requires the `downloads` permission. The API includes MIME, filename and URLs, which can reveal private activity. File hashes are not supplied as a general property. [Chrome downloads API](https://developer.chrome.com/docs/extensions/reference/api/downloads)
- The `contentSettings` API requires its own permission and exposes settings for camera, microphone, location and notifications. A setting is not proof of actual use. [Chrome contentSettings API](https://developer.chrome.com/docs/extensions/reference/api/contentSettings)
- Request visibility is restricted by extension permissions and host access. A tracker conclusion also needs a reviewed, appropriately licensed list. [Chrome webRequest API](https://developer.chrome.com/docs/extensions/reference/api/webRequest)

## Remaining work

The ML Laboratory shows a sanitized static summary of the pilot and its unavailable observations. The isolated MV3 extension requests `webNavigation`, `cookies`, `contentSettings` and loopback host access. It keeps up to eight top-frame event categories per tab for at most 30 seconds, clears them when a tab closes and retains no URL. Chrome may collapse intermediate server redirects into a single committed event. This bounded event sequence is not a complete redirect chain. A content script inspects at most 20 form structures and 20 iframes. It classifies password form actions and reports a cross-origin iframe as contextual evidence without reading form values or iframe contents. Cross-origin iframes occur in legitimate pages and cannot establish maliciousness. The classifier receives an explicitly unavailable reputation state. Redirect events alone produce no verdict because authorization context is unavailable. Loopback HTTP is accepted solely for the fixture, and is not a security assessment for real sites.

Five loopback Chromium 159 fixtures included a local login, OAuth and payment redirect controls, an external form action and an insecure external action. The expected categories matched in all five. Three benign controls produced zero credential advisories and both suspicious controls produced advisories. Reputation was unavailable in all five. These are synthetic fixture counts and do not measure real-world coverage or false positives. Messaging and form inspection, excluding navigation, measured 39.19 ms median and 98.81 ms p95 over five samples. The guarded job used two logical CPUs, 7.69 seconds wall time, 7.41 CPU seconds and 562,417,664 bytes peak job commit including Chromium and the driver.

The cookie API returns complete cookie objects, including values, to the isolated worker. The fixture cookie uses an empty synthetic value. The worker immediately computes counts for Secure, HttpOnly, host-only and SameSite attributes, and returns no values, names, domains or paths. Its missing-Secure observation on this HTTP fixture is a privacy observation and does not establish compromise. The permission API reads the camera, microphone, location and notification settings for the loopback origin. An allowed setting does not establish use. These are isolated fixture calls and are not connected to production.

Seven synthetic Chromium scenarios repeated five times yielded 35 expected observations. Twenty ordinary login, OAuth, SSO and payment trials produced zero credential advisories, and ten external or insecure form trials produced ten. Five external-frame trials produced contextual iframe evidence. Reputation was unavailable in all 35. Cookie counts were checked in all 35 and four permission settings in each trial. Messaging and inspection, excluding navigation, measured 24.47 ms median and 45.75 ms p95. The guarded process tree used two logical CPUs, 17.69 seconds wall time, 28.13 CPU seconds and 562,274,304 bytes peak job commit. Repeated trials share fixtures and are not independent observations.

A second run of the same seven scenarios also passed all 35 trials. It measured 30.10 ms median, 87.84 ms p95, 19.27 seconds wall time, 29.25 CPU seconds and 563,564,544 bytes peak process-tree job commit. Both runs used two logical CPUs. The results illustrate variation on one workstation and do not establish a target-hardware bound.

A third run passed all 35 trials, including explicit assertions on iframe and cookie evidence. Median was 29.69 ms, p95 114.43 ms, wall time 19.25 seconds, CPU time 29.19 seconds and peak job commit 599,756,800 bytes. It used the same machine and two-CPU guard.

Download assessment is deferred. The Chrome API requires broad download access and returns URLs and local filenames, while this research has no reviewed need or authorized reputation feed for a real download. Tracker identification is deferred until a licensed, maintained list and a narrowly scoped measurement design are approved. These are unavailable capabilities, not clean results. Additional cookie configurations, real-world controls, repeated hardware tests and accessibility speech review remain necessary before evaluating readiness. Phase 6B and 6C remain draft dependencies. Phase 6D canvas parity and independent visual validation remain unresolved. Production security decisions and reputation precedence remain governed by the existing product.

Run `node --test research/phase6e/*.test.mjs` from the repository root. No cookie values, credentials, file contents or URLs are required by these fixtures.

To reproduce the loopback run, set `NODE_PATH` and `PLAYWRIGHT_BROWSERS_PATH` to the existing private Playwright and Chromium installation. Run `research/phase3d/resource_guard.py --metrics <new-private-resource-file> -- node research/phase6e/browser.cjs <new-private-result-file>` with the Phase 5B Python environment. The runner creates a disposable Chromium profile and loopback server. It does not submit forms or collect input values. After Chrome exits, the runner verifies the profile is its own temporary child directory and removes it.

## Capability decisions

| Capability | Decision | Reason |
| --- | --- | --- |
| Redirects and form metadata | GO for isolated research | Bounded fixture observations need broader validation and context. |
| Cookie and permission attributes | GO for isolated research | APIs expose sensitive capability surfaces and require explicit privacy review. |
| Cross-origin iframe | GO for isolated research | Common legitimate uses make it weak contextual evidence. |
| Downloads and trackers | Deferred | Broader data access, authorized reputation and a reviewed list are unresolved. |
| New production warnings and blocking | NO-GO | Independent evaluation and operational false-positive evidence are unavailable. |

Maven verification passed 62 tests, extension unit tests passed 29, both direct and secure Windows Chromium smoke tests passed with the responsive matrix, and two 6E unit tests passed. Fifty-four frozen artifact receipt checks passed in the preceding 6E stage, with unchanged frozen dependencies. Live screen-reader speech remains an open Phase 6B acceptance gate. GO for offline research and NO-GO for new production warnings or blocking.

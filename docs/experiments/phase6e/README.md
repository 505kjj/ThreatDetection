# Phase 6E extended security research

Status is an offline evidence-classification pilot. No new warnings, blocking, browser permissions, data collection or production telemetry are enabled. The classifier accepts predefined synthetic categories and returns bounded reason codes. It does not inspect a browser, establish maliciousness or evaluate operational effectiveness.

The two synthetic tests cover confirmed authorized reputation evidence, financial impersonation, unexplained redirects, credential forms, cookie attributes, permissions, MIME mismatches, tracking, interface behavior, experimental evidence and an OAuth control. Only reputation evidence can receive the confirmed category. Cookie and tracking observations are privacy findings. Missing reputation and experimental evidence can be marked unavailable. A legitimate control creates no finding. These are contract fixtures rather than coverage or false-positive estimates.

## Chrome capability review

- Cookie metadata requires the `cookies` permission and host permissions. Chrome's cookie object includes a value, so a future design must explicitly avoid retaining or exposing that field. HttpOnly cookies are inaccessible to client-side scripts. [Chrome cookies API](https://developer.chrome.com/docs/extensions/reference/api/cookies)
- Navigation events require `webNavigation`. Their relationship to `webRequest` events is not a guaranteed ordering. Neither observation alone establishes intent. [Chrome webNavigation API](https://developer.chrome.com/docs/extensions/reference/api/webNavigation)
- Download metadata requires the `downloads` permission. The API includes MIME, filename and URLs, which can reveal private activity. File hashes are not supplied as a general property. [Chrome downloads API](https://developer.chrome.com/docs/extensions/reference/api/downloads)
- The `contentSettings` API requires its own permission and exposes settings for camera, microphone, location and notifications. A setting is not proof of actual use. [Chrome contentSettings API](https://developer.chrome.com/docs/extensions/reference/api/contentSettings)
- Request visibility is restricted by extension permissions and host access. A tracker conclusion also needs a reviewed, appropriately licensed list. [Chrome webRequest API](https://developer.chrome.com/docs/extensions/reference/api/webRequest)

## Remaining work

The ML Laboratory shows a sanitized static summary of the pilot and its unavailable observations. The pilot has no Chrome API integration, tracker list, live cookie inspection, redirect-chain reconstruction, form extraction, permission lookup or download inspection. Synthetic API and browser fixtures, quantitative false-positive controls, latency and memory measurements, and accessibility review remain necessary before evaluating technical readiness. Phase 6B and 6C remain draft dependencies. Phase 6D canvas parity and independent visual validation remain unresolved. Production security decisions and reputation precedence remain governed by the existing product.

Run `node --test research/phase6e/*.test.mjs` from the repository root. No cookie values, credentials, file contents or URLs are required by these fixtures.

Maven verification passed 62 tests, extension unit tests passed 29, and the direct Chromium smoke passed with its six-size responsive matrix after adding the summary. Four 6D and 6E unit tests and 54 frozen artifact receipt checks passed. The synthetic 6E classifier has no measured CPU, memory, detection coverage or false-positive rate. The secure Windows smoke was last run on the Phase 6C base and has not been repeated for this summary change. GO for offline research and NO-GO for new production warnings or blocking.

# UI-1 continuation

Product base is Phase 4C `b9b4add`. The inspected remote main includes Phase 5E but lacks Phase 4C. Phase 6A is on the research line. Leave research branches and frozen evidence untouched.

## Completed

- Replaced the Spring-served `/monitor` design with black-and-violet tokens, a responsive rail, dark and light themes, visible focus, and reduced-motion styling.
- Kept the original same-origin API, administrator bearer token, scope checks, request cancellation and storage/outage handling. Added a token visibility control, sign-in feedback and keyboard focus transitions. Secrets remain in memory.
- Wired Overview and Threat Centre navigation to the existing reports and evidence table.

## Continue here

1. Build and test from this worktree. Run `Push-Location backend; .\mvnw.cmd verify; Pop-Location`. Use the existing [secure Windows walkthrough](docs/windows-local-setup.md) to run an isolated synthetic profile at `/monitor`. No frontend build is required.
2. Add count transitions, charts and investigation filters using the existing dashboard contract in `MonitoringService.Dashboard`. Scope category stats to retention, plus clearly label activity and source charts as the latest event sample. Add Chromium coverage and capture 1440px and 390px views.
3. Next add supported infrastructure and reporting views, financial protection, and labs using sanitized versioned summaries. Then style the extension and warning surfaces without changing behavior.
4. The written brief is available. No dashboard reference image was present in the supplied attachments. Obtain it for image-to-image comparison before final visual sign-off.

The frontend is deliberately dependency-free for Spring packaging and CSP compatibility. The first stage uses system typography pending local font review. Do not import research binaries, add production model functionality, or introduce unsupported live statistics.

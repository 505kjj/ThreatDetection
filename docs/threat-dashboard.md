# Threat dashboard

Phase 4A adds optional reporting to the Chrome extension, a protected Spring Boot API, and an administrator dashboard at `/monitor`. Reporting is off by default and requires explicit consent for the configured backend origin. Protection uses the existing local reputation and financial rules. No experiment or ML score is connected to this workflow.

## Run locally

1. From `backend/`, run `.\mvnw.cmd verify` with Java 21. Load `extension/` as an unpacked extension and copy the ID displayed in `chrome://extensions`.
2. In PowerShell 7, use the [README’s local token helper](../README.md#run-and-verify-locally) to define `New-LocalApiClient`. In the same shell, from `backend/`:

   ```powershell
   $extensionId = Read-Host 'ID shown in chrome://extensions'
   $browser = New-LocalApiClient BROWSER
   $admin = New-LocalApiClient ADMIN
   $env:THREAT_REPUTATION_SNAPSHOT_PATH = 'C:\path\to\authorized-current-snapshot.json'
   $env:SPRING_APPLICATION_JSON = @{
       threat = @{
           security = @{
               clients = @{ 'local-chrome' = $browser.Settings; 'local-admin' = $admin.Settings }
               'allowed-origins' = @("chrome-extension://$extensionId")
           }
           monitoring = @{ 'retention-days' = 14; 'events-per-minute' = 60 }
       }
   } | ConvertTo-Json -Depth 8 -Compress
   $backend = Start-Process java -ArgumentList '-jar', 'target/threat-detection-0.0.1-SNAPSHOT.jar' -PassThru -WindowStyle Hidden
   Set-Clipboard -Value $browser.Token
   ```

   Set the snapshot path to data you have permission to use. Leave it unset if you only need to inspect the dashboard or verify unavailable status. When using any synthetic snapshot or traffic, set `'synthetic-clients' = @('local-chrome')` inside `monitoring` before starting a disposable backend. Use different browser IDs for test and live reporting and never move an in-use ID between these scopes.

3. In extension **Settings**, save the browser token for `http://127.0.0.1:8081`. Then enable **Share threat detections with this backend**. This switch is separate from the existing per-site activity monitoring controls.
4. Run `Set-Clipboard -Value $admin.Token`. Open `http://127.0.0.1:8081/monitor` and sign in with that admin token. Choose **Synthetic fixtures** when working with a configured fixture browser. Clear your clipboard afterward. To stop the disposable backend, run `Stop-Process -InputObject $backend` and remove the shell configuration when finished.

For a fully repeatable demonstration, run the [Chromium smoke test](../README.md#extension-regression-checks). From the repository root, set `$env:THREAT_MONITOR_SCREENSHOT = Join-Path (Get-Location) 'docs/phase-4a-dashboard.png'` to capture the authenticated dashboard and `$env:THREAT_MONITOR_OFFLINE_SCREENSHOT = Join-Path (Get-Location) 'docs/phase-4a-dashboard-offline.png'` to capture the outage state. Then run `node extension/tests/chrome-smoke.cjs`. The smoke test uses a separate disposable backend and browser profile. Synthetic destinations resolve to loopback.

## Events and status

| Source | Category | What the dashboard records |
| --- | --- | --- |
| Active reputation snapshot | Phishing or malware | Blocked after a network interception matching an installed blocking rule. A confirmed hash-only or other post-navigation interstitial is recorded as warned. |
| Existing one-time exception | Phishing | Bypassed only after the permitted navigation commits. It is counted separately from detections. |
| Verified financial-domain rules | Financial impersonation | An unconfirmed advisory with a fixed explanation of the detected hostname structure. |
| Existing per-site activity rules | Suspicious behavior | An unconfirmed warning when the authenticated analysis returns an advisory. |

The extension sends detection timestamps, a random event UUID, one enumerated signal, and one action. The server derives category, source, severity and a fixed reason from that signal. The dashboard displays totals for submitted detections in the retention period, the latest 20 event records, and the connection and protection status of reporting browsers. It cannot count the detections of browsers that have reporting disabled or failed to submit an event.

While opted in and unpaused the extension sends a status heartbeat approximately once a minute. The backend reports availability of current local reputation data for each recently reporting browser. A browser without a heartbeat for three minutes counts as having unknown status. Opt-out and pause stop sending and the prior heartbeat can remain visible until that timeout. An inaccessible backend is shown as unavailable and the page clears its old results. Protection still uses fresh cached reputation data and the existing local rules during backend outages. Reporting does not retain an offline queue or backfill missed detections.

## API, access and retention

| Route | Role | Contract |
| --- | --- | --- |
| `POST /api/threat/monitoring/heartbeat` | BROWSER | `protection` is `REPUTATION_AVAILABLE` or `REPUTATION_UNAVAILABLE`. Returns 204. |
| `POST /api/threat/monitoring/events` | BROWSER | `id` is a random UUID v4, `signal` is an allow-listed code, `action` is allowed for that signal and `detectedAt` is UTC with milliseconds. Returns 204, including idempotent retries with identical data. |
| `GET /api/threat/monitoring/dashboard?scope=REAL` | ADMIN | Returns the live rollup and recent history by default. `SYNTHETIC` returns only reports from server-configured synthetic clients. No request can set its own scope. |
| `GET /monitor`, `/monitor.css`, `/monitor.js` | Public shell | These resources contain the sign-in UI and render no data until admin authentication. The bearer token lives in page memory and is cleared on sign-out, reload or page exit. |

All data APIs use the existing bearer roles. Browser tokens cannot read dashboard data. The extension service worker accepts reporting consent only from extension Settings and uses its own results to create events. There is no webpage message for submitting a detection. The backend caps write bodies at 512 bytes, rejects unknown fields and invalid combinations, rate-limits configured browser principals (default 60 submissions and 12 heartbeats per minute), and requires a recent heartbeat for writes. Event time may be at most five minutes old or 30 seconds ahead. The database enforces one event UUID per browser identity. Reused IDs with differing data return 409, missing heartbeats return 412, oversized requests return 413, and over-limit authenticated requests return 429.

The dashboard path sends and stores **no hostname, URL or URL hash, page content, form value, cookie, credential captured from a page, or referrer**. The configured client ID is used internally for rate limits, deduplication and fixture isolation. The existing separately enabled activity analysis still sends the hostname and bounded counts for explicitly configured sites. Dashboard reporting alone does not enable activity monitoring. The dashboard bearer authenticates the API and is never exposed as event data.

Events are filtered by server receipt age and physically purged hourly. Set `threat.monitoring.retention-days` to 1–90 days (default 14). The default H2 database is in memory, so records are lost on restart. Browser heartbeat and rate-limit state also restart with the service. The browser journal is session-only and keeps up to 256 short-lived navigation/action deduplication entries without destinations. Turning reporting off clears that journal and does not delete historical server records ahead of their configured retention.

The API authenticates a configured installation credential. A compromised credential or browser can still fabricate allowed codes within its quota. Issue a distinct token per installation, keep admin tokens separate, and rotate exposed secrets. Use a trusted HTTPS ingress for remote operation, exclude credential headers and request bodies from logging, and apply ingress limits for unauthenticated traffic. Shared rate limiting and heartbeat state are needed before deploying multiple backend replicas. Dashboard events indicate detections by the deployed rules and feed, with synthetic results tagged by server configuration. They do not validate real-world detection accuracy.

# Threat Detection

Threat Detection contains a Java 21 Spring Boot API and monitoring console, a Manifest V3 Chrome extension, a Java Swing admin client, an offline evaluation framework, and isolated ML/visual phishing research pipelines. Chrome matches exact hostnames and URL-path hashes locally against an authenticated reputation snapshot, evaluates local financial impersonation signals, and can run optional activity monitoring on configured sites. Production ML warnings, blocking, shadow testing, and visual telemetry remain disabled.

## Unified workspace and modules

- **Architecture guide:** [System architecture](docs/architecture.md)
- **Integration audit:** [Phase 6B integration report](docs/phase-6b-integration.md)

Use a repository checkout for product development. Keep private research artifacts outside Git.

See [threat intelligence ingestion](docs/threat-intelligence-ingestion.md) for the managed CERT Polska source, provider terms, signed publication, and operations. [URL reputation operations](docs/url-reputation.md) describes the browser contract and the legacy operator-file format. An instance without a current, authorized browser snapshot reports **Protection unavailable**.

The [offline evaluation guide](docs/dataset-evaluation.md) covers Phase 3A dataset provenance, held-out rule baselines, and the versioned URL feature interface. It is separate from the browser and backend.

The [Phase 3B research preflight](research/README.md) and Phases 3C–6A research directories verify the offline CPU model environment and frozen research artifacts independently of the production runtime.

| Module | Location | Current behavior |
| --- | --- | --- |
| Spring Boot REST API, rules, and `/monitor` UI | [`backend/`](backend/) | Secured API with temporary activity sessions, Flyway-migrated H2 monitoring store, and UI-1/UI-2 black-and-violet console at `/monitor`. |
| Chrome extension | [`extension/`](extension/) | MV3 extension that downloads an authenticated threat snapshot, enforces local blocks/advisories, and supports opt-in privacy-preserving reporting. |
| Swing admin client | [`admin-swing/`](admin-swing/) | Desktop client (compiles on Java 21; requires admin bearer token and updated session contract for live requests). |
| Offline evaluation harness | [`evaluation/`](evaluation/) | Dataset manifest validator, feature extractor (`url-lexical-v1`), and replay tests. |
| Offline ML and visual research | [`research/`](research/) | Phases 3B–6A offline experiments, Windows resource guard, and Phase 5G frozen-model custody preflight. Not required by production. |
| Windows lifecycle & research projection | [`scripts/`](scripts/) | DPAPI-protected local backend manager (`local.ps1`) and sanitized aggregate projector (`project-monitor-research.mjs`). |
| Documentation & experiment receipts | [`docs/`](docs/) | Operational guides, [architecture overview](docs/architecture.md), and Phases 3B–6A experiment receipts. |
| Static browser demos | [`backend/src/main/resources/static/`](backend/src/main/resources/static/) | Legacy assets retained for reference. The server disables static mappings and denies the demo routes. |

## Unified startup and test workflow

Run commands from the repository root. Production startup does not require Python or any research packages.

### Production lifecycle (Windows PowerShell 5.1 or 7)

1. Build and verify the backend JAR (set `JAVA_HOME` to Java 21 if an Oracle javapath shim or another JDK is ahead on `PATH`):
   ```powershell
   Push-Location backend
   .\mvnw.cmd clean verify
   Pop-Location
   ```
2. Load `extension/` unpacked in `chrome://extensions` (Developer mode) and copy the 32-character extension ID.
3. Provision a DPAPI-protected profile, start the backend, and check status:
   ```powershell
   $extensionId = Read-Host 'Chrome extension ID'
   .\scripts\local.ps1 -Action Setup -Profile demo -ExtensionId $extensionId -Synthetic
   .\scripts\local.ps1 -Action Start -Profile demo
   .\scripts\local.ps1 -Action Status -Profile demo
   ```
4. Retrieve credentials safely via clipboard and connect the clients:
   - Browser extension Settings (`http://127.0.0.1:8081`): `.\scripts\local.ps1 -Action CopyToken -Profile demo -Role Browser`
   - Admin dashboard (`http://127.0.0.1:8081/monitor`): `.\scripts\local.ps1 -Action CopyToken -Profile demo -Role Admin`
5. Stop the backend or rotate credentials when needed:
   ```powershell
   .\scripts\local.ps1 -Action Stop -Profile demo
   .\scripts\local.ps1 -Action Rotate -Profile demo -Role Admin
   ```

See [Windows local setup](docs/windows-local-setup.md) for live vs. synthetic profiles, H2 backup/restore, and troubleshooting.

### Verification and isolated research commands

- **Backend Maven tests:** `Push-Location backend; .\mvnw.cmd clean verify; Pop-Location`
- **Swing client compile:** `Push-Location admin-swing; .\mvnw.cmd test-compile; Pop-Location`
- **Extension unit tests:** `node --test --test-concurrency=1 extension/tests/*.test.mjs`
- **Evaluation tests:** `npm ci --prefix evaluation --ignore-scripts --offline; node --test evaluation/tests/evaluation.test.mjs`
- **Chromium smoke tests (direct & secure Windows setup):** see [Extension regression checks](#extension-regression-checks) and [Windows local setup](docs/windows-local-setup.md#verify-in-chromium).
- **Research aggregate projection check:** `node scripts/project-monitor-research.mjs`
- **Isolated research tests & Phase 5G frozen-artifact preflight:** run with the private Phase 5B CPython 3.11 environment and `research/phase3d/resource_guard.py` (see [`research/phase5g/README.md`](research/phase5g/README.md) and [`research/phase6a/README.md`](research/phase6a/README.md)).

### Outstanding acceptance gates

- **Visual reference comparison:** Compare `overview.png`, `mobile.png`, and `light.png` in `C:\Users\kj\threat-detection-experiments\ui-2-final-evidence` against the external dashboard reference image before final UI sign-off.
- **Live screen-reader speech verification:** Complete an interactive Windows desktop NVDA/Narrator speech pass across login, navigation, scopes, sorting, dialogs, research controls, and warnings (see [`UI-PROGRESS.md`](UI-PROGRESS.md)).
- **Production ML gate:** Production ML deployment remains **NO-GO** pending independent Phase 5G validation.

## Run and verify locally

For repeated local use on Windows, follow the [PowerShell 5.1 and 7 setup](docs/windows-local-setup.md). It provisions a locked-down profile with separate browser and administrator tokens, starts the loopback backend, and keeps dashboard events across restarts. The procedure below remains available for disposable manual verification.

Use **Java 21** and **PowerShell 7** from the repository root. This procedure generates disposable credentials in memory and passes only SHA-256 digests to the server. The default listener is loopback on port 8081.

```powershell
Set-Location backend
.\mvnw.cmd clean verify
```

If the build succeeds, run the following in the same shell. Choose a free port with `$env:SERVER_PORT` beforehand if port 8081 is already in use, and change `$base` to match. On macOS or Linux, use `sh ./mvnw clean verify` for the build and supply the same `SPRING_APPLICATION_JSON` configuration to the JAR.

```powershell
function New-LocalApiClient([string] $Role) {
    $bytes = [byte[]]::new(32)
    [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $token = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    $digest = [Security.Cryptography.SHA256]::HashData([Text.Encoding]::ASCII.GetBytes($token))
    @{
        Token = $token
        Settings = @{ role = $Role; 'token-sha256' = [Convert]::ToHexString($digest).ToLowerInvariant() }
    }
}

$browser = New-LocalApiClient BROWSER
$admin = New-LocalApiClient ADMIN
$env:SPRING_APPLICATION_JSON = @{
    threat = @{ security = @{
        clients = @{ 'local-browser' = $browser.Settings; 'local-admin' = $admin.Settings }
        'allowed-origins' = @('https://ops.example.test')
    } }
} | ConvertTo-Json -Depth 7 -Compress

$server = Start-Process -FilePath java -ArgumentList '-jar', 'target/threat-detection-0.0.1-SNAPSHOT.jar' -PassThru -WindowStyle Hidden
$base = 'http://127.0.0.1:8081'
$browserHeaders = @{ Authorization = "Bearer $($browser.Token)" }
$adminHeaders = @{ Authorization = "Bearer $($admin.Token)" }

try {
    $deadline = [DateTime]::UtcNow.AddSeconds(45)
    do {
        try { $health = Invoke-RestMethod "$base/api/health" -TimeoutSec 2 } catch { $health = $null }
        if ($health.status -eq 'UP') { break }
        if ($server.HasExited) { throw 'The backend exited during startup.' }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($health.status -ne 'UP') { throw 'The backend did not become healthy.' }

    # Expected 401 and 403, respectively
    (Invoke-WebRequest "$base/api/threat/logs" -SkipHttpErrorCheck).StatusCode
    (Invoke-WebRequest "$base/api/threat/logs" -Headers $browserHeaders -SkipHttpErrorCheck).StatusCode

    $session = Invoke-RestMethod "$base/api/threat/session/start" -Method Post -Headers $browserHeaders `
        -ContentType 'application/json' -Body '{"domain":"bank.example.test"}'
    $packet = @{
        sessionId = $session.sessionId; eventType = 'password_focus'
        actionType = 'sensitive_action'; pageCategory = 'sensitive_page'; formSubmitCount = 1
    }

    # Expected Safe and ALLOW
    Invoke-RestMethod "$base/api/threat/analyze" -Method Post -Headers $browserHeaders `
        -ContentType 'application/json' -Body ($packet | ConvertTo-Json -Compress) |
        Select-Object riskLevel, action

    # Expected 400 when the request includes a legacy sensitive field
    $packet.url = 'https://bank.example.test/login?fixture=synthetic#marker'
    (Invoke-WebRequest "$base/api/threat/analyze" -Method Post -Headers $browserHeaders `
        -ContentType 'application/json' -Body ($packet | ConvertTo-Json -Compress) -SkipHttpErrorCheck).StatusCode

    # Expected 200 and a summary CSV without a hostname or the rejected URL
    (Invoke-WebRequest "$base/api/threat/logs/export" -Headers $adminHeaders).Content

    # Expected 403 for an unlisted browser origin
    (Invoke-WebRequest "$base/api/threat/analyze" -Method Options -SkipHttpErrorCheck -Headers @{
        Origin = 'https://unknown.example.test'
        'Access-Control-Request-Method' = 'POST'
        'Access-Control-Request-Headers' = 'authorization, content-type'
    }).StatusCode
} finally {
    if (-not $server.HasExited) { Stop-Process -InputObject $server }
    Remove-Item Env:SPRING_APPLICATION_JSON
}
```

For manual requests with an HTTP client, see [`backend/test.http`](backend/test.http). Keep generated tokens in your local shell or private client settings.

## Connect the Chrome extension

1. In Chrome 120 or later, open `chrome://extensions`, enable **Developer mode**, and load the repository’s `extension/` directory as an unpacked extension. Copy the displayed extension ID.
2. Register a separate `BROWSER` client and its token digest in the backend configuration. Include the extension's exact `chrome-extension://<extension-id>` origin in `threat.security.allowed-origins`. Set `THREAT_REPUTATION_SNAPSHOT_PATH` to an absolute path to an authorized, current [snapshot](docs/url-reputation.md#snapshot-format). For a disposable local client, use the `New-LocalApiClient` helper from the verification block above and the configuration below. Run it from `backend/` after building the JAR.

   ```powershell
   $extensionId = Read-Host 'ID shown in chrome://extensions'
   $browser = New-LocalApiClient BROWSER
   $env:SPRING_APPLICATION_JSON = @{
       threat = @{ security = @{
           clients = @{ 'local-chrome' = $browser.Settings }
           'allowed-origins' = @("chrome-extension://$extensionId")
       } }
   } | ConvertTo-Json -Depth 7 -Compress
   $backend = Start-Process -FilePath java -ArgumentList '-jar', 'target/threat-detection-0.0.1-SNAPSHOT.jar' -PassThru -WindowStyle Hidden
   Set-Clipboard -Value $browser.Token
   ```

3. Open the extension's **Settings**, use `http://127.0.0.1:8081` for local verification, paste the browser token, and choose **Save connection**. For a remote backend, use its HTTPS origin and approve the host permission requested by Chrome. Changing the origin requires a new token for that origin.
4. Visit a website and check the popup. Add the hostname in Settings only if you also want server-side activity checks. Clearing the token makes reputation and activity checks unavailable. Pausing protection also stops local financial impersonation checks. Stop the disposable backend with `Stop-Process -InputObject $backend` when finished.

The token and snapshot are kept in trusted extension memory for the browser session. Reloading or updating the extension, or restarting Chrome, clears them. The snapshot request contains no destination. For opted-in activity monitoring, the service worker renews a session once if the backend loses it. Each such session starts with the hostname only. Analysis sends the server-issued UUID, bounded counts, and activity categories. Requests never include page URLs, paths, query strings, fragments, referrers, or form values.

Financial impersonation checks use only the hostname and run locally, including when reputation is unavailable. See the [verified domain registry, decision policy, and evaluation](docs/financial-impersonation.md).

On an unverified financial lookalike, a bounded local check can add credential-form and redirect evidence to the amber advisory. See the [financial login protection rules and evaluation](docs/financial-login-protection.md).

Confirmed host and authorized exact-path indicators can stop navigations before they reach the destination. See the [blocking policy and verification](docs/browser-protection.md).

Open `/monitor` on the backend to sign into the threat dashboard as an administrator. In extension **Settings**, opt in to **Share threat detections with this backend** to send event categories, actions and protection status without sending any site address. See [setup, API, fixture isolation, and retention](docs/threat-dashboard.md).

### Extension regression checks

Run `node --test extension/tests/*.test.mjs` from the repository root with Node.js 24.

The browser smoke test requires the built backend JAR and a separate Playwright installation. From the repository root in PowerShell 7:

```powershell
$toolPath = Join-Path ([IO.Path]::GetTempPath()) ('threat-chrome-' + [guid]::NewGuid())
npm install --prefix $toolPath playwright --no-audit --no-fund
$env:NODE_PATH = Join-Path $toolPath 'node_modules'
$env:PLAYWRIGHT_BROWSERS_PATH = Join-Path $toolPath 'browsers'
node (Join-Path $env:NODE_PATH 'playwright/cli.js') install chromium --no-shell
node extension/tests/chrome-smoke.cjs
```

It uses a disposable Chromium profile, a local login fixture, synthetic phishing, malware and impersonation indicators, and an isolated backend with separate generated browser and admin credentials. The browser resolves the synthetic sites to loopback. The test verifies that reports flow to the authenticated dashboard only after opt-in and only in the synthetic view.

## Authentication and CORS configuration

- Only `GET /api/health` and `GET /api/threat/health` are public. All other API routes require an `Authorization: Bearer <token>` header. The server does not issue authentication cookies or accept tokens from query parameters.
- Configure each client under `threat.security.clients.<client-id>` with `role` and `token-sha256`. Use one 32-byte cryptographically random, unpadded base64url token per identity. Hash the 43-character token string as ASCII and configure its lowercase SHA-256 hex digest. A duplicate digest causes startup to fail. Missing client configuration leaves every restricted route locked. Rotate a token by changing the corresponding digest and restarting the service. Maintain the client ID to preserve the existing principal’s ownership. Do not reuse an ID for a different installation.
- `BROWSER` can start sessions and submit data for its own sessions. It can read its own session, timeline, and summary. `ADMIN` can read registered sessions and use the global logs, CSV export, dashboard stats, alert actions, and admin action API. A browser receives **404** for absent or cross-owner records. An authenticated client with the wrong role receives **403**.
- Set `threat.security.allowed-origins` to exact origins with no path, query, wildcard, or trailing slash. HTTPS origins, HTTP loopback origins, and exact Chrome extension origins are supported. The default list is empty. CORS allows `GET` and `POST` with `Authorization`, `Content-Type`, and `Accept`, with credentialed CORS disabled. Origin allowlisting does not grant API access. Only allow origins you operate.
- The default server address is `127.0.0.1`. Use a trusted HTTPS ingress before exposing this API beyond loopback. Avoid recording Authorization headers, query strings, or request bodies at the ingress. H2 Console and static demo routes are disabled in every profile. `SERVER_PORT` and `SERVER_ADDRESS` override the listener settings.

## API contract and client changes

| Method and route | Input and access |
| --- | --- |
| `GET /api/threat/reputation/snapshot` | Browser bearer token. An authenticated download without query parameters, browsing data, or body. Returns `503` if a current snapshot is unavailable. |
| `POST /api/threat/session/start` | Browser bearer token. JSON with only `domain`, a hostname with DNS-style labels, up to 253 characters. Send IDNs as ASCII Punycode. Do not send a URL, port, user-agent hash, or client-supplied session ID. The API normalizes the hostname and returns a new lowercase UUID v4 in `sessionId`. Cache that returned ID and obtain a new one after a **404** for an expired or missing session. |
| `POST /api/threat/analyze`, `POST /api/threat/event` | Browser bearer token. JSON with required `sessionId` and `eventType`, plus the optional metadata below. The backend gets the hostname from the authorized session. The client must omit `domain`, `url`, `path`, `referrer`, `fieldType`, `timestamp`, and `userAgentHash`. Unknown fields and invalid types return **400**. |
| `GET /api/threat/session/{sessionId}` and its `/summary`, `/timeline` subroutes | Owner or admin bearer token. A canonical UUID v4 is required. |
| `GET /api/threat/logs`, `/logs/filtered`, `/logs/export`, `/dashboard/stats`, `/alerts`, `/alerts/latest`, `/alerts/unresolved` | Admin bearer token. Log filters accept a known risk level, a hostname fragment up to 253 ASCII characters, or plain search text up to 100 ASCII characters. CSV exports the latest 100 secured records with only IDs, scores, verdict, action, confidence, and creation time. |
| `POST /api/threat/alerts/{id}/resolve` | Admin bearer token and positive numeric alert ID. |
| `POST /api/threat/action` | Admin bearer token and JSON containing `sessionId` and one of `ALLOW`, `SHOW_WARNING`, `FORCE_RELOGIN`, or `ADMIN_ALERT`. The recorded action is an admin log entry. The domain and risk level come from the session. |

- `eventType` accepts `page_view`, `sensitive_page_visit`, `navigation_change`, `password_focus`, `form_focus`, `form_submit`, `copy_paste`, `rapid_clicking`, `tab_blur`, `tab_focus`, `heartbeat`, or `recheck_risk`.
- `actionType` accepts `normal_action` (default), `navigation`, `sensitive_action`, `behavior_anomaly`, or `session_anomaly`. `pageCategory` accepts `normal_page` (default) or `sensitive_page`.
- `redirectCount` is an integer from 0 to 100. `averageClickGapMs` is an integer from −1 to 10,000, with −1 meaning unavailable. Each of `clicksLast10Sec`, `pagesVisitedLast30Sec`, `tabSwitchCount`, `copyPasteCount`, `formSubmitCount`, and `failedActionCount` is an integer from 0 to 1,000. Counts default to zero. `deviceChanged` is a boolean that defaults to false.
- Behavior by itself can reach **Suspicious / SHOW_WARNING**, with a maximum score of 60. Only an exact host present in the current reputation snapshot can elevate backend analysis to **Critical / ADMIN_ALERT**. The backend returns a separate `reputationStatus`, and the popup describes a miss as **No known threat match**. Exact URL-path matches are evaluated only in Chrome.
- The extension uses a configured HTTPS backend origin or an HTTP loopback origin for local development. Use a separate browser token per identity. Keep admin credentials and shared credentials out of the extension package.

## Data handling and remaining release work

Full URLs, paths, referrers, user-agent hashes, and field types are rejected at the API and excluded from the new persistence model. Protected JSON risk logs retain a canonical hostname for domain triage. CSVs and application log messages omit it. Previous unowned sessions and unmarked risk or alert rows are hidden by the secured API. If an older externally managed database was used, start with a fresh secured database or purge and migrate legacy tables and backups explicitly. Java schema updates do not erase previously stored columns or data.

The local bearer registry is suitable for a controlled pilot. A public release still needs managed identity and credential lifecycle, rate limits and ingress request-size controls, durable storage with migrations and retention, and licensed threat feeds with operational monitoring. The backend uses Spring Security 7.1.3, Spring Framework 7.0.11, Tomcat 11.0.27, and Jackson 3.1.8 through Spring Boot 4.1.3. The Swing dependency set is separate.

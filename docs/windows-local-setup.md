# Windows local setup

Use Java 21, Windows PowerShell 5.1 or PowerShell 7, and Chromium or Chrome. Run the commands from the primary repository directory (`C:\Users\kj\threat-detection-system\phase-6b-system-consolidation`). The scripts run under your Windows account and bind the backend to IPv4 loopback. No Python or offline research dependencies are needed to run the production backend, `/monitor` console, or Chrome extension.

If `java.exe` on `PATH` points to an Oracle javapath shim or another JDK version, point `JAVA_HOME` and `PATH` to JDK 21 first (for example `$env:JAVA_HOME = 'C:\Program Files\Java\jdk-21'; $env:Path = "$env:JAVA_HOME\bin;$env:Path"`).

## Build and start

1. Build the backend.

   ```powershell
   Push-Location backend
   .\mvnw.cmd verify
   Pop-Location
   ```

2. Open `chrome://extensions`, enable **Developer mode**, and **Load unpacked** from this checkout’s `extension/` directory. Copy its displayed ID. Chrome assigns the unpacked ID, and the backend uses it for an exact allowed origin. The ID can change when a checkout is moved or a different build is loaded. Extension Settings also shows the ID.

3. Set up a synthetic profile and start the backend. The setup command validates the ID and generates two independent credentials.

   ```powershell
   $extensionId = Read-Host 'Chrome extension ID'
   .\scripts\local.ps1 -Action Setup -Profile demo -ExtensionId $extensionId -Synthetic
   .\scripts\local.ps1 -Action Start -Profile demo
   .\scripts\local.ps1 -Action Status -Profile demo
   ```

   Use `-Port 8082` during setup if 8081 is occupied. Choose `-RetentionDays` from 1 to 90 to override the 14-day default. Each named profile has its own keys and database. Set up a new named profile when the extension ID changes.

4. Copy the browser token with the command below. In extension **Settings**, enter `http://127.0.0.1:8081` (or your selected port), paste the token, and select **Save connection**. The backend must be reachable when adding a token. If verification fails, the extension keeps its previously saved connection. **Check connection** uses the existing reputation endpoint to test the saved settings. Paste the browser token again after restarting Chrome, and clear the clipboard once pasted.

   ```powershell
   .\scripts\local.ps1 -Action CopyToken -Profile demo -Role Browser
   ```

5. Enable **Share threat detections with this backend** in Settings. This is optional and off by default. In a separate tab open `http://127.0.0.1:8081/monitor` and paste the admin token at sign-in. Keep that token out of extension Settings.

   ```powershell
   .\scripts\local.ps1 -Action CopyToken -Profile demo -Role Admin
   ```

6. For the built-in synthetic profile, visit `http://127.0.0.1:8081/phase4b-demo-phishing` using your selected port. The local snapshot contains only that synthetic exact-path indicator and is refreshed when the backend starts. It expires after two hours. The browser warning should appear before a request reaches that path. Select **Synthetic fixtures** on the dashboard and refresh to see the block. The **Live reports** view should remain empty for this profile.

   Spring Boot serves the console with the backend build. Overview shows counts for the configured retention window. The activity charts and Threat Centre use the latest 20 events from the selected scope. Use Connected Browsers for heartbeat coverage and System Health to distinguish a storage error from an API outage. Threat Intelligence displays managed feed health. A local snapshot can provide browser protection while managed ingestion is disabled.

   Focus or select an activity point or category to inspect its value. Press Escape to dismiss the chart detail. On wide screens, **Compact navigation** switches between labeled and icon-only navigation. The laboratory diagrams describe offline research stages.

For authorized real reputation data, use a separate name and supply `-SnapshotPath 'C:\path\to\current-authorized-snapshot.json'` during setup without `-Synthetic`. For an operator-provided synthetic snapshot, use both options. Keep real and synthetic profiles separate. If no snapshot is provided for a live profile, reputation is unavailable until you set up a profile with an authorized snapshot. See the [reputation snapshot format](url-reputation.md#snapshot-format).

## Lifecycle and credential rotation

```powershell
.\scripts\local.ps1 -Action Status -Profile demo
.\scripts\local.ps1 -Action Stop -Profile demo
.\scripts\local.ps1 -Action Start -Profile demo
```

The script checks the recorded process start time and executable before stopping it. Startup checks the owning loopback listener and the public health endpoint. Inspect `backend.log` in the private profile if startup or migrations fail, or `launcher-error.log` for errors before Spring starts. The script leaves an unrelated listener running.

To replace a compromised or lost credential, stop the backend, rotate the affected role, then restart it. Copy the new token into the corresponding client. The other role keeps its credential, and existing events keep their original scope.

```powershell
.\scripts\local.ps1 -Action Stop -Profile demo
.\scripts\local.ps1 -Action Rotate -Profile demo -Role Browser
.\scripts\local.ps1 -Action Start -Profile demo
.\scripts\local.ps1 -Action CopyToken -Profile demo -Role Browser
```

Use `-Role Admin` for the dashboard token. Credentials are generated using the OS CSPRNG. The private profile stores DPAPI-protected tokens and their SHA-256 digests. Java receives only the digests. Commands print lifecycle messages and never print tokens. `CopyToken` writes one token to the Windows clipboard on request. Disable and clear clipboard history or cloud sync for a session that handles credentials, and never paste tokens into terminals, chat, or issue reports.

## Database, backup, and reset

The script defaults to a persistent embedded H2 store at `%LOCALAPPDATA%\ThreatDetection-local\<profile>\monitoring.mv.db`. It shares the profile’s user-only Windows ACL. Flyway applies and validates the versioned monitoring schema at startup. The file stores only the dashboard event fields and deduplication IDs. The existing activity/session H2 database remains in memory. Synthetic scope is stored per event. Stored detections survive restarts, while heartbeat freshness and per-client quotas start again with the new process. Fresh profiles start with empty history. Older Phase 4A records in a manually customized primary database require a separate migration. The dashboard distinguishes a reachable backend with unavailable storage from a backend outage.

- **Backup** with the profile stopped. Copy `monitoring.mv.db` into a user-only backup location outside Git. Treat that copy as retained telemetry and apply your retention policy to backups as well.
- **Restore** with the backend stopped. Move the current database to a private backup first, then copy a known-good database to `monitoring.mv.db` in the same profile and start it. Keep the profile’s original real or synthetic scope.
- **Reset** with the backend stopped. Move `monitoring.mv.db` to a private backup outside the profile, then start the backend. It creates a fresh database and empty history. Credentials are kept in a different file.
- To start the JAR manually, set `threat.monitoring.store-path` in Spring config to an absolute H2 base path without the `.mv.db` suffix. Its parent directory must exist and have restricted permissions. An unset path uses an in-memory monitoring store for disposable runs.

## Verify in Chromium

Follow the [Playwright installation steps](../README.md#extension-regression-checks), then run this from the repository root on Windows with both PowerShell versions on PATH:

```powershell
$env:THREAT_SMOKE_LOCAL_SETUP = '1'
node extension/tests/chrome-smoke.cjs
Remove-Item Env:THREAT_SMOKE_LOCAL_SETUP
```

The test uses a disposable DPAPI profile, generated loopback-only indicators, and a real Chromium extension. It checks backup restoration after deliberate corruption of that disposable database, event persistence and deduplication, role rotation, protection while offline, and fixture isolation.

Set `THREAT_UI_MATRIX=1` for layout checks across the 11 console views in both themes. Set `THREAT_MONITOR_CAPTURE_DIR` to a private directory outside Git to save screenshots. Clear `THREAT_SMOKE_LOCAL_SETUP` and rerun for the direct Chromium mode.

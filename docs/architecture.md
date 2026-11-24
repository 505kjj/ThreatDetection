# ThreatDetection System Architecture

## 1. Unified Workspace and Repository Layout

- **Antigravity Workspace:** `C:\Users\kj\threat-detection-system`
- **Primary Integrated Git Repository:** `C:\Users\kj\threat-detection-system\phase-6b-system-consolidation`
- **Development Workflow:** Future phases (starting with Phase 6C) use feature branches inside the primary repository rather than creating additional worktrees. Legacy phase worktrees and private experiment directories (`C:\Users\kj\threat-detection-experiments`) remain preserved outside the active branch flow.

| Directory | Role | Runtime / Build Stack |
| --- | --- | --- |
| [`backend/`](../backend/) | Stateless security API, behavioral rule engine, reputation ingestion, persistent monitoring store, and `/monitor` console | Java 21, Spring Boot 4.1.3, Spring Security 7.1.3, H2, Flyway |
| [`extension/`](../extension/) | Manifest V3 Chrome extension for local reputation enforcement, financial lookalike advisories, and opt-in telemetry | Chrome MV3, native ES modules, `declarativeNetRequest` |
| [`admin-swing/`](../admin-swing/) | Legacy desktop administrative client and behavioral simulator | Java 21, Maven Shade, Jackson 2.17.2 |
| [`evaluation/`](../evaluation/) | Offline dataset manifest validation, feature extraction (`url-lexical-v1`), and replay harness | Node.js 24, `csv-parse` |
| [`research/`](../research/) | Offline ML, DOM, multimodal fusion, custody, and visual brand similarity experiments (Phases 3B–6A) | CPython 3.11 (isolated venv), scikit-learn, XGBoost, PyTorch CPU, ONNX |
| [`scripts/`](../scripts/) | Windows DPAPI profile/lifecycle manager (`local.ps1`) and sanitized research summary projector (`project-monitor-research.mjs`) | PowerShell 5.1 / 7, Node.js 24 |
| [`docs/`](../docs/) | Operational guides, security policies, architecture docs, and versioned experiment reports | Markdown, JSON receipts |

## 2. Production vs. Research Isolation

Production protection and offline ML research are strictly separated:

1. **Zero Research Runtime Dependencies in Production:** Running the Spring Boot backend and Chrome extension requires only Java 21 and Chrome. Python, PyTorch, XGBoost, ONNX Runtime, raw datasets, and model weights are never loaded or invoked by the backend or production extension path.
2. **ML & Visual Protection Remain Disabled:** Production ML warnings, ML blocking, shadow testing, and visual brand telemetry are disabled (**NO-GO** pending independent Phase 5G custody validation).
3. **Sanitized Aggregate Projection:** The `/monitor` console's Financial Protection, ML Laboratory (17 cohort views), Visual Intelligence, and Dataset Laboratory read static, sanitized aggregates from [`backend/src/main/resources/monitoring/research.json`](../backend/src/main/resources/monitoring/research.json), served only to authenticated `ADMIN` callers at `GET /api/threat/monitoring/research-summary`. Regenerate this file offline with `node scripts/project-monitor-research.mjs`.

## 3. Production Runtime Architecture

### Chrome Extension (`extension/`)

- **Reputation Enforcement:** Fetches a signed/authenticated snapshot from `GET /api/threat/reputation/snapshot` into session memory (`chrome.storage.session`) without sending visited URLs. Exact host and URL-path rules are installed via `chrome.declarativeNetRequest` session rules (`block-rules.mjs`); hash-only indicators and post-navigation mismatches render the extension-owned `warning.html` interstitial bound to a tab-specific nonce.
- **Financial Impersonation Advisories:** Runs locally on hostname tokens, Punycode/Unicode confusables, and `tldts` public-suffix parsing (`impersonation.mjs`, `financial-domains.mjs`), enriched by bounded local DOM credential/payment form cues (`login-risk.mjs`) without transmitting page content or form values.
- **Optional Telemetry & Reporting:** Per-site behavioral analysis sends only a server-issued session UUID, canonical hostname (at session start), and bounded integer counts. Opt-in dashboard reporting (`threat-reporting.mjs`) sends only enumerated signals, actions, timestamps, random UUID v4 event IDs, and heartbeat status.

### Spring Boot Backend (`backend/`)

- **Authentication & Authorization (`ApiSecurityConfig`):** Opaque `43`-character base64url bearer tokens compared via constant-time SHA-256 digests (`MessageDigest.isEqual`). Separate `BROWSER` and `ADMIN` roles; exact-origin CORS; `H2` console and legacy static demo routes disabled.
- **Monitoring Storage (`monitoring/`):** Isolated embedded H2 database (`%LOCALAPPDATA%\ThreatDetection-local\<profile>\monitoring.mv.db`) managed by Flyway (`V1__create_monitoring_event.sql`), separate from the in-memory behavioral session database. Synthetic test traffic is isolated via server-configured `threat.monitoring.synthetic-clients`.
- **Console Frontend (`resources/monitoring/`):** Black-and-violet UI-1/UI-2 console served directly by Spring Boot (`/monitor`, `/monitor.css`, `/monitor.js`, plus shared `theme.css`, `icons/mark.svg`, and `fonts/inter-latin.woff2` packaged from `extension/`) with zero frontend build step.

### Secure Windows Lifecycle (`scripts/local.ps1`)

- Provisions user-only ACL directories under `%LOCALAPPDATA%\ThreatDetection-local\<profile>`.
- Generates independent `BROWSER` and `ADMIN` CSPRNG credentials, stores DPAPI-encrypted secrets (`ConvertFrom-SecureString`), and passes only SHA-256 digests to Java via `SPRING_APPLICATION_JSON`.
- Validates process ownership, executable path, start timestamp, loopback listener, and `/api/health` on start/stop/status, and supports role-specific token rotation and clipboard retrieval.

## 4. Known Pending Sign-Offs

- **Visual Reference Comparison:** Compare `overview.png`, `mobile.png`, and `light.png` in the private UI-2 evidence folder against the external dashboard reference image.
- **Live Screen-Reader Verification:** Perform interactive Windows desktop speech verification (NVDA / Narrator) across login, navigation, scope switching, table sorting, dialogs, research controls, and warnings.
- **Production ML Validation:** Production ML deployment and shadow testing remain **NO-GO** until independent Phase 5G custody datasets are scored.

# 🛡️ Generic Browser-Based Threat Detection System

A modular, privacy-safe threat detection system consisting of a **Chrome Extension**, a **Spring Boot Backend API**, and a **Java Swing Admin Dashboard**. The extension monitors user behavior on configured websites, collects **only metadata** (never passwords, OTPs, or form values), sends it to the backend for risk analysis, and displays actionable results via popup and overlay.

> The system is **fully generic** and can monitor any website. A default demo domain (`example.com`) is preconfigured as an example.

---

## Java-Centered Architecture

This project follows a **Java-centered architecture**:

| Component | Technology | Role |
|-----------|-----------|------|
| **Backend API** | Java Spring Boot | All threat analysis, risk scoring, session management, alerts, export |
| **Risk Engine** | Java (rule-based) | All risk decisions: score, trust score, level, reasons, tags, action |
| **Database Models** | Java JPA/Hibernate | H2 (dev) / PostgreSQL (prod) — sessions, events, risk logs, alerts |
| **Admin APIs** | Java REST Controllers | Logs, alerts, timeline, summary, CSV export, dashboard stats |
| **Admin Dashboard** | Java Swing | Desktop GUI with JTable, JTabbedPane — no web UI, no Electron |
| **CSV Export** | Java | Server-side CSV generation from risk log data |
| **Alert Logic** | Java | Auto-generates alerts for non-Safe risk levels, resolve via API |
| **Chrome Extension** | JavaScript (HTML/CSS/JS) | **Metadata collector only** — browser extensions require JS |

### Why JavaScript in the extension?

Chrome extensions **require** JavaScript — there is no alternative. However, the extension performs **no threat detection logic**. It only:
- Detects browser events (clicks, navigation, form focus, tab switches)
- Collects behavioral metadata (timing, counts, page categories)
- Sends metadata to the Java backend via `POST /api/threat/analyze`
- Displays the backend's response in the popup and overlay

**All decisions are made by the Java backend:**
- Risk score computation
- Trust score computation
- Risk level classification
- Reason generation
- Tag assignment
- Action determination
- Alert generation

---

## Generic Website Support

This extension is **not tied to any specific website**. A demo domain is included as a preconfigured example.

### How it works

- **Any domain can be monitored.** Users can add any website from the extension's Options page or directly from the popup.
- **The extension activates only on configured domains.** Content scripts run on all URLs but immediately check if the current domain is in the monitored sites list. If not, no tracking, no form monitoring, and no backend requests occur.
- **Sensitive paths and fields are configurable per domain.** Each monitored site has its own list of sensitive paths (e.g., `/login`, `/dashboard`) and sensitive fields (e.g., `password`, `email`). Defaults are provided when adding a new domain.
- **The backend analyzes generic behavior metadata, not website-specific data.** The risk engine evaluates click speed, navigation patterns, tab switches, form interactions, and other behavioral signals. It does not contain any domain-specific rules.
- **No passwords, OTPs, or form values are collected.** The extension only collects metadata such as field types, page paths, click timing, and event counts.

### Adding a new website

1. **From the Popup:** Visit any website → Click the extension icon → Click **"+ Monitor This Site"**
2. **From Options:** Click **⚙ Settings** → Enter a domain (e.g., `example.com`) → Click **"+ Add Domain"**

### Per-site configuration

From the Options page, each monitored site supports:
- **Enable/Disable** — temporarily pause monitoring for a specific domain
- **Edit Sensitive Paths** — customize which URL paths are considered sensitive
- **Edit Sensitive Fields** — customize which form fields trigger sensitive action events
- **Remove** — completely remove a domain from monitoring

### Domain matching

The extension uses normalized domain matching:
- `example.com` matches `example.com`, `www.example.com`, and `app.example.com`
- Domains are normalized by removing `http(s)://`, `www.`, and trailing paths

---

## Architecture

```
Chrome Extension (Manifest V3) — JavaScript metadata collector only
        ↓
Configured monitored websites (user/admin managed)
        ↓
Behavior metadata collection (clicks, navigation, form focus, tab switches...)
        ↓
POST /api/threat/analyze → Java Spring Boot Backend
        ↓
Java Modular Weighted Risk Engine (10 rules)
        ↓
H2 Database (sessions, events, risk logs, alerts)
        ↓
Extension popup / warning overlay / Java Swing admin dashboard
```

---

## Privacy

This system collects **ONLY behavioral metadata**:
- ✅ Click timing, navigation speed, tab switches, event types
- ✅ Page paths, referrers, field types (e.g., "password", "email")
- ✅ Session IDs, domains, timestamps
- ❌ **NEVER** collects: actual passwords, OTPs, card numbers, form values, medical/patient data

---

## Quick Start

### Prerequisites
- **Java 21** (required for Spring Boot backend AND Swing admin app)
- **Google Chrome** (for the extension)
- **No global Maven installation needed** — Maven Wrapper is included

### Step 1: Run Java Spring Boot Backend

#### Method A: From IntelliJ IDEA

1. Open `backend/` folder in IntelliJ IDEA
2. Wait for IntelliJ to import the Maven project from `pom.xml`
3. Open `src/main/java/com/example/threatdetection/ThreatDetectionApplication.java`
4. Click the **Run ▶** button
5. Backend starts on `http://localhost:8081`
6. Verify: open `http://localhost:8081/api/health`

#### Method B: From Terminal (Maven Wrapper)

**Windows:**
```cmd
cd backend
mvnw.cmd spring-boot:run
```

**macOS / Linux:**
```bash
cd backend
./mvnw spring-boot:run
```

**Package as JAR:**
```cmd
# Windows
mvnw.cmd clean package

# macOS / Linux
./mvnw clean package

# Run the JAR
java -jar target/threat-detection-0.0.1-SNAPSHOT.jar
```

> ⚠️ Do NOT use `mvn` — Maven is not required globally. The Maven Wrapper (`mvnw.cmd`) downloads Maven automatically on first run.

### Step 2: Run Java Swing Admin App

#### Method A: From IntelliJ IDEA

1. Open `admin-swing/` folder in IntelliJ IDEA as a separate project (or add as module)
2. Wait for IntelliJ to import the Maven project from `pom.xml`
3. Open `src/main/java/com/threatdetection/admin/AdminSwingApplication.java`
4. Click the **Run ▶** button
5. The Swing admin dashboard window opens

#### Method B: From Terminal

**Windows:**
```cmd
cd admin-swing
mvnw.cmd compile exec:java -Dexec.mainClass="com.threatdetection.admin.AdminSwingApplication"
```

Or build and run:
```cmd
cd admin-swing
mvnw.cmd clean package
java -jar target/admin-swing-1.0.0.jar
```

> The Swing app connects to `http://localhost:8081` by default. You can change the backend URL from the Dashboard tab.

### Step 3: Load Chrome Extension

1. Open Chrome → navigate to `chrome://extensions`
2. Enable **Developer Mode** (top-right toggle)
3. Click **Load unpacked**
4. Select the `extension/` folder
5. The extension icon appears in the toolbar

### Step 4: Configure & Test

1. **Add a monitored domain** from the extension popup or options page
2. **Generate behavior** by browsing the monitored website or using the **Swing Demo Simulator** tab
3. **View results** in:
   - Extension popup (risk level overlay)
   - Website overlay (warning banner)
   - Backend logs (`http://localhost:8081/api/threat/logs`)
   - **Swing admin dashboard** (all tabs)

---

## High Risk Blocking Behavior

The extension enforces real-time blocking on any monitored website based *exclusively* on the Java backend's risk decision (`riskLevel` and `action`). The extension never makes risk decisions locally.

- **Safe (`ALLOW`)**: No overlay is shown.
- **Suspicious (`SHOW_WARNING`)**: A non-blocking warning overlay appears. It alerts the user to proceed with caution but allows continued interaction with the site.
- **High Risk (`FORCE_RELOGIN`)**: A full-screen blocking overlay covers the current website, instructing the user to re-authenticate or verify their identity. All interaction with the underlying site (clicking, typing) is disabled.
- **Critical (`ADMIN_ALERT`)**: A severe, full-screen hard block is applied. The activity is instantly logged for admin review. No further interaction is possible until the session risk is cleared.

### Demo Mode Options

Demo Mode can be toggled via the extension's Settings (Options) page. 
- **Production Mode (Demo Mode OFF)**: High Risk overlays show a "Re-check Risk" button, but no close button. Critical overlays offer no user-facing dismissal option. The block remains until the backend returns a lower risk score or the session resets.
- **Demo Mode ON**: Both High Risk and Critical blocking overlays include a "Close for Demo" button, allowing presenters to easily bypass the block during demonstrations.

*Note: Blocking applies to any configured domain.*

---

## Swing Admin Dashboard

The Java Swing desktop admin app (`admin-swing/`) provides a full-featured admin interface:

| Tab | Features |
|-----|----------|
| **📊 Dashboard** | Total logs, Safe/Suspicious/High Risk/Critical counts, latest alert, backend health, configurable backend URL |
| **📋 Threat Logs** | JTable with session ID, domain, risk/trust scores, risk level, action, timestamp. Filter by risk level, search. View full details on selection. |
| **🔔 Alerts** | JTable of all alerts with resolve button. Shows alert ID, session, domain, risk score, level, message, resolved status, timestamp. |
| **📈 Session Summary** | Enter session ID → view aggregated stats: highest risk score, trust score, event counts, reasons, final action. |
| **⏱️ Timeline** | Enter session ID → chronological JTable of all risk events with scores, levels, actions, reasons. |
| **🧪 Demo Simulator** | 4 buttons (Safe/Suspicious/High Risk/Critical) that generate Java-crafted behavior JSON and POST to /api/threat/analyze. |

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/threat/analyze` | Main behavior analysis endpoint |
| `POST` | `/api/threat/session/start` | Start/resume a session |
| `POST` | `/api/threat/event` | Log a raw behavior event |
| `GET` | `/api/threat/session/{id}` | Get session details |
| `GET` | `/api/threat/session/{id}/summary` | Get session risk summary |
| `GET` | `/api/threat/session/{id}/timeline` | Get session event timeline |
| `GET` | `/api/threat/logs` | Get recent risk logs (admin) |
| `GET` | `/api/threat/logs/filtered` | Get filtered logs (riskLevel, domain, search) |
| `GET` | `/api/threat/logs/export` | Export logs as CSV |
| `GET` | `/api/threat/alerts` | Get all alerts |
| `GET` | `/api/threat/alerts/latest` | Get latest alert |
| `GET` | `/api/threat/alerts/unresolved` | Get unresolved alerts |
| `POST` | `/api/threat/alerts/{id}/resolve` | Resolve an alert |
| `GET` | `/api/threat/dashboard/stats` | Dashboard statistics |
| `POST` | `/api/threat/action` | Record admin action |
| `GET` | `/api/threat/health` | Health check (legacy) |
| `GET` | `/api/health` | Health check (primary) |

### Example: Analyze Request (Generic)

```bash
curl -X POST http://localhost:8081/api/threat/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "sessionId": "S-001",
    "domain": "example.com",
    "url": "https://example.com/login",
    "path": "/login",
    "referrer": "https://google.com",
    "redirectCount": 1,
    "eventType": "password_focus",
    "actionType": "sensitive_action",
    "pageCategory": "sensitive_page",
    "fieldType": "password",
    "averageClickGapMs": 220,
    "clicksLast10Sec": 12,
    "pagesVisitedLast30Sec": 4,
    "tabSwitchCount": 2,
    "copyPasteCount": 1,
    "formSubmitCount": 1,
    "timestamp": "2026-05-03T22:00:00"
  }'
```

---

## Risk Scoring

| Rule | Conditions | Points |
|------|-----------|--------|
| Redirect | 1 / 2 / 3+ redirects | +10 / +18 / +25 |
| Unknown Referrer | Empty on sensitive / External | +8 / +15 |
| Click Speed | Gap <250ms / 250-500ms / >15 clicks / 8-15 clicks | +20 / +12 / +20 / +10 |
| Navigation Burst | >8 pages / 4-8 pages in 30s | +15 / +8 |
| Sensitive Context | Page / password / OTP / action / event | +15 / +15 / +15 / +20 / +15 |
| Form Behavior | >3 submits / submit on sensitive | +15 / +15 |
| Tab Switching | >5 / 2-5 switches | +15 / +8 |
| Copy/Paste | >5 / >2 on sensitive | +15 / +10 |
| Failed Actions | ≥3 / 2 failures | +30 / +15 |
| Device Change | Changed fingerprint | +20 |

**Classification:** 0-30 Safe → 31-60 Suspicious → 61-90 High Risk → 91+ Critical

**Trust Score:** `trustScore = 100 - riskScore` (inverse measure of safety)

---

## Project Structure

```
ThreatDetection/
├── backend/                              ← Java Spring Boot backend
│   ├── pom.xml
│   ├── mvnw / mvnw.cmd
│   ├── .mvn/wrapper/
│   └── src/main/java/com/example/threatdetection/
│       ├── ThreatDetectionApplication.java
│       ├── config/CorsConfig.java
│       ├── controller/
│       │   ├── ThreatController.java      — Main analyze, event, health APIs
│       │   ├── SessionController.java     — Session start/get APIs
│       │   ├── LogController.java         — Log viewing, admin actions
│       │   ├── AdminController.java       — Filtered logs, timeline, summary, CSV, stats
│       │   └── AlertController.java       — Alert CRUD APIs
│       ├── dto/
│       │   ├── BehaviorRequest.java       — Behavior metadata from extension
│       │   ├── RiskResponse.java          — Risk analysis result (includes trustScore)
│       │   ├── RiskSignal.java            — Individual rule signal
│       │   ├── ActionRequest.java         — Admin action request
│       │   └── SessionStartRequest.java   — Session registration
│       ├── engine/
│       │   ├── RiskEngine.java            — Core risk evaluation orchestrator
│       │   ├── RiskLevel.java             — Risk classification enum
│       │   └── RiskAction.java            — Action determination enum
│       ├── rules/                         — 10 modular risk rules (all Java)
│       ├── model/
│       │   ├── ThreatSession.java         — Session entity
│       │   ├── BehaviorEvent.java         — Raw event entity
│       │   ├── RiskLog.java               — Risk analysis log entity (with trustScore)
│       │   └── AlertLog.java              — Alert entity
│       ├── repository/
│       │   ├── ThreatSessionRepository.java
│       │   ├── BehaviorEventRepository.java
│       │   ├── RiskLogRepository.java     — With filtering queries
│       │   └── AlertLogRepository.java
│       ├── service/
│       │   ├── ThreatAnalysisService.java — Orchestrates analysis + alert generation
│       │   ├── SessionService.java
│       │   ├── EventLoggingService.java
│       │   ├── AlertService.java          — Alert generation and resolution
│       │   ├── TimelineService.java       — Session timeline retrieval
│       │   ├── SessionSummaryService.java — Session risk aggregation
│       │   ├── CsvExportService.java      — CSV export generation
│       │   └── LogQueryService.java       — Filtered log queries + dashboard stats
│       └── legacy/
│
├── admin-swing/                           ← Java Swing admin dashboard
│   ├── pom.xml
│   └── src/main/java/com/threatdetection/admin/
│       ├── AdminSwingApplication.java     — Main entry point (JFrame + JTabbedPane)
│       ├── ApiClient.java                 — Java HttpClient wrapper for backend APIs
│       ├── DashboardPanel.java            — Stats, health, backend URL config
│       ├── ThreatLogsPanel.java           — Filterable JTable with detail view
│       ├── AlertsPanel.java               — Alert JTable with resolve button
│       ├── SessionSummaryPanel.java       — Session risk profile viewer
│       ├── TimelinePanel.java             — Chronological event JTable
│       └── DemoSimulatorPanel.java        — 4-button behavior simulator
│
├── extension/                             ← Chrome extension (JS metadata collector)
│   ├── manifest.json
│   ├── background.js
│   ├── content.js
│   ├── popup.html / popup.js
│   ├── options.html / options.js
│   ├── styles.css
│   └── icons/
│
└── README.md
```

---

## Verification Checklist

- [ ] Backend runs on `http://localhost:8081`
- [ ] Health check: `GET /api/health` returns `{"status":"UP"}`
- [ ] Swing app opens with 6 tabs
- [ ] Swing Dashboard tab shows stats and health status
- [ ] Swing Demo Simulator sends requests and shows responses
- [ ] Swing Threat Logs tab loads and filters logs
- [ ] Swing Alerts tab loads alerts and resolves them
- [ ] Swing Session Summary shows aggregated data
- [ ] Swing Timeline shows chronological events
- [ ] CSV export: `GET /api/threat/logs/export` downloads CSV
- [ ] Chrome extension still works: monitors domains, sends metadata, shows backend response
- [ ] Extension does NOT perform any risk scoring — all decisions come from Java backend

---

## Deployment

### Backend (Render / Railway)
1. Push backend folder to a Git repo
2. Set build command: `./mvnw clean package -DskipTests`
3. Set start command: `java -jar target/threat-detection-0.0.1-SNAPSHOT.jar`
4. Set environment: `SERVER_PORT=8081`
5. For production, switch from H2 to MySQL/PostgreSQL in `application.properties`

### Swing Admin App
1. Build: `cd admin-swing && mvnw.cmd clean package`
2. Run: `java -jar target/admin-swing-1.0.0.jar`
3. Update backend URL in Dashboard tab to point to your deployed API

### Extension
1. Update backend URL in extension settings to your deployed API URL
2. Package extension via Chrome → Extensions → Pack Extension
3. Or submit to Chrome Web Store

---

## Design Principles

- **Java-centered** — all core logic, scoring, alerts, export, and admin GUI are Java
- **Chrome extension is JS only because required** — it collects metadata, nothing more
- **Not tied to any specific website** — works on any domain the user configures
- **Demo domain is an example** — included as a pre-configured example, fully removable
- **Domain-configurable monitoring** — each site has independent sensitive paths, fields, and toggle
- **Generic domain matching** — supports base domains, www, and subdomains
- **No domain-specific backend rules** — risk engine evaluates behavioral metadata generically
- **Configurable backend URL** — point to any deployed backend (extension + Swing app)
- **Privacy-safe** — metadata only, never captures sensitive values

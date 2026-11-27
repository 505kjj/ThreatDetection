# Phase 8A free-tier deployment verification

The deployment branch starts at `ec7d579` from [release draft #36](https://github.com/505kjj/ThreatDetection/pull/36). Its [deployment guide](phase-8a-deployment.md) uses Vercel Hobby, Render Free and a dedicated Neon Free database. The Windows launch profile and existing Chromium extension package remain available for controlled local use.

## Local verification

| Area | Evidence |
| --- | --- |
| Static website | Vercel's project schema accepted the configuration. Two deployment tests verified the public artifact allowlist, owner-contact and HTTPS build gates, clean paths and the 404 route configuration. The public bundle serves the ten pages with no API proxy. |
| Browser and accessibility | The Chromium matrix passed 50 local website layout checks and 20 axe audits with zero automated violations. Direct and secure Windows smoke runs passed with the extracted ZIP. Each console run checked 19 surfaces across the existing accessibility and responsive exercises. |
| Maven and research | Maven verify passed. The TLS run passed all five storage tests, including the PostgreSQL test skipped in the default run. The 29 extension tests, 12 research tests and 54 frozen receipts passed. CI checks the 33 public Git receipts without private artifacts. |
| Dependencies and secrets | An OSV query on 2026-11-27 returned no matches for 95 Maven runtime coordinates. Gitleaks reported zero matches in the new release commits. Container OS advisories require a check against the built image. |
| Deployment boundaries | The Render Blueprint selects one Free service and keeps auto-deploy off. The Vercel configuration disables Git-triggered deployments. Provider URLs, privacy contact and runtime credentials are supplied through the approved deployment configuration. |

The tested extension ZIP is version 1.4.0 and weighs 168,720 bytes. SHA-256 `3e5875fdc548b32c1c49091f0a91c731b883a537687e856bed0b0af94f6a0aaf`. Runtime extension files and frozen research inputs match the release base.

### JVM sizing and persistent load

The Render profile uses a Java 21 JVM with Serial GC, a 160 MiB heap cap, one reported active CPU, a 512 KiB thread stack and a 64 MiB reserved code cache. Spring bounds the Tomcat and H2 pools and uses two direct PostgreSQL connections. The earlier TLS load from [release readiness](phase-8a-release-readiness.md) is the local reference. The current load uses 100 rounds of four writes and four reads paced at 900 ms, with one Windows JVM and a fresh PostgreSQL 17.12 TLS database. Memory is measured through JVM Native Memory Tracking and the Windows process working set. These are local measurements. Render cgroup memory, CPU throttling and Neon network and wake latency require provider-side evidence.

| Local metric | Initial profile run | Final profile run |
| --- | ---: | ---: |
| Cold JVM to healthy HTTP | 13.43 s | 15.63 s |
| JVM peak Windows working set | 331 MiB | 326 MiB |
| Heap used after load | 60 MiB | 62 MiB |
| JVM native committed memory after load | 189 MiB | 185 MiB |
| OS threads after load | 37 | 38 |
| Write median/p95/p99 | 51.84/90.46/132.04 ms | 61.16/219.87/329.46 ms |
| Dashboard read median/p95/p99 | 30.22/76.14/119.17 ms | 40.76/212.13/287.28 ms |
| Errors over 400 writes and 400 reads per run | 0 | 0 |

Chromium smoke tests ran concurrently on the final workstation pass. Earlier Phase 8A local p95 values were 81.12 ms for writes and 67.04 ms for reads. The conditions differ across runs and the figures do not isolate the effect of JVM tuning. The final profile logged 98 young and 6 full collections with a longest observed pause of 87.20 ms. The guarded total process tree, including the JVM, PostgreSQL, Maven and test driver, reached 939 MiB peak commit and used 104.20 CPU seconds during the 235.33-second session.

The final PostgreSQL run rejected the wrong password, CA and hostname at startup, applied Flyway version 1 and observed two TLS connections. An outage returned HTTP 503 in 2.04 seconds. The running backend accepted reads again in 4.60 seconds after restart began. A duplicate replay kept the total at 400. Restoring the logical backup into a fresh database preserved Flyway and reports, then retention removed the seeded expired record. The restored synthetic total was 399 and the live total remained zero.

To reproduce locally, build the JAR from `backend` with `mvnw.cmd verify`, set `THREAT_RELEASE_RENDER_PROFILE=1` and `THREAT_RELEASE_RUN_STORAGE_MAVEN=1`, and run the guarded storage exercise:

```powershell
python research/phase3d/resource_guard.py --metrics <private-resource-json> -- node scripts/verify-release-storage.cjs <private-result-json> <pg-server-bin> <pg-client-bin> <openssl-exe>
```

The runner uses the deployed JVM flags with diagnostic recording, loopback bind and a temporary local CA. The guard applies two logical CPUs to the process tree. All database records and tokens are synthetic.

## Git review path

All recorded heads of [#27](https://github.com/505kjj/ThreatDetection/pull/27) and [#29](https://github.com/505kjj/ThreatDetection/pull/29) through [#36](https://github.com/505kjj/ThreatDetection/pull/36) are ancestors of the deployment branch. The verified release base contains the current main tip `bbbaaff7`. That main tip had zero unique commits and the release base had 45 unique commits at the reconciliation check.

[PR #30](https://github.com/505kjj/ThreatDetection/pull/30) still reports `82825868` while its branch points to [`3c35fdc9`](https://github.com/505kjj/ThreatDetection/commit/3c35fdc9caccf65f9f0bd41e0615befa196ace61). The PR now links to that exact follow-up. The integration already contains the source commit through `1f2249a`, so deployment preparation has the intended Phase 6C content. GitHub's displayed head remains a review gate. Keep the draft stack and verify the reviewed aggregate against the current main tip before requesting main integration. After approval, select an integration method that preserves the existing commits and respects repository protections. Leave public deployments manual.

## Release gates

| Component | Decision | Evidence or required approval |
| --- | --- | --- |
| Windows and manual extension | **GO** for controlled local installation | Existing ZIP, local role separation, warnings, bypass, scope isolation and outage handling. |
| Vercel Hobby | **GO** for configuration, **NO-GO** for publication | Owner-approved public contact, provider authorization, actual Render URL and hosted routing checks. |
| Render Free | **NO-GO** for hosted release | Account and public URL approval, working image on Render, gateway health, memory, cold starts and exact native Chrome HTTPS permission. |
| Neon Free | **GO** for local TLS profile, **NO-GO** for hosted release | Disposable Neon account/project authorization and measured direct TLS, wake, outage and restore on the real endpoint. |
| Reputation | **GO** for controlled synthetic staging after approval | Public academic service normally starts with reputation unavailable. An authorized fixture can be mounted in a disposable staging service. Redistributing a live feed requires the appropriate rights. |
| Chrome Web Store and experimental protection | **NO-GO** | Initial distribution is manual. Experimental detection and telemetry remain disabled pending independent validation. |

Hosted end-to-end tests, provider usage and deployed Chromium screenshots are pending. Local captures are available. Live screen-reader speech and the original dashboard design reference are also pending. No cloud resource usage or hosting charges were incurred by these checks.

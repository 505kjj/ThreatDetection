# Phase 7 release readiness

## Integration

Review [PR #29](https://github.com/505kjj/ThreatDetection/pull/29) as the base integration path toward main. [PR #27](https://github.com/505kjj/ThreatDetection/pull/27) is the existing UI stack review. It provides UI sign-off evidence for #29. The remaining stack follows #30 through #35. The original 6C and 6D follow-ups and their prior cherry-picks had equivalent patches. Merge commit `1f2249a` reconciles their ancestry on #35 with an identical tree. Preserve original commits, draft review gates and existing branches.

Keep the [Windows startup workflow](windows-local-setup.md) for local evaluation. The current branch adds opt-in monitoring PostgreSQL and retains the H2 default. The Dockerfile packages the built JAR as a non-root image recipe. The workstation has neither Docker nor an installed WSL distribution. Container build, runtime, base-image provenance, networking, volume restarts and PostgreSQL connectivity remain unverified.

For a local container exercise, build the JAR with `mvnw.cmd verify` from `backend`. Set `THREAT_DOCKER_CONFIG_DIR` to a protected directory outside Git containing the Spring config-tree files for your browser and administrator client roles, token digests and exact CORS origins. For example, configured client `admin` uses files named `threat.security.clients.admin.role` and `threat.security.clients.admin.token-sha256`. From the repository root, run `docker compose config --quiet`, then `docker compose up --build -d`. Check `http://127.0.0.1:8081/api/health`, confirm the container user and role-denial matrix, and verify that synthetic records survive `docker compose restart`. The recipe binds the host port to loopback and uses a named H2 volume. Shut it down with `docker compose down` to preserve the volume. Validate PostgreSQL connectivity against a dedicated TLS-enabled server before preparing a PostgreSQL container profile. [Docker port publishing](https://docs.docker.com/engine/network/port-publishing/)

## Deterministic security product

**GO for local controlled use. NO-GO for release or public deployment.** The browser and administrator role split, reputation blocking, phishing bypass, malware no-bypass, financial advisories, consent and synthetic scope continue to rely on the existing product paths.

The review checked the Spring Security route and role matrix, bearer configuration, exact-origin CORS, dashboard CSP and referrer policy, JSON validation, per-client write quota, SQL parameter binding, secret logging configuration, extension permissions and frozen snapshot tests. The body advice now applies an 8 KiB cap to other JSON API routes alongside the existing 512-byte monitoring cap. Added coverage verifies HTTP 413 on the session, analysis, event and administrator-action routes. OSV returned no known advisory matches for 95 resolved Maven runtime coordinates on 2026-11-25. Browser tooling and container image dependencies have separate coverage. A redacted Gitleaks pass over the 34 commits from main through the ancestry reconciliation found no leaks. These checks are bounded to the inspected revisions, package versions and rule sets.

Maven passed 65 tests with a disposable PostgreSQL 17.12 server enabled. The extension passed 29 unit tests and the research suites passed 12. All 54 frozen receipt checks passed. Automated axe checks found zero violations across 19 surfaces and flagged four surfaces for manual contrast review of gradients and charts. The interface reference image and interactive screen-reader speech remain unavailable for manual UI acceptance. Docker build and deployment checks, production-like persistence recovery, and longer capacity testing remain open. [PostgreSQL setup](postgresql-monitoring.md) · [Stabilization measurements](experiments/phase7c/README.md)

## Experimental intelligent protection

**GO for isolated research. NO-GO for deployment, warnings, blocking, shadow testing and visual telemetry.** Phase 7A prepared the [custodian handoff](experiments/phase7a/custodian-handoff.md). Independent custody and an eligible forward corpus remain unavailable. No sealed labels were accessed and no independent results were scored.

The [Phase 6C report](experiments/phase6c/README.md) records synthetic browser and frozen Python parity. Local browser fixture scores establish implementation agreement only. The strictest cutoff lacks close synthetic cases. Long-running memory, broader workload coverage and neural service-worker execution remain open.

The [Phase 6D report](experiments/phase6d/README.md) records an explicit resize pipeline that clears the frozen embedding cosine gate on three fictional fixtures. Broader visual preprocessing coverage and independent recognition evidence remain open. The offline pHash, ORB and MobileNet bridge retains its limited fixture scope.

[Phase 6E](experiments/phase6e/README.md) is closed at the accepted research scope. Download and tracker assessment remain deferred. The [Phase 7B policy](experiments/phase7b/README.md) accepts isolated research observations and preserves existing authoritative decisions and bypass. Real production routing and validation remain separate gates.

## Sign-off sequence

| Review | Current decision | Evidence still needed |
| --- | --- | --- |
| Windows deterministic product | Local controlled use | Dashboard reference comparison, live screen-reader speech and normal release approval. |
| PostgreSQL monitoring | Disposable lab use | Deployed certificate validation, PostgreSQL outage recovery and verified backup and restore. |
| Container package | Configuration prepared | Image provenance and build, non-root startup, host networking, secret handling, health and restart persistence. |
| Production scale | NO-GO | Longer workload and production-like storage comparison, error behavior and per-query database timings. |
| Intelligent protection | Isolated research only | Independent intake and scoring, broader browser parity and performance, explicit activation approval. |

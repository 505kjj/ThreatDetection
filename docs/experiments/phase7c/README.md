# Phase 7C security and scalability review

## Current controls and boundaries

The existing API uses opaque bearer tokens, separate browser and administrator roles, exact-origin CORS, an allowlist of routes and deny-by-default routing. The monitoring service validates event fields, limits per-client rates, separates synthetic and real scope, deduplicates by client and event ID, and bounds retention. The monitoring repository uses a three-connection H2 pool, a two-second connection timeout, three-second query timeout, Flyway migrations and indexed scope and expiry queries. The Windows setup keeps separate DPAPI-protected browser and administrator credentials and stores dashboard events in a private H2 file. These observations describe the current implementation and do not constitute a complete security audit.

The stabilization branch adds opt-in PostgreSQL monitoring storage with a separate migration, the PostgreSQL JDBC and Flyway modules, bounded pooling and verified TLS by default. A disposable PostgreSQL 17.12 server passed migration, concurrent duplicate writes through two pools, reopen, scope separation and retention. The H2 path remains the default. PostgreSQL backup and restoration, live outage recovery and authenticated TLS against a deployed server remain open. No existing database was migrated. [PostgreSQL configuration](../../postgresql-monitoring.md)

Stabilization Maven tests passed all 65 cases with the disposable PostgreSQL server enabled. The storage suite covered H2 backup and restore and an unavailable HTTP response on a database error. The API suite verified that the new JSON body limit returns HTTP 413. Extension units passed 29 tests and Phase 6C, 6D, 6E and 7B research units passed 12. The frozen receipt checker passed all 54 checks. Grouped membership inputs are unchanged from the previous successful recomputation. The direct Chromium run checked both themes, six responsive sizes and 19 axe surfaces. It reported zero violations and four surfaces needing manual contrast review for existing gradient or chart elements.

## Bounded synthetic load

A guarded loopback test launched the existing backend with four disposable synthetic browser identities, an in-memory H2 store and four concurrent request streams. All 100 event submissions returned 204 and the synthetic dashboard returned 100. The measured submission interval was 315.87 ms, approximately 316.59 events per second, with 5.55 ms median and 36.04 ms p95 per request. This is one short run on the available workstation, below the configured per-client rate limit. It is not a sustained capacity, durability or multi-instance result. The two-CPU guard observed 17.42 seconds wall time including startup, 15.61 CPU seconds and 688,836,608 bytes peak job commit across the harness and JVM.

The stabilization harness ran three paced, eight-second stages per store using 1, 4 and 8 concurrent clients. Each stage sent two request waves per second. Results are paced throughput and request latencies on one workstation.

| H2 storage | Concurrency | Accepted / attempted | Events/s | Median ms | p95 ms | p99 ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Memory | 1 | 16 / 16 | 2.00 | 28.55 | 67.15 | 67.15 |
| Memory | 4 | 64 / 64 | 7.99 | 52.97 | 108.58 | 119.60 |
| Memory | 8 | 128 / 128 | 15.98 | 89.79 | 131.90 | 187.50 |
| File | 1 | 16 / 16 | 2.00 | 50.41 | 103.01 | 103.01 |
| File | 4 | 64 / 64 | 7.98 | 71.72 | 143.44 | 181.38 |
| File | 8 | 128 / 128 | 16.00 | 100.93 | 233.17 | 273.34 |

Each dashboard reported 208 accepted events. In a separate quota check with a fresh client, 60 requests succeeded and the 61st returned HTTP 429 for each store. Whole-job CPU and peak commit were 37.41 s and 692,719,616 B for memory and 40.27 s and 687,423,488 B for file. Each run was guarded to two logical CPUs. Per-query database latency and prolonged saturation remain unmeasured.

Reproduce after building the backend with `backend/mvnw.cmd verify`. With the Phase 5B Python environment, run `research/phase3d/resource_guard.py --metrics <new-private-resource-file> -- node research/phase7c/load.cjs <new-private-result-file> memory`. Repeat with fresh receipt paths and `file` for the durable H2 mode. The harness generates ephemeral credentials, binds to loopback, stops its own process and removes its disposable H2 profile.

## Container preparation

The root Dockerfile packages the existing built JAR with a Java 21 runtime and runs as numeric non-root user 10001. The build context excludes everything except the JAR. Docker was unavailable in this environment, so image build, runtime, base-image provenance and container security checks remain unverified. The application retains its loopback default and requires deliberate listener and port configuration for container access. Supply independent browser and administrator token digests through secured runtime configuration. Do not put plaintext tokens in the image. Local Windows startup remains documented in the existing Windows guide. Docker port publishing can bind explicitly to loopback. [Docker port publishing](https://docs.docker.com/engine/network/port-publishing/)

## Decision and remaining work

GO for local synthetic research. NO-GO for deployment readiness or public exposure. Longer load runs, PostgreSQL recovery and deployed TLS exercises, the Docker build and runtime checks, and manual accessibility acceptance remain open. The [release report](../../phase-7-release-readiness.md) separates these deterministic product gates from independent validation and experimental activation.

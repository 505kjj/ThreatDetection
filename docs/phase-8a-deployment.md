# Phase 8A deployment guide

The public site is a static build. The Spring application keeps `/monitor` and the API on a separate origin. Only the console collects an administrator bearer token. The public origin needs no API CORS entry or credentials. Use the existing [Windows launch instructions](windows-local-setup.md) for H2 and DPAPI-protected local use.

## Prepare a static website

```powershell
node website/build.mjs
node website/preview.mjs 4173
```

Open `http://127.0.0.1:4173/`. The default administrator link points to the local Windows backend. For a hosted build, set `THREAT_PUBLIC_MONITOR_URL` to your approved HTTPS dashboard URL ending in `/monitor`, then run the build into a fresh directory. The builder accepts the destination as its first argument. Publish only its output on the static host. Do not copy the repository, release test profiles, Git metadata, database files, tokens, or model artifacts to that host.

Install the response headers from [website/_headers](../website/_headers) on all website routes, including error pages. Use the host's directory index or clean URL behavior so routes such as `/demo/` resolve to their own index. Confirm `/api/threat/monitoring/dashboard` and `/monitor` return 404 on the site origin, the demo makes no remote requests, and the administrator link opens only the approved origin. Configure host log handling and publish the operator's contact and data-retention information before accepting real traffic.

## Docker build and runtime verification

Docker and WSL were unavailable on the Phase 8A workstation. Build, image inspection, health, secret mount, network and volume assertions below are commands for a compatible host.

1. On Windows, review [Docker Desktop prerequisites and terms](https://docs.docker.com/desktop/setup/install/windows-install/). Enable and update the supported WSL backend with `wsl --install` and `wsl --update` as required. Restart if Windows requests it, then install and start Docker Desktop using the official installer. Confirm `docker version`, `docker info` and `docker compose version`. On Linux, install Docker Engine and the Compose plugin from the [official platform packages](https://docs.docker.com/engine/install/).
2. Build and verify the JAR from `backend` using `mvnw.cmd verify` on Windows or `./mvnw verify` on Linux. Inspect the approved Eclipse Temurin Java 21 runtime with `docker buildx imagetools inspect docker.io/library/eclipse-temurin:21-jre`. Verify the image is from the [Docker Official Image repository](https://hub.docker.com/_/eclipse-temurin), record its manifest and target-platform digest, scan that resolved image, and set `THREAT_JAVA_BASE_IMAGE` to the approved `docker.io/library/eclipse-temurin:21-jre@sha256:<digest>`. The image recipe assumes a Bash-capable base. Use the same pinned input for verification and staging.
3. Set `THREAT_DOCKER_CONFIG_DIR` to a protected directory outside the checkout. Use config-tree files `threat.security.clients.browser.role` and `threat.security.clients.admin.role` with values `BROWSER` and `ADMIN`. Generate distinct 32-byte random base64url bearer tokens, issue them separately over an authorized channel and store only their lowercase SHA-256 hex digests in the two respective `threat.security.clients.<id>.token-sha256` files. Set `threat.security.allowed-origins[0]` to the exact `chrome-extension://<id>` of the installed test package. Use `threat.monitoring.synthetic-clients[0]` for the disposable browser client ID during synthetic verification. The app user must be able to read its mounted files. Scope every file and ACL to the operator and UID/GID 10001 as supported by the host.
4. From the repository root, run the following with a new Compose project after verifying host port 8081 is free. The repository default publishes port 8081 only on host IPv4 loopback. Verify the effective bind and absence of public access on the target Docker version.

   ```powershell
   docker compose -p threat8a-lab config --quiet
   docker compose -p threat8a-lab build --pull
   docker compose -p threat8a-lab up -d --wait
   docker compose -p threat8a-lab ps
   docker compose -p threat8a-lab exec -T backend id
   docker compose -p threat8a-lab port backend 8081
   curl.exe --fail http://127.0.0.1:8081/api/health
   docker compose -p threat8a-lab restart backend
   docker compose -p threat8a-lab up -d --wait
   docker compose -p threat8a-lab down
   ```

   Between the health check and restart, send one synthetic heartbeat and event using the browser role and inspect the synthetic dashboard with the admin role. After restart assert the total remains one, repeat the event ID after a new heartbeat and confirm the total stays one. Check the image user and health metadata with `docker inspect`, inspect mount and read-only settings, and check that credentials and configuration files are absent from image layers and environment output. Use Docker Scout or your approved scanner against the exact built image and its resolved base. Check role denials, request limits, stale snapshot handling and unauthorized origin denial. The command `down` preserves the test volume. The health probe checks JVM HTTP liveness. Storage and snapshot readiness need separate authenticated checks.

## PostgreSQL staging and recovery

Provision a disposable database and private network path for the first Compose check. Put the provider CA file and a separate app database role's credentials in the respective protected config tree. Use the [supported PostgreSQL properties](postgresql-monitoring.md). When the CA file is mounted under `/run/threat-config/`, the value of `threat.monitoring.postgres.root-certificate` is its container path. Use the certificate's DNS name in the JDBC URL and leave JDBC parameters out of it. Keep `allow-loopback-without-tls` off.

```powershell
docker compose -p threat8a-pg -f compose.yaml -f compose.postgres.yaml config --quiet
docker compose -p threat8a-pg -f compose.yaml -f compose.postgres.yaml up -d --build --wait
```

This override clears the local H2 monitoring path. The main application's short-lived activity session store remains H2. Start with the configured monitoring pool of three and budget provider connections for migration and backup tasks. Verify connections in `pg_stat_ssl`, inspect the Flyway schema history, then check monitoring read/write persistence. Test wrong credentials, a mismatched hostname and an untrusted CA on a separate disposable service. Verify outage returns an unavailable result and that the application recovers when the database returns. Keep protected logical backups or provider snapshots, restore to a different database and verify counts, scope isolation, retention and event-ID deduplication before changing the live endpoint.

Use the Windows [local startup workflow](windows-local-setup.md) and H2 for controlled workstation use. Avoid placing a PostgreSQL password in a JDBC URL, shell history, Git, process command-line arguments, dashboards or access logs. Ensure the backup retention policy and operator notices match the data handling actually deployed.

## HTTPS and access

Use the host's HTTPS edge or adapt [the Caddy example](../deploy/Caddyfile.example), with distinct approved website and backend hostnames. Only the HTTPS edge should be externally reachable. Ensure the reverse proxy preserves authorization headers without logging them, never caches authenticated API responses, rejects excess request bodies, and uses bounded timeouts and connection limits. Keep the exact extension origin in Spring CORS and require separate browser and administrator credentials. The existing monitoring limits are per process. Keep a single backend instance until shared rate-limit and session behavior is designed and tested.

If publishing a reputation snapshot is in scope, mount only an authorized snapshot or signed publication using the existing [reputation workflow](url-reputation.md). A healthy backend without an eligible current snapshot still reports protection unavailable. Preserve the API role and scope checks, verify HTTPS from Chrome with the actual extension host grant, check that stale or lost evidence remains unavailable, and exercise bypass and retry with synthetic inputs. Review the [Caddy automatic HTTPS behavior](https://caddyserver.com/docs/automatic-https) or the chosen provider's TLS configuration before enabling public routes.

## Hosting and monthly cost estimate

USD list prices and included limits checked on 2026-11-25. DNS registration, taxes, egress overages and optional backups are separate. Confirm current plan and regional limits before purchasing.

| Component | Option and monthly baseline | Technical and operational limits |
| --- | --- | --- |
| Static public site | Cloudflare Pages Free, $0 | Static requests are free and unlimited. 500 builds/month, 25 MiB per file, custom domain with managed TLS. Static files need no provisioned application CPU, RAM or database and have no app cold start. [Limits](https://developers.cloudflare.com/pages/platform/limits/) · [Static requests](https://developers.cloudflare.com/pages/functions/pricing/) · [Domains](https://developers.cloudflare.com/pages/configuration/custom-domains/) |
| Static public site | Render static, $0 plus shared workspace usage | No application compute. Hobby includes 5 GB/month bandwidth and two custom domains, with TLS. Site traffic shares the workspace allocation with a Render backend. [Pricing](https://render.com/pricing) · [Domains](https://render.com/docs/custom-domains) |
| Spring Boot preview | Render Free, $0 | 0.1 CPU, 512 MB RAM, 750 instance-hours per workspace, suspends after 15 minutes idle, and has no persistent service disk. Workspace bandwidth applies. Suitable for an approved trial with synthetic evidence. [Free service limits](https://render.com/docs/free) · [CPU and RAM](https://render.com/docs/compute-plans) |
| Spring Boot candidate | Render paid Starter or Standard, $7 or $25 | Starter 0.5 CPU and 512 MB RAM. Standard 1 CPU and 2 GB RAM. No free-tier idle suspension. Managed TLS and custom domain. Persistent disk is separately metered. Validate heap plus native memory and readiness on the actual container. [Pricing](https://render.com/pricing) · [CPU and RAM](https://render.com/docs/compute-plans) |
| Disposable PostgreSQL | Render Free or Neon Free, $0 | Render 256 MB RAM, 1 GB storage, 100 connections, expires after 30 days, and has no provider backups. Neon lists 1 GB/project, 100 CU-hours/project/month, up to 2 CU and 8 GB RAM, 5 GB public transfer/month, scale to zero, and up to 6 hours restore history. Test database wake latency before selecting a sleeping endpoint. [Render free limits](https://render.com/docs/free) · [Neon pricing](https://neon.com/pricing) · [Neon storage and restore limits](https://neon.com/blog/neon-free-plan-1-gb-per-project) |
| Durable PostgreSQL candidate | Render Basic 256 MB or Neon Launch | Render lists 0.1 CPU and 256 MB RAM at $6/month plus applicable storage at $0.30/GB and three days of paid Hobby PITR. Neon Launch is usage-billed at $0.106/CU-hour and $0.35/GB-month before history and overages. Neon lists about $15/month for an intermittent 1 GB example, up to seven days of restore history and 500 GB public transfer/month. [Render pricing](https://render.com/pricing) · [Render backups](https://render.com/docs/postgresql-backups) · [Neon pricing](https://neon.com/pricing) |

A static site on Cloudflare Pages, a Render Starter backend and a small paid Render PostgreSQL database would start at about $13–14/month before domain registration and overages. With Render Standard the same components would start at about $31–32/month. A Starter backend plus Neon's published illustrative Launch usage would be about $22/month before domain and overages. Trial infrastructure can cost $0 under the free limits while remaining subject to sleep, database retention and quota restrictions. These are estimates. The PostgreSQL certificate chain, host routing, backup operation and service performance of each candidate require staging verification.

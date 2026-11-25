# PostgreSQL monitoring storage

The monitoring repository defaults to H2. Windows DPAPI setup continues to select its private H2 file. To test PostgreSQL, provision an empty, dedicated database with a role that can create the monitoring schema objects. The opt-in runs a separate Flyway migration on that database. This setting does not move the short-lived application session store or import H2 events.

Provide the following Spring properties through the operator's protected runtime configuration. Spring config trees are suitable for mounted secrets. Keep credentials out of the JDBC URL and Git.

| Property suffix under `threat.monitoring.postgres` | Purpose |
| --- | --- |
| `jdbc-url` | Endpoint such as `jdbc:postgresql://postgres.example.test:5432/monitoring`. URL options are rejected. |
| `username`, `password` | Dedicated database role credentials. |
| `root-certificate` | Trusted CA file inside the application environment, when needed. |
| `pool-size` | Optional bounded connection pool, defaults to 3. |
| `allow-loopback-without-tls` | Disposable local test mode, accepted only with the exact IPv4 loopback host. Defaults to false. |

Leave `threat.monitoring.store-path` unset when configuring PostgreSQL. The driver defaults to certificate and hostname verification. Use a dedicated database with the expected CA, restrict server access to the application role, and confirm that certificate failures and wrong credentials fail startup. The repository sets two-second connection and three-second query timeouts, with a five-second PostgreSQL socket timeout. PostgreSQL stores receipt timestamps at microsecond precision and event timestamps at millisecond precision. Existing H2 migration checksums are preserved. [pgJDBC TLS](https://jdbc.postgresql.org/documentation/ssl/) · [Flyway PostgreSQL support](https://documentation.red-gate.com/flyway/reference/database-driver-reference/postgresql-database)

On a disposable IPv4 loopback PostgreSQL server, set `THREAT_TEST_POSTGRES_URL` to its `/postgres` database, and provide `THREAT_TEST_POSTGRES_USER` and `THREAT_TEST_POSTGRES_PASSWORD` privately. Run `mvnw.cmd -Dtest=MonitoringStorageTests test` from `backend`. The test requires an empty database and verifies migration, competing inserts through two pools, repository reopen, scope separation and expiry. Use separate operator backups and a verified restore on an empty target before planning a data migration. A PostgreSQL backup and restore, live network recovery and authenticated TLS against a deployed server remain release checks.

To return to the Windows profile, remove the PostgreSQL properties and start with the existing H2 configuration. Keep the original H2 file and credentials in their private location. Coordinate data migration, release and distributed limits separately. The per-client rate and heartbeat state remains local to each application process.

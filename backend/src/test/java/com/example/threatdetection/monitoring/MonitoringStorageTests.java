package com.example.threatdetection.monitoring;

import com.zaxxer.hikari.HikariConfig;
import com.example.threatdetection.config.ApiSecurityProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Executors;

import static com.example.threatdetection.monitoring.MonitoringSignal.Action.BLOCKED;
import static com.example.threatdetection.monitoring.MonitoringSignal.PHISHING;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class MonitoringStorageTests {
    @TempDir
    Path folder;

    @Test
    void versionedStoreReopensWithItsEventsAndRejectsDuplicateIds() throws Exception {
        var profile = properties(folder.resolve("monitoring").toString());
        Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        var event = new MonitoringEvent("synthetic", UUID.randomUUID(), now, now, true, PHISHING, BLOCKED);
        var first = new MonitoringEventRepository(profile);
        try {
            first.save(event);
        } finally {
            first.close();
        }
        Files.copy(folder.resolve("monitoring.mv.db"), folder.resolve("restored.mv.db"));
        var restored = new MonitoringEventRepository(properties(folder.resolve("restored").toString()));
        try {
            assertThat(restored.findByClientIdAndEventId(event.clientId(), event.eventId())).contains(event);
        } finally {
            restored.close();
        }
        var restarted = new MonitoringEventRepository(profile);
        try {
            assertThat(restarted.recent(true, now)).containsExactly(event);
            assertThat(restarted.recent(false, now)).isEmpty();
            assertThatThrownBy(() -> restarted.save(event)).isInstanceOf(DataIntegrityViolationException.class);
            restarted.purge(now.plusSeconds(1));
            assertThat(restarted.recent(true, now)).isEmpty();
        } finally {
            restarted.close();
        }
    }

    @Test
    void missingOrMalformedStorePathFailsClosed() {
        assertThatThrownBy(() -> new MonitoringEventRepository(properties("relative")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new MonitoringEventRepository(properties(folder.resolve("missing/db").toString())))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new MonitoringEventRepository(properties(folder.resolve("monitoring;IGNORECASE=TRUE").toString())))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void databaseFailureYieldsUnavailableWithoutFabricatedTotalsOrDatabaseDetails() throws Exception {
        var settings = properties(null);
        var repository = new MonitoringEventRepository(settings);
        repository.close();
        var service = new MonitoringService(repository, settings, new ApiSecurityProperties(null, null));
        MockMvcBuilders.standaloneSetup(new MonitoringController(service)).build()
                .perform(get("/api/threat/monitoring/dashboard"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(header().string("X-Threat-Monitoring-Status", "storage-unavailable"))
                .andExpect(content().string(""));
    }

    private static MonitoringProperties properties(String path) {
        return new MonitoringProperties(14, 60, Set.of(), path, null);
    }

    @Test
    void postgresUsesVerifiedTlsAndRejectsAmbiguousOrUnsafeConfiguration() {
        var pool = new HikariConfig();
        var secure = new MonitoringProperties.Postgres("jdbc:postgresql://postgres.example.test:5432/monitoring",
                "monitor", "fixture-secret", "fixture-ca.pem", false, 4);
        MonitoringEventRepository.configurePostgres(pool, null, secure);
        assertThat(pool.getDataSourceProperties()).containsEntry("sslmode", "verify-full")
                .containsEntry("sslrootcert", "fixture-ca.pem").containsEntry("gssEncMode", "disable");
        assertThat(pool.getMaximumPoolSize()).isEqualTo(4);
        assertThat(secure.toString()).doesNotContain("fixture-secret");
        assertThatThrownBy(() -> MonitoringEventRepository.configurePostgres(pool, "existing-store", secure))
                .isInstanceOf(IllegalArgumentException.class);
        for (String url : Set.of("jdbc:postgresql://postgres.example.test/db",
                "jdbc:postgresql://127.0.0.1/db?sslmode=disable")) {
            var unsafe = new MonitoringProperties.Postgres(url, "monitor", "fixture-secret", null, true, 3);
            assertThatThrownBy(() -> MonitoringEventRepository.configurePostgres(pool, null, unsafe))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    @EnabledIfEnvironmentVariable(named = "THREAT_TEST_POSTGRES_URL",
            matches = "jdbc:postgresql://(127[.]0[.]0[.]1|localhost):[0-9]+/postgres")
    void postgresMigrationConcurrentDuplicatePersistenceAndRetention() throws Exception {
        String ca = System.getenv("THREAT_TEST_POSTGRES_CA");
        var config = new MonitoringProperties.Postgres(System.getenv("THREAT_TEST_POSTGRES_URL"),
                System.getenv("THREAT_TEST_POSTGRES_USER"), System.getenv("THREAT_TEST_POSTGRES_PASSWORD"), ca, ca == null, 3);
        var profile = new MonitoringProperties(14, 60, Set.of(), null, config);
        Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        var event = new MonitoringEvent("phase7-test", UUID.randomUUID(), now, now, true, PHISHING, BLOCKED);
        var first = new MonitoringEventRepository(profile);
        var second = new MonitoringEventRepository(profile);
        try (var workers = Executors.newFixedThreadPool(2)) {
            assertThat(first.countActions(true, Instant.EPOCH)).isEmpty();
            assertThat(first.countActions(false, Instant.EPOCH)).isEmpty();
            var writes = workers.invokeAll(java.util.List.of(
                    () -> insertOnce(first, event), () -> insertOnce(second, event)));
            assertThat(writes.getFirst().get()).isNotEqualTo(writes.getLast().get());
        } finally {
            second.close();
            first.close();
        }
        var restarted = new MonitoringEventRepository(profile);
        try {
            assertThat(restarted.findByClientIdAndEventId(event.clientId(), event.eventId())).contains(event);
            assertThat(restarted.recent(true, now)).contains(event);
            assertThat(restarted.recent(false, now)).doesNotContain(event);
            restarted.purge(now.plusSeconds(1));
            assertThat(restarted.findByClientIdAndEventId(event.clientId(), event.eventId())).isEmpty();
        } finally {
            restarted.close();
        }
    }

    private static boolean insertOnce(MonitoringEventRepository repository, MonitoringEvent event) {
        try {
            repository.save(event);
            return true;
        } catch (DataIntegrityViolationException duplicate) {
            return false;
        }
    }
}

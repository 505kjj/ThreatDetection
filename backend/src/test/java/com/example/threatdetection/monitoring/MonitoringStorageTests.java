package com.example.threatdetection.monitoring;

import com.example.threatdetection.config.ApiSecurityProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;
import java.util.UUID;

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
    void versionedStoreReopensWithItsEventsAndRejectsDuplicateIds() {
        var profile = properties(folder.resolve("monitoring").toString());
        Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        var event = new MonitoringEvent("synthetic", UUID.randomUUID(), now, now, true, PHISHING, BLOCKED);
        var first = new MonitoringEventRepository(profile);
        try {
            first.save(event);
        } finally {
            first.close();
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
        return new MonitoringProperties(14, 60, Set.of(), path);
    }
}

package com.example.threatdetection.reputation;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.MockMvcPrint;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:h2:mem:managed-reputation",
        "threat.reputation.ingestion.enabled=true",
        "threat.reputation.ingestion.browser-distribution-approved=true",
        "threat.reputation.ingestion.initial-delay=PT30M",
        "threat.reputation.reload-interval=PT30M"
})
@AutoConfigureMockMvc(print = MockMvcPrint.NONE)
@Import(ManagedReputationIntegrationTests.SyntheticFeedConfig.class)
class ManagedReputationIntegrationTests {
    private static final String BASE = "/api/threat/reputation";
    private static final String ADMIN = token();
    private static final String BROWSER = token();
    private static final Path PATH = snapshotPath();
    private static final String KEY = PublishedSnapshotStoreTests.key();
    @Autowired private MockMvc mvc;
    @Autowired private ReputationIngestor ingestor;
    @Autowired private FixtureFeed feed;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry settings) {
        settings.add("threat.reputation.snapshot-path", PATH::toString);
        settings.add("threat.reputation.ingestion.signing-key", () -> KEY);
        settings.add("threat.security.clients.fixture-admin.role", () -> "ADMIN");
        settings.add("threat.security.clients.fixture-admin.token-sha256", () -> FixtureReputationProvider.sha256(ADMIN));
        settings.add("threat.security.clients.fixture-browser.role", () -> "BROWSER");
        settings.add("threat.security.clients.fixture-browser.token-sha256", () -> FixtureReputationProvider.sha256(BROWSER));
    }

    @Test
    void publishesSyntheticIndicatorsAndRetainsThemAcrossFailedUpdates() throws Exception {
        mvc.perform(get(BASE + "/feed-status")).andExpect(status().isUnauthorized());
        mvc.perform(get(BASE + "/feed-status").header(HttpHeaders.AUTHORIZATION, bearer(BROWSER)))
                .andExpect(status().isForbidden());
        mvc.perform(get(BASE + "/feed-status").header(HttpHeaders.AUTHORIZATION, bearer(ADMIN)))
                .andExpect(status().isOk()).andExpect(jsonPath("$.dataState").value("MISSING"));
        mvc.perform(get(BASE + "/snapshot").header(HttpHeaders.AUTHORIZATION, bearer(BROWSER)))
                .andExpect(status().isServiceUnavailable());

        feed.sourceTime = Instant.now().truncatedTo(ChronoUnit.SECONDS).minusSeconds(2);
        ingestor.update();
        byte[] initial = Files.readAllBytes(PATH);
        String version = ingestor.status().version();
        Instant expiry = ingestor.status().expiresAt();
        mvc.perform(get(BASE + "/snapshot").header(HttpHeaders.AUTHORIZATION, bearer(BROWSER)))
                .andExpect(status().isOk()).andExpect(jsonPath("$.entries[0].value").value("fixture.example.test"))
                .andExpect(jsonPath("$.hmacSha256").doesNotExist());
        mvc.perform(get(BASE + "/feed-status").header(HttpHeaders.AUTHORIZATION, bearer(ADMIN)))
                .andExpect(status().isOk()).andExpect(jsonPath("$.pollState").value("AVAILABLE"))
                .andExpect(jsonPath("$.publishedIndicators").value(1))
                .andExpect(jsonPath("$.providerAvailable").value(true))
                .andExpect(content().string(not(containsString("fixture.example.test"))));
        feed.available = false;
        ingestor.update();
        assertThat(Files.readAllBytes(PATH)).isEqualTo(initial);
        assertThat(ingestor.status().version()).isEqualTo(version);
        assertThat(ingestor.status().expiresAt()).isEqualTo(expiry);
        mvc.perform(get(BASE + "/feed-status").header(HttpHeaders.AUTHORIZATION, bearer(ADMIN)))
                .andExpect(status().isOk()).andExpect(jsonPath("$.pollState").value("FEED_FAILED"))
                .andExpect(jsonPath("$.providerAvailable").value(false))
                .andExpect(jsonPath("$.dataState").value("CURRENT"))
                .andExpect(jsonPath("$.failedPolls").value(1));
        mvc.perform(get(BASE + "/snapshot").header(HttpHeaders.AUTHORIZATION, bearer(BROWSER)))
                .andExpect(status().isOk()).andExpect(jsonPath("$.entries[0].value").value("fixture.example.test"));

        feed.available = true;
        feed.sourceTime = feed.sourceTime.minusSeconds(1);
        ingestor.update();
        assertThat(ingestor.status().pollState()).isEqualTo(ReputationIngestor.PollState.PUBLISH_FAILED);
        assertThat(Files.readAllBytes(PATH)).isEqualTo(initial);
        feed.sourceTime = feed.sourceTime.plusSeconds(1);
        Files.writeString(PATH, "externally corrupted snapshot");
        ingestor.update();
        assertThat(ingestor.status().version()).isEqualTo(version);
        assertThat(Files.readAllBytes(PATH)).isEqualTo(initial);
    }

    private static String bearer(String token) {
        return "Bearer " + token;
    }

    private static String token() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static Path snapshotPath() {
        try {
            Path folder = Files.createTempDirectory("managed-reputation-fixture-");
            folder.toFile().deleteOnExit();
            Path file = folder.resolve("published.json");
            file.toFile().deleteOnExit();
            return file;
        } catch (IOException failure) {
            throw new UncheckedIOException(failure);
        }
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class SyntheticFeedConfig {
        @Bean
        @Primary
        FixtureFeed syntheticFeed() {
            return new FixtureFeed();
        }
    }

    static class FixtureFeed implements ThreatFeed {
        private boolean available = true;
        private Instant sourceTime;

        @Override
        public Result fetch(Instant now) throws IOException {
            if (!available) throw new IOException("Synthetic outage");
            byte[] data = ("1\tfixture.example.test\t" + now.minusSeconds(3600) + "\t\n")
                    .getBytes(StandardCharsets.UTF_8);
            return CertPolskaFeed.parse(data, sourceTime, now);
        }
    }
}

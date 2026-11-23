package com.example.threatdetection.reputation;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.time.Instant;
import java.security.SecureRandom;
import java.util.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.MockMvcPrint;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {"spring.datasource.url=jdbc:h2:mem:reputation-regression",
        "threat.reputation.reload-interval=PT0.1S"})
@AutoConfigureMockMvc(print = MockMvcPrint.NONE)
class ReputationIntegrationTests {
    private static final String API = "/api/threat";
    private static final String SNAPSHOT_API = API + "/reputation/snapshot";
    private static final Path SNAPSHOT = temporarySnapshot();
    private static final String BROWSER = testToken();
    private static final String ADMIN = testToken();

    @Autowired private MockMvc mvc;
    @Autowired private JsonMapper json;
    @Autowired private ReputationService reputation;

    @DynamicPropertySource
    static void configuration(DynamicPropertyRegistry properties) {
        properties.add("threat.reputation.snapshot-path", SNAPSHOT::toString);
        properties.add("threat.security.clients.browser.role", () -> "BROWSER");
        properties.add("threat.security.clients.browser.token-sha256", () -> FixtureReputationProvider.sha256(BROWSER));
        properties.add("threat.security.clients.admin.role", () -> "ADMIN");
        properties.add("threat.security.clients.admin.token-sha256", () -> FixtureReputationProvider.sha256(ADMIN));
    }

    @BeforeEach
    void loadFixture() throws Exception {
        var current = new FixtureReputationProvider(Instant.now().minusSeconds(1), Instant.now().plusSeconds(60))
                .current().orElseThrow();
        publish(json.writeValueAsString(current));
        await().atMost(Duration.ofSeconds(5)).until(() -> reputation.snapshot().filter(current::equals).isPresent());
    }

    @Test
    void servesOneDestinationFreeSnapshotOnlyToBrowserCredentials() throws Exception {
        mvc.perform(get(SNAPSHOT_API)).andExpect(status().isUnauthorized());
        mvc.perform(get(SNAPSHOT_API).header(HttpHeaders.AUTHORIZATION, bearer(ADMIN))).andExpect(status().isForbidden());
        mvc.perform(get(SNAPSHOT_API).header(HttpHeaders.AUTHORIZATION, bearer(BROWSER)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.entries[0].kind").value("HOST"))
                .andExpect(jsonPath("$.entries[1].kind").value("URL_SHA256"))
                .andExpect(jsonPath("$.entries[1].value").value(FixtureReputationProvider.sha256(FixtureReputationProvider.MALWARE_PATH)));
        mvc.perform(get(SNAPSHOT_API + "?url=https://private.example.test")
                        .header(HttpHeaders.AUTHORIZATION, bearer(BROWSER)))
                .andExpect(status().isBadRequest()).andExpect(content().string(""));
    }

    @Test
    void integratesExactHostReputationAndKeepsBehaviorUnconfirmed() throws Exception {
        evaluate(FixtureReputationProvider.PHISH, "")
                .andExpect(jsonPath("$.reputationStatus").value("CONFIRMED_MALICIOUS"))
                .andExpect(jsonPath("$.riskLevel").value("Critical"))
                .andExpect(jsonPath("$.action").value("ADMIN_ALERT"));
        evaluate(FixtureReputationProvider.SAFE, ",\"redirectCount\":3,\"clicksLast10Sec\":25")
                .andExpect(jsonPath("$.reputationStatus").value("SUSPICIOUS_UNCONFIRMED"))
                .andExpect(jsonPath("$.action").value("SHOW_WARNING"));
        evaluate("shared.example.test", "")
                .andExpect(jsonPath("$.reputationStatus").value("NO_KNOWN_MATCH"))
                .andExpect(jsonPath("$.riskLevel").value("Safe"));
    }

    @Test
    void invalidProviderDataBecomesUnavailableWithoutEchoingIt() throws Exception {
        publish("{\"private-marker\":\"https://private.example.test/?private=secret\"}");
        await().atMost(Duration.ofSeconds(5)).until(() -> reputation.snapshot().isEmpty());
        mvc.perform(get(SNAPSHOT_API).header(HttpHeaders.AUTHORIZATION, bearer(BROWSER)))
                .andExpect(status().isServiceUnavailable()).andExpect(content().string(""));
        evaluate(FixtureReputationProvider.PHISH, "")
                .andExpect(jsonPath("$.reputationStatus").value("UNAVAILABLE"))
                .andExpect(jsonPath("$.action").value("ALLOW"));
    }

    private ResultActions evaluate(String host, String fields) throws Exception {
        String response = mvc.perform(post(API + "/session/start").header(HttpHeaders.AUTHORIZATION, bearer(BROWSER))
                        .contentType(MediaType.APPLICATION_JSON).content("{\"domain\":\"%s\"}".formatted(host)))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        String id = json.readTree(response).path("sessionId").asText();
        assertThat(id).isNotBlank();
        return mvc.perform(post(API + "/analyze").header(HttpHeaders.AUTHORIZATION, bearer(BROWSER))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"sessionId\":\"%s\",\"eventType\":\"password_focus\"%s}".formatted(id, fields)))
                .andExpect(status().isOk());
    }

    private static void publish(String contents) throws IOException {
        Path next = Files.createTempFile(SNAPSHOT.getParent(), "next-reputation-", ".json");
        try {
            Files.writeString(next, contents);
            Files.move(next, SNAPSHOT, StandardCopyOption.REPLACE_EXISTING);
        } finally {
            Files.deleteIfExists(next);
        }
    }

    private static String bearer(String token) {
        return "Bearer " + token;
    }

    private static String testToken() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static Path temporarySnapshot() {
        try {
            Path path = Files.createTempFile("reputation-fixture-", ".json");
            path.toFile().deleteOnExit();
            return path;
        } catch (IOException failure) {
            throw new UncheckedIOException(failure);
        }
    }
}

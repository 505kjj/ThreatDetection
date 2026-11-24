package com.example.threatdetection.monitoring;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.MockMvcPrint;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import tools.jackson.databind.json.JsonMapper;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {"spring.datasource.url=jdbc:h2:mem:monitoring-regression",
        "threat.monitoring.retention-days=7", "threat.monitoring.events-per-minute=4"})
@AutoConfigureMockMvc(print = MockMvcPrint.NONE)
@ExtendWith(OutputCaptureExtension.class)
class MonitoringApiTests {
    private static final String API = "/api/threat/monitoring";
    private static final String ADMIN = token();
    private static final String TEST_BROWSER = token();
    private static final String LIVE_BROWSER = token();
    private static final String LIMITED_BROWSER = token();
    private static final String INVALID_BROWSER = token();

    @Autowired MockMvc mvc;
    @Autowired JsonMapper json;
    @Autowired MonitoringEventRepository events;
    @Autowired MonitoringService service;

    @DynamicPropertySource
    static void configuration(DynamicPropertyRegistry config) {
        client(config, "ops", "ADMIN", ADMIN);
        client(config, "fixture", "BROWSER", TEST_BROWSER);
        client(config, "live", "BROWSER", LIVE_BROWSER);
        client(config, "limited", "BROWSER", LIMITED_BROWSER);
        client(config, "validation", "BROWSER", INVALID_BROWSER);
        config.add("threat.monitoring.synthetic-clients[0]", () -> "fixture");
    }

    @BeforeEach
    void clearEvents() {
        events.purge(Instant.now().plus(1, ChronoUnit.DAYS));
    }

    @Test
    void shellDoesNotContainDataAndApisEnforceDistinctRoles() throws Exception {
        mvc.perform(get("/monitor")).andExpect(status().isOk())
                .andExpect(header().string("Content-Security-Policy", containsString("frame-ancestors 'none'")));
        mvc.perform(get("/admin.html")).andExpect(status().isUnauthorized());
        mvc.perform(get(API + "/dashboard").param("access_token", ADMIN)).andExpect(status().isUnauthorized());
        mvc.perform(auth(get(API + "/dashboard"), LIVE_BROWSER)).andExpect(status().isForbidden());
        mvc.perform(auth(get(API + "/dashboard").param("scope", "bogus"), ADMIN)).andExpect(status().isBadRequest());
        mvc.perform(auth(get(API + "/dashboard"), ADMIN)).andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", containsString("no-store")))
                .andExpect(header().doesNotExist("Set-Cookie"));
        for (String route : new String[]{"heartbeat", "events"}) {
            mvc.perform(post(API + "/" + route)).andExpect(status().isUnauthorized());
            mvc.perform(auth(post(API + "/" + route), ADMIN)).andExpect(status().isForbidden());
        }
    }

    @Test
    void acceptsMinimumEvidenceAndSeparatesSyntheticFromLiveEvents() throws Exception {
        heartbeat(TEST_BROWSER, "REPUTATION_UNAVAILABLE");
        heartbeat(LIVE_BROWSER, "REPUTATION_AVAILABLE");
        Map<String, String> live = event("MALWARE", "BLOCKED");
        Map<String, String> fixture = event("REGISTERED_HOMOGRAPH", "WARNED");
        mvc.perform(write("events", TEST_BROWSER, fixture)).andExpect(status().isNoContent());
        mvc.perform(write("events", LIVE_BROWSER, live)).andExpect(status().isNoContent());
        mvc.perform(write("events", LIVE_BROWSER, event("PHISHING", "BYPASSED"))).andExpect(status().isNoContent());
        mvc.perform(auth(get(API + "/dashboard"), ADMIN))
                .andExpect(jsonPath("$.synthetic").value(false))
                .andExpect(jsonPath("$.total").value(1))
                .andExpect(jsonPath("$.blocked").value(1))
                .andExpect(jsonPath("$.bypassed").value(1))
                .andExpect(jsonPath("$.categories.FINANCIAL_IMPERSONATION").value(0))
                .andExpect(jsonPath("$.clientStatus.REPUTATION_AVAILABLE").value(1))
                .andExpect(jsonPath("$.recent[1].action").value("BLOCKED"))
                .andExpect(jsonPath("$.recent[1].source").value("REPUTATION"))
                .andExpect(jsonPath("$.recent[1].severity").value("HIGH"))
                .andExpect(jsonPath("$.recent[1].clientId").doesNotExist());
        mvc.perform(auth(get(API + "/dashboard").param("scope", "SYNTHETIC"), ADMIN))
                .andExpect(jsonPath("$.synthetic").value(true))
                .andExpect(jsonPath("$.total").value(1))
                .andExpect(jsonPath("$.warned").value(1))
                .andExpect(jsonPath("$.clientStatus.REPUTATION_UNAVAILABLE").value(1))
                .andExpect(jsonPath("$.recent[0].reason").value(containsString("Unicode")))
                .andExpect(jsonPath("$.recent[0].eventId").doesNotExist());
    }

    @Test
    void rejectsPrivateFieldsOversizedBodiesUntrustedLabelsAndInvalidActions(CapturedOutput logs) throws Exception {
        heartbeat(INVALID_BROWSER, "REPUTATION_AVAILABLE");
        var valid = json.writeValueAsString(event("SUBDOMAIN_BRAND", "WARNED"));
        for (String field : new String[]{"url", "hostname", "query", "cookie", "reason", "clientId", "synthetic"}) {
            var payload = valid.replaceFirst("\\{", "{\"" + field + "\":\"private-fixture-marker\",");
            mvc.perform(writeRaw("events", INVALID_BROWSER, payload)).andExpect(status().isBadRequest());
        }
        mvc.perform(writeRaw("events", INVALID_BROWSER, valid + " ".repeat(513)))
                .andExpect(status().is(413));
        mvc.perform(writeRaw("events", INVALID_BROWSER, "{}")).andExpect(status().isBadRequest());
        mvc.perform(write("events", INVALID_BROWSER, event("SUBDOMAIN_BRAND", "BLOCKED")))
                .andExpect(status().isBadRequest());
        mvc.perform(write("events", INVALID_BROWSER, event("MALWARE", "BYPASSED")))
                .andExpect(status().isBadRequest());
        mvc.perform(write("events", INVALID_BROWSER, event("MADE_UP_SOURCE", "WARNED")))
                .andExpect(status().isBadRequest());
        mvc.perform(write("events", INVALID_BROWSER,
                event("PHISHING", "BLOCKED", Instant.now().minusSeconds(600))))
                .andExpect(status().isBadRequest());
        assertThat(events.countActions(false, Instant.EPOCH)).isEmpty();
        assertThat(logs.getAll()).doesNotContain("private-fixture-marker", INVALID_BROWSER);
    }

    @Test
    void heartbeatRequiredAndPerBrowserWritesAreBoundedAndIdempotent() throws Exception {
        var event = event("PHISHING", "BLOCKED");
        mvc.perform(write("events", LIMITED_BROWSER, event)).andExpect(status().isPreconditionFailed());
        heartbeat(LIMITED_BROWSER, "REPUTATION_AVAILABLE");
        mvc.perform(write("events", LIMITED_BROWSER, event)).andExpect(status().isNoContent());
        mvc.perform(write("events", LIMITED_BROWSER, event)).andExpect(status().isNoContent());
        var conflicting = new java.util.HashMap<>(event);
        conflicting.put("signal", "MALWARE");
        mvc.perform(write("events", LIMITED_BROWSER, conflicting)).andExpect(status().isConflict());
        mvc.perform(write("events", LIMITED_BROWSER, event("PHISHING", "BLOCKED")))
                .andExpect(status().isTooManyRequests());
        assertThat(events.countActions(false, Instant.EPOCH)).extracting(MonitoringEventRepository.Count::total).containsExactly(1L);
    }

    @Test
    void expiredEventsAreHiddenThenPurged() throws Exception {
        Instant expired = Instant.now().minus(8, ChronoUnit.DAYS);
        events.save(new MonitoringEvent("fixture", UUID.randomUUID(), expired, expired, true,
                MonitoringSignal.MALWARE, MonitoringSignal.Action.BLOCKED));
        mvc.perform(auth(get(API + "/dashboard").param("scope", "SYNTHETIC"), ADMIN))
                .andExpect(jsonPath("$.total").value(0))
                .andExpect(jsonPath("$.recent").isEmpty());
        service.purgeExpired();
        assertThat(events.countActions(true, Instant.EPOCH)).isEmpty();
    }

    private void heartbeat(String credential, String protection) throws Exception {
        mvc.perform(write("heartbeat", credential, Map.of("protection", protection))).andExpect(status().isNoContent());
    }

    private Map<String, String> event(String signal, String action) {
        return event(signal, action, Instant.now());
    }

    private Map<String, String> event(String signal, String action, Instant now) {
        String at = new java.time.format.DateTimeFormatterBuilder().appendInstant(3).toFormatter().format(now);
        return Map.of("id", UUID.randomUUID().toString(), "signal", signal, "action", action, "detectedAt", at);
    }

    private MockHttpServletRequestBuilder write(String route, String credential, Map<String, String> body) {
        return writeRaw(route, credential, json.writeValueAsString(body));
    }

    private MockHttpServletRequestBuilder writeRaw(String route, String credential, String body) {
        return auth(post(API + "/" + route), credential).contentType(MediaType.APPLICATION_JSON).content(body);
    }

    private static MockHttpServletRequestBuilder auth(MockHttpServletRequestBuilder request, String credential) {
        return request.header("Authorization", "Bearer " + credential);
    }

    private static String token() {
        byte[] value = new byte[32];
        new SecureRandom().nextBytes(value);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private static void client(DynamicPropertyRegistry config, String id, String role, String token) {
        String base = "threat.security.clients." + id;
        config.add(base + ".role", () -> role);
        config.add(base + ".token-sha256", () -> {
            try {
                return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                        .digest(token.getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
            } catch (java.security.NoSuchAlgorithmException ex) {
                throw new IllegalStateException(ex);
            }
        });
    }
}

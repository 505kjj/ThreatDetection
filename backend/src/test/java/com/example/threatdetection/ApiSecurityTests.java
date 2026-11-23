package com.example.threatdetection;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.MockMvcPrint;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import tools.jackson.databind.json.JsonMapper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = "spring.datasource.url=jdbc:h2:mem:security-regression")
@AutoConfigureMockMvc(print = MockMvcPrint.NONE)
@ExtendWith(OutputCaptureExtension.class)
class ApiSecurityTests {

    private static final String API = "/api/threat";
    private static final String FIRST = randomToken();
    private static final String SECOND = randomToken();
    private static final String ADMIN = randomToken();
    private static final String EXTENSION_ORIGIN = "chrome-extension://abcdefghijklmnopabcdefghijklmnop";

    @Autowired
    private MockMvc mvc;

    @Autowired
    private JsonMapper json;

    @Autowired
    private JdbcTemplate jdbc;

    @DynamicPropertySource
    static void configureApi(DynamicPropertyRegistry settings) {
        addClient(settings, "browser-one", "BROWSER", FIRST);
        addClient(settings, "browser-two", "BROWSER", SECOND);
        addClient(settings, "operations", "ADMIN", ADMIN);
        settings.add("threat.security.allowed-origins[0]", () -> EXTENSION_ORIGIN);
        settings.add("threat.security.allowed-origins[1]", () -> "https://ops.example.test");
    }

    @Test
    void onlyHealthIsPublicAndBrowserCannotUseAdminRoutes() throws Exception {
        String id = UUID.randomUUID().toString();
        mvc.perform(get("/api/health")).andExpect(status().isOk());
        mvc.perform(get(API + "/health")).andExpect(status().isOk());
        for (String path : new String[]{"/logs", "/logs/filtered", "/logs/export", "/dashboard/stats",
                "/alerts", "/alerts/latest", "/alerts/unresolved"}) {
            mvc.perform(get(API + path)).andExpect(status().isUnauthorized());
            mvc.perform(auth(get(API + path), FIRST)).andExpect(status().isForbidden());
            mvc.perform(auth(get(API + path), ADMIN)).andExpect(status().isOk());
        }
        for (String suffix : new String[]{"", "/summary", "/timeline"}) {
            mvc.perform(get(API + "/session/" + id + suffix)).andExpect(status().isUnauthorized());
        }
        for (String path : new String[]{"/session/start", "/analyze", "/event", "/action", "/alerts/1/resolve"}) {
            mvc.perform(post(API + path)).andExpect(status().isUnauthorized());
        }
        mvc.perform(auth(post(API + "/alerts/1/resolve"), FIRST)).andExpect(status().isForbidden());
        mvc.perform(auth(post(API + "/action"), FIRST)).andExpect(status().isForbidden());
        mvc.perform(auth(post(API + "/session/start"), ADMIN)).andExpect(status().isForbidden());
        mvc.perform(auth(post(API + "/analyze"), ADMIN)).andExpect(status().isForbidden());
        mvc.perform(auth(post(API + "/event"), ADMIN)).andExpect(status().isForbidden());
    }

    @Test
    void onlyValidBearerHeaderCanAuthenticate() throws Exception {
        mvc.perform(auth(get(API + "/logs"), randomToken())).andExpect(status().isUnauthorized());
        mvc.perform(auth(get(API + "/logs"), "incorrect-format")).andExpect(status().isUnauthorized());
        mvc.perform(get(API + "/logs").param("access_token", ADMIN)).andExpect(status().isUnauthorized());
        mvc.perform(get(API + "/logs").cookie(new Cookie("access_token", ADMIN)))
                .andExpect(status().isUnauthorized());
        mvc.perform(auth(get(API + "/logs"), ADMIN))
                .andExpect(status().isOk())
                .andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE))
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")));
    }

    @Test
    void ownsSessionAndCannotReadOrModifyAnotherBrowsersRecords() throws Exception {
        String id = startSession(FIRST, "Login.Example.TEST");
        assertThat(startSession(FIRST, "login.example.test")).isNotEqualTo(id);
        for (String suffix : new String[]{"", "/summary", "/timeline"}) {
            String uri = API + "/session/" + id + suffix;
            mvc.perform(auth(get(uri), FIRST)).andExpect(status().isOk());
            mvc.perform(auth(get(uri), ADMIN)).andExpect(status().isOk());
            mvc.perform(auth(get(uri), SECOND)).andExpect(status().isNotFound());
        }
        mvc.perform(auth(get(API + "/session/" + id), FIRST))
                .andExpect(jsonPath("$.domain").value("login.example.test"))
                .andExpect(jsonPath("$.ownerId").doesNotExist());
        for (String path : new String[]{"/analyze", "/event"}) {
            submit(path, SECOND, event(id, "")).andExpect(status().isNotFound());
        }
        assertThat(jdbc.queryForObject("select count(*) from behavior_events where session_id = ?",
                Integer.class, id)).isZero();
        submit("/event", FIRST, event(id, "")).andExpect(status().isOk());
        submit("/analyze", FIRST, event(id, "")).andExpect(status().isOk());
        mvc.perform(auth(get(API + "/session/" + id + "/timeline"), FIRST))
                .andExpect(jsonPath("$[0].sessionId").value(id));
        submit("/action", ADMIN, """
                {"sessionId":"%s","action":"SHOW_WARNING"}
                """.formatted(id)).andExpect(status().isOk());
        mvc.perform(auth(get(API + "/session/" + id + "/timeline"), FIRST))
                .andExpect(jsonPath("$[?(@.action == 'SHOW_WARNING')]").isNotEmpty());
    }

    @Test
    void configuresExactCorsOriginsWithoutCookies() throws Exception {
        mvc.perform(preflight(EXTENSION_ORIGIN))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, EXTENSION_ORIGIN))
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS,
                        containsString("Authorization")))
                .andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS));
        mvc.perform(preflight("https://ops.example.test"))
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "https://ops.example.test"));
        for (String origin : new String[]{"https://unknown.example.test", "https://ops.example.test.other.test",
                "null", EXTENSION_ORIGIN.replace("abcd", "bbbb")}) {
            mvc.perform(preflight(origin)).andExpect(status().isForbidden())
                    .andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
        }
        mvc.perform(auth(post(API + "/analyze"), FIRST)
                        .header(HttpHeaders.ORIGIN, "https://unknown.example.test")
                        .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isForbidden());
    }

    @ParameterizedTest
    @ValueSource(strings = {"{}", "{\"domain\":null}", "{\"domain\":123}",
            "{\"domain\":\"https://example.test/login?secret=one#fragment\"}",
            "{\"domain\":\"invalid..test\"}", "{\"domain\":\"-invalid.test\"}",
            "{\"domain\":\"=untrusted\"}", "{\"domain\":\"valid.test\",\"sessionId\":\"client-id\"}",
            "{\"domain\":\"valid.test\",\"userAgentHash\":\"discard-me\"}",
            "{\"domain\":\"valid.test\",\"domain\":\"other.test\"}", "{\"domain\":\"valid.test\"}{}"})
    void rejectsMalformedSessionRequests(String payload) throws Exception {
        submit("/session/start", FIRST, payload).andExpect(status().isBadRequest());
    }

    @ParameterizedTest
    @ValueSource(strings = {",\"redirectCount\":-1", ",\"redirectCount\":101",
            ",\"averageClickGapMs\":-2", ",\"averageClickGapMs\":10001", ",\"averageClickGapMs\":1.2",
            ",\"clicksLast10Sec\":\"10\"", ",\"clicksLast10Sec\":null",
            ",\"pagesVisitedLast30Sec\":1001", ",\"tabSwitchCount\":-1", ",\"copyPasteCount\":-1",
            ",\"formSubmitCount\":1001", ",\"failedActionCount\":1001", ",\"deviceChanged\":\"true\"",
            ",\"actionType\":\"unknown\"", ",\"pageCategory\":null", ",\"eventType\":\"heartbeat\""})
    void rejectsInvalidTelemetryTypesAndRanges(String attributes) throws Exception {
        String id = UUID.randomUUID().toString();
        submit("/analyze", FIRST, event(id, attributes)).andExpect(status().isBadRequest());
        submit("/event", FIRST, event(id, attributes)).andExpect(status().isBadRequest());
    }

    @Test
    void validatesRequiredFieldsAndAdministrativeInputs() throws Exception {
        String absent = UUID.randomUUID().toString();
        submit("/analyze", FIRST, "{}").andExpect(status().isBadRequest());
        submit("/analyze", FIRST, event("client-id", "")).andExpect(status().isBadRequest());
        submit("/analyze", FIRST, event(absent, "")).andExpect(status().isNotFound());
        submit("/action", ADMIN, """
                {"sessionId":"%s","action":"operator supplied text"}
                """.formatted(absent)).andExpect(status().isBadRequest());
        submit("/action", ADMIN, """
                {"sessionId":"%s","action":"ALLOW"}
                """.formatted(absent)).andExpect(status().isNotFound());
        mvc.perform(auth(get(API + "/session/invalid/summary"), FIRST)).andExpect(status().isBadRequest());
        mvc.perform(auth(get(API + "/logs/filtered").param("riskLevel", "unknown"), ADMIN))
                .andExpect(status().isBadRequest());
        mvc.perform(auth(get(API + "/logs").param("domain", "https://example.test?a=private"), ADMIN))
                .andExpect(status().isBadRequest());
        mvc.perform(auth(get(API + "/logs").param("search", "x".repeat(101)), ADMIN))
                .andExpect(status().isBadRequest());
        mvc.perform(auth(post(API + "/alerts/0/resolve"), ADMIN)).andExpect(status().isBadRequest());
    }

    @Test
    void rejectsBrowsingDataWithoutPersistingOrEchoingIt(CapturedOutput output) throws Exception {
        String id = startSession(FIRST, "private-host.example.test");
        String url = "https://private-host.example.test/private?audit=secret-marker#fragment-marker";
        for (String field : new String[]{"url", "path", "referrer", "domain", "fieldType",
                "timestamp", "userAgentHash"}) {
            submit("/analyze", FIRST, event(id, ",\"%s\":\"%s\"".formatted(field, url)))
                    .andExpect(status().isBadRequest())
                    .andExpect(content().string(not(containsString("secret-marker"))));
        }
        assertThat(jdbc.queryForObject("select count(*) from behavior_events where session_id = ?",
                Integer.class, id)).isZero();
        assertThat(jdbc.queryForObject("select count(*) from risk_logs where session_id = ?",
                Integer.class, id)).isZero();
        submit("/analyze", FIRST, event(id, "")).andExpect(status().isOk());
        mvc.perform(auth(get(API + "/logs"), ADMIN))
                .andExpect(content().string(containsString("private-host.example.test")))
                .andExpect(jsonPath("$[*].url").isEmpty())
                .andExpect(content().string(not(containsString("secret-marker"))));
        mvc.perform(auth(get(API + "/logs/export"), ADMIN))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(id)))
                .andExpect(content().string(not(containsString("private-host.example.test"))))
                .andExpect(content().string(not(containsString("secret-marker"))));
        assertThat(output).doesNotContain("private-host.example.test", "secret-marker", "fragment-marker");
        assertThat(jdbc.queryForList("""
                select column_name from information_schema.columns
                where table_name in ('BEHAVIOR_EVENTS', 'RISK_LOGS', 'THREAT_SESSIONS')
                """, String.class)).doesNotContain("URL", "PATH", "REFERRER", "FIELD_TYPE", "USER_AGENT_HASH");
    }

    @Test
    void historicalUnownedRecordsAreNotExposedByTheSecuredApi() throws Exception {
        String legacy = UUID.randomUUID().toString();
        String marker = "legacy-sensitive-marker";
        jdbc.update("insert into threat_sessions (session_id, domain, current_risk_score) values (?, ?, 72)",
                legacy, marker);
        jdbc.update("""
                insert into risk_logs (session_id, domain, reasons, risk_score, trust_score, confidence)
                values (?, ?, ?, 72, 28, .72)
                """, legacy, marker, marker);
        jdbc.update("insert into alert_logs (session_id, domain, risk_score, resolved) values (?, ?, 72, false)",
                legacy, marker);
        for (String route : new String[]{"/logs", "/logs/filtered", "/logs/export", "/alerts", "/alerts/latest",
                "/alerts/unresolved"}) {
            mvc.perform(auth(get(API + route), ADMIN)).andExpect(status().isOk())
                    .andExpect(content().string(not(containsString(marker))));
        }
        for (String suffix : new String[]{"", "/summary", "/timeline"}) {
            mvc.perform(auth(get(API + "/session/" + legacy + suffix), ADMIN)).andExpect(status().isNotFound());
        }
        Long alertId = jdbc.queryForObject("select id from alert_logs where session_id = ?", Long.class, legacy);
        mvc.perform(auth(post(API + "/alerts/" + alertId + "/resolve"), ADMIN)).andExpect(status().isNotFound());
    }

    @Test
    void ordinaryLoginStaysSafeAndBehaviorCannotTriggerBlocking() throws Exception {
        String id = startSession(FIRST, "bank.example.test");
        for (String type : new String[]{"password_focus", "form_focus", "form_submit"}) {
            submit("/analyze", FIRST, """
                    {"sessionId":"%s","eventType":"%s","actionType":"sensitive_action",
                     "pageCategory":"sensitive_page","formSubmitCount":1,"redirectCount":1}
                    """.formatted(id, type))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.riskLevel").value("Safe"))
                    .andExpect(jsonPath("$.action").value("ALLOW"));
        }
        submit("/analyze", FIRST, event(id, """
                ,"redirectCount":3,"clicksLast10Sec":40,"tabSwitchCount":40,"formSubmitCount":40,
                "failedActionCount":40,"deviceChanged":true
                 """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.riskLevel").value("Suspicious"))
                .andExpect(jsonPath("$.riskScore").value(60))
                .andExpect(jsonPath("$.action").value("SHOW_WARNING"));
        String alert = mvc.perform(auth(get(API + "/alerts/latest"), ADMIN)).andReturn().getResponse().getContentAsString();
        long alertId = json.readTree(alert).path("id").asLong();
        mvc.perform(auth(post(API + "/alerts/" + alertId + "/resolve"), ADMIN)).andExpect(status().isOk())
                .andExpect(jsonPath("$.resolved").value(true));
    }

    @Test
    void demoAndConsoleRoutesAreDisabled() throws Exception {
        for (String path : new String[]{"/", "/index.html", "/admin.html", "/h2-console/", "/h2-console/login.do"}) {
            mvc.perform(auth(get(path), ADMIN)).andExpect(status().isForbidden());
        }
        for (String path : new String[]{"/analyze", "/analyze-legacy"}) {
            mvc.perform(auth(post(path), ADMIN)).andExpect(status().isForbidden());
        }
    }

    private String startSession(String token, String domain) throws Exception {
        var response = submit("/session/start", token, "{\"domain\":\"%s\"}".formatted(domain))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String id = json.readTree(response).path("sessionId").asText();
        assertThat(UUID.fromString(id).version()).isEqualTo(4);
        return id;
    }

    private static MockHttpServletRequestBuilder auth(MockHttpServletRequestBuilder request, String token) {
        return request.header(HttpHeaders.AUTHORIZATION, "Bearer " + token);
    }

    private ResultActions submit(String path, String token, String payload) throws Exception {
        return mvc.perform(auth(post(API + path), token).contentType(MediaType.APPLICATION_JSON).content(payload));
    }

    private static MockHttpServletRequestBuilder preflight(String origin) {
        return options(API + "/analyze").header(HttpHeaders.ORIGIN, origin)
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, "Authorization, Content-Type");
    }

    private static String event(String sessionId, String attributes) {
        return "{\"sessionId\":\"%s\",\"eventType\":\"page_view\"%s}".formatted(sessionId, attributes);
    }

    private static String randomToken() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static void addClient(DynamicPropertyRegistry settings, String name, String role, String token) {
        String prefix = "threat.security.clients." + name;
        settings.add(prefix + ".role", () -> role);
        settings.add(prefix + ".token-sha256", () -> {
            try {
                return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                        .digest(token.getBytes(StandardCharsets.US_ASCII)));
            } catch (NoSuchAlgorithmException exception) {
                throw new IllegalStateException(exception);
            }
        });
    }
}

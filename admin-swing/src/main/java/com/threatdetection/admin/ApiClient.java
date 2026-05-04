package com.threatdetection.admin;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * HTTP API client for communicating with the Spring Boot backend.
 * Uses Java HttpClient and Jackson for JSON serialization.
 */
public class ApiClient {

    private String baseUrl;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    public ApiClient(String baseUrl) {
        this.baseUrl = baseUrl;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new JavaTimeModule());
        this.objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        this.objectMapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    // ===== Health =====

    public JsonNode getHealth() throws Exception {
        return getJson("/api/health");
    }

    // ===== Dashboard Stats =====

    public JsonNode getDashboardStats() throws Exception {
        return getJson("/api/threat/dashboard/stats");
    }

    // ===== Logs =====

    public List<Map<String, Object>> getLogs() throws Exception {
        return getList("/api/threat/logs");
    }

    public List<Map<String, Object>> getFilteredLogs(String riskLevel, String domain, String search) throws Exception {
        StringBuilder url = new StringBuilder("/api/threat/logs/filtered?");
        if (riskLevel != null && !riskLevel.isBlank() && !"All".equals(riskLevel)) {
            url.append("riskLevel=").append(riskLevel).append("&");
        }
        if (domain != null && !domain.isBlank()) {
            url.append("domain=").append(domain).append("&");
        }
        if (search != null && !search.isBlank()) {
            url.append("search=").append(search).append("&");
        }
        return getList(url.toString());
    }

    // ===== Alerts =====

    public List<Map<String, Object>> getAlerts() throws Exception {
        return getList("/api/threat/alerts");
    }

    public JsonNode getLatestAlert() throws Exception {
        return getJson("/api/threat/alerts/latest");
    }

    public JsonNode resolveAlert(long alertId) throws Exception {
        return postJson("/api/threat/alerts/" + alertId + "/resolve", "{}");
    }

    // ===== Session Summary =====

    public JsonNode getSessionSummary(String sessionId) throws Exception {
        return getJson("/api/threat/session/" + sessionId + "/summary");
    }

    // ===== Timeline =====

    public List<Map<String, Object>> getTimeline(String sessionId) throws Exception {
        return getList("/api/threat/session/" + sessionId + "/timeline");
    }

    // ===== Analyze (Demo Simulator) =====

    public JsonNode analyze(Map<String, Object> request) throws Exception {
        String json = objectMapper.writeValueAsString(request);
        return postJson("/api/threat/analyze", json);
    }

    // ===== Internal Helpers =====

    private JsonNode getJson(String path) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + path))
                .header("Accept", "application/json")
                .GET()
                .timeout(Duration.ofSeconds(15))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        return objectMapper.readTree(response.body());
    }

    private List<Map<String, Object>> getList(String path) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + path))
                .header("Accept", "application/json")
                .GET()
                .timeout(Duration.ofSeconds(15))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        return objectMapper.readValue(response.body(), new TypeReference<>() {});
    }

    private JsonNode postJson(String path, String body) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + path))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .timeout(Duration.ofSeconds(15))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        return objectMapper.readTree(response.body());
    }
}

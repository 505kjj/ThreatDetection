package com.example.threatdetection.controller;

import com.example.threatdetection.dto.BehaviorRequest;
import com.example.threatdetection.dto.RiskResponse;
import com.example.threatdetection.service.EventLoggingService;
import com.example.threatdetection.service.ThreatAnalysisService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;

/**
 * Main threat detection API controller.
 */
@RestController
@RequestMapping("/api/threat")
public class ThreatController {

    private final ThreatAnalysisService analysisService;
    private final EventLoggingService eventLoggingService;

    public ThreatController(ThreatAnalysisService analysisService,
                            EventLoggingService eventLoggingService) {
        this.analysisService = analysisService;
        this.eventLoggingService = eventLoggingService;
    }

    /**
     * POST /api/threat/analyze
     * Main endpoint: receives behavior metadata, returns risk analysis.
     */
    @PostMapping("/analyze")
    public ResponseEntity<RiskResponse> analyze(@RequestBody BehaviorRequest request) {
        RiskResponse response = analysisService.analyze(request);
        return ResponseEntity.ok(response);
    }

    /**
     * POST /api/threat/event
     * Log a raw behavior event without full analysis.
     */
    @PostMapping("/event")
    public ResponseEntity<Map<String, String>> logEvent(@RequestBody BehaviorRequest request) {
        eventLoggingService.logEvent(request);
        return ResponseEntity.ok(Map.of("status", "logged", "sessionId", request.getSessionId()));
    }

    /**
     * GET /api/threat/health
     * Health check endpoint.
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        return ResponseEntity.ok(Map.of(
                "status", "UP",
                "service", "Threat Detection API",
                "timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)
        ));
    }
}

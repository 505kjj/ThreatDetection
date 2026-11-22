package com.example.threatdetection.controller;

import com.example.threatdetection.dto.BehaviorRequest;
import com.example.threatdetection.dto.RiskResponse;
import com.example.threatdetection.model.ThreatSession;
import com.example.threatdetection.service.EventLoggingService;
import com.example.threatdetection.service.SessionService;
import com.example.threatdetection.service.ThreatAnalysisService;
import jakarta.validation.Valid;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
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
    private final SessionService sessionService;

    public ThreatController(ThreatAnalysisService analysisService,
                            EventLoggingService eventLoggingService,
                            SessionService sessionService) {
        this.analysisService = analysisService;
        this.eventLoggingService = eventLoggingService;
        this.sessionService = sessionService;
    }

    /**
     * POST /api/threat/analyze
     * Main endpoint: receives behavior metadata, returns risk analysis.
     */
    @PostMapping(value = "/analyze", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<RiskResponse> analyze(@Valid @RequestBody BehaviorRequest request, Authentication principal) {
        RiskResponse response = analysisService.analyze(request, principal.getName());
        return ResponseEntity.ok(response);
    }

    /**
     * POST /api/threat/event
     * Log a raw behavior event without full analysis.
     */
    @PostMapping(value = "/event", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, String>> logEvent(@Valid @RequestBody BehaviorRequest request,
                                                        Authentication principal) {
        ThreatSession session = sessionService.requireOwnedSession(request.getSessionId(), principal.getName());
        eventLoggingService.logEvent(request, session);
        return ResponseEntity.ok(Map.of("status", "logged", "sessionId", session.getSessionId()));
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

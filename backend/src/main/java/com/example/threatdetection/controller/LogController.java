package com.example.threatdetection.controller;

import com.example.threatdetection.dto.ActionRequest;
import com.example.threatdetection.dto.ApiFields;
import com.example.threatdetection.model.RiskLog;
import com.example.threatdetection.model.ThreatSession;
import com.example.threatdetection.repository.RiskLogRepository;
import com.example.threatdetection.service.LogQueryService;
import com.example.threatdetection.service.SessionService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Pattern;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Admin log viewing and action recording controller.
 */
@RestController
@RequestMapping("/api/threat")
public class LogController {

    private final RiskLogRepository riskLogRepository;
    private final LogQueryService logQueryService;
    private final SessionService sessionService;

    public LogController(RiskLogRepository riskLogRepository, LogQueryService logQueryService,
                         SessionService sessionService) {
        this.riskLogRepository = riskLogRepository;
        this.logQueryService = logQueryService;
        this.sessionService = sessionService;
    }

    /**
     * GET /api/threat/logs
     * Returns recent risk logs for admin review, with optional filtering.
     */
    @GetMapping("/logs")
    public ResponseEntity<List<RiskLog>> getLogs(
            @RequestParam(required = false) @Pattern(regexp = ApiFields.RISK_LEVEL) String riskLevel,
            @RequestParam(required = false) @Pattern(regexp = ApiFields.HOST_FILTER) String domain,
            @RequestParam(required = false) @Pattern(regexp = ApiFields.LOG_SEARCH) String search) {
        return ResponseEntity.ok(logQueryService.getFilteredLogs(riskLevel, domain, search));
    }

    /**
     * POST /api/threat/action
     * Records an admin action taken on a session.
     */
    @PostMapping(value = "/action", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, String>> recordAction(@Valid @RequestBody ActionRequest request,
                                                            Authentication principal) {
        ThreatSession session = sessionService.requireReadableSession(request.getSessionId(), principal);
        // Log the action as a risk log entry
        RiskLog actionLog = RiskLog.builder()
                .sessionId(session.getSessionId())
                .domain(session.getDomain())
                .riskScore(0)
                .riskLevel(session.getRiskLevel())
                .reasons("Admin action: " + request.getAction())
                .tags("admin_action")
                .action(request.getAction())
                .confidence(1.0)
                .build();
        riskLogRepository.save(actionLog);

        return ResponseEntity.ok(Map.of(
                "status", "recorded",
                "action", request.getAction(),
                "sessionId", request.getSessionId()
        ));
    }
}

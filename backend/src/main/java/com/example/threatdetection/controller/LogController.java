package com.example.threatdetection.controller;

import com.example.threatdetection.dto.ActionRequest;
import com.example.threatdetection.model.RiskLog;
import com.example.threatdetection.repository.RiskLogRepository;
import org.springframework.http.ResponseEntity;
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
    private final com.example.threatdetection.service.LogQueryService logQueryService;

    public LogController(RiskLogRepository riskLogRepository, com.example.threatdetection.service.LogQueryService logQueryService) {
        this.riskLogRepository = riskLogRepository;
        this.logQueryService = logQueryService;
    }

    /**
     * GET /api/threat/logs
     * Returns recent risk logs for admin review, with optional filtering.
     */
    @GetMapping("/logs")
    public ResponseEntity<List<RiskLog>> getLogs(
            @RequestParam(required = false) String riskLevel,
            @RequestParam(required = false) String domain,
            @RequestParam(required = false) String search) {
        if (riskLevel != null || domain != null || search != null) {
            return ResponseEntity.ok(logQueryService.getFilteredLogs(riskLevel, domain, search));
        }
        List<RiskLog> logs = riskLogRepository.findTop100ByOrderByCreatedAtDesc();
        return ResponseEntity.ok(logs);
    }

    /**
     * POST /api/threat/action
     * Records an admin action taken on a session.
     */
    @PostMapping("/action")
    public ResponseEntity<Map<String, String>> recordAction(@RequestBody ActionRequest request) {
        // Log the action as a risk log entry
        RiskLog actionLog = RiskLog.builder()
                .sessionId(request.getSessionId())
                .domain(request.getDomain())
                .riskScore(0)
                .riskLevel(request.getRiskLevel())
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

package com.example.threatdetection.controller;

import com.example.threatdetection.model.RiskLog;
import com.example.threatdetection.service.*;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Admin controller for logs, timeline, session summary, CSV export, and dashboard stats.
 */
@RestController
@RequestMapping("/api/threat")
public class AdminController {

    private final LogQueryService logQueryService;
    private final TimelineService timelineService;
    private final SessionSummaryService sessionSummaryService;
    private final CsvExportService csvExportService;

    public AdminController(LogQueryService logQueryService,
                           TimelineService timelineService,
                           SessionSummaryService sessionSummaryService,
                           CsvExportService csvExportService) {
        this.logQueryService = logQueryService;
        this.timelineService = timelineService;
        this.sessionSummaryService = sessionSummaryService;
        this.csvExportService = csvExportService;
    }

    /**
     * GET /api/threat/logs/filtered
     * Returns filtered risk logs for admin review.
     */
    @GetMapping("/logs/filtered")
    public ResponseEntity<List<RiskLog>> getFilteredLogs(
            @RequestParam(required = false) String riskLevel,
            @RequestParam(required = false) String domain,
            @RequestParam(required = false) String search) {
        return ResponseEntity.ok(logQueryService.getFilteredLogs(riskLevel, domain, search));
    }

    /**
     * GET /api/threat/logs/export
     * Export risk logs as CSV.
     */
    @GetMapping("/logs/export")
    public ResponseEntity<String> exportLogs() {
        String csv = csvExportService.exportLogsAsCsv();
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=threat_logs.csv")
                .contentType(MediaType.parseMediaType("text/csv"))
                .body(csv);
    }

    /**
     * GET /api/threat/session/{sessionId}/timeline
     * Get the timeline (chronological risk logs) for a session.
     */
    @GetMapping("/session/{sessionId}/timeline")
    public ResponseEntity<List<RiskLog>> getTimeline(@PathVariable String sessionId) {
        return ResponseEntity.ok(timelineService.getSessionTimeline(sessionId));
    }

    /**
     * GET /api/threat/session/{sessionId}/summary
     * Get a summary of a session's risk profile.
     */
    @GetMapping("/session/{sessionId}/summary")
    public ResponseEntity<Map<String, Object>> getSessionSummary(@PathVariable String sessionId) {
        return ResponseEntity.ok(sessionSummaryService.getSessionSummary(sessionId));
    }

    /**
     * GET /api/threat/dashboard/stats
     * Get dashboard statistics (counts by risk level).
     */
    @GetMapping("/dashboard/stats")
    public ResponseEntity<LogQueryService.DashboardStats> getDashboardStats() {
        return ResponseEntity.ok(logQueryService.getDashboardStats());
    }
}

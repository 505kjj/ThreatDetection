package com.example.threatdetection.controller;

import com.example.threatdetection.model.AlertLog;
import com.example.threatdetection.service.AlertService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * REST controller for managing threat alerts.
 */
@RestController
@RequestMapping("/api/threat/alerts")
public class AlertController {

    private final AlertService alertService;

    public AlertController(AlertService alertService) {
        this.alertService = alertService;
    }

    /**
     * GET /api/threat/alerts
     * Get all alerts.
     */
    @GetMapping
    public ResponseEntity<List<AlertLog>> getAllAlerts() {
        return ResponseEntity.ok(alertService.getAllAlerts());
    }

    /**
     * GET /api/threat/alerts/unresolved
     * Get unresolved alerts only.
     */
    @GetMapping("/unresolved")
    public ResponseEntity<List<AlertLog>> getUnresolvedAlerts() {
        return ResponseEntity.ok(alertService.getUnresolvedAlerts());
    }

    /**
     * GET /api/threat/alerts/latest
     * Get the latest alert.
     */
    @GetMapping("/latest")
    public ResponseEntity<?> getLatestAlert() {
        Optional<AlertLog> latest = alertService.getLatestAlert();
        if (latest.isPresent()) {
            return ResponseEntity.ok(latest.get());
        }
        return ResponseEntity.ok(Map.of("message", "No alerts found"));
    }

    /**
     * POST /api/threat/alerts/{id}/resolve
     * Resolve an alert by ID.
     */
    @PostMapping("/{id}/resolve")
    public ResponseEntity<?> resolveAlert(@PathVariable Long id) {
        Optional<AlertLog> resolved = alertService.resolveAlert(id);
        if (resolved.isPresent()) {
            return ResponseEntity.ok(resolved.get());
        }
        return ResponseEntity.notFound().build();
    }
}

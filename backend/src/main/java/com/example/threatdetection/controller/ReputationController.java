package com.example.threatdetection.controller;

import com.example.threatdetection.reputation.ReputationIngestionSettings;
import com.example.threatdetection.reputation.ReputationIngestor;
import com.example.threatdetection.reputation.ReputationService;
import com.example.threatdetection.reputation.ReputationSnapshot;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ReputationController {
    private final ReputationService reputation;
    private final ReputationIngestionSettings ingestion;
    private final ObjectProvider<ReputationIngestor> ingestor;

    public ReputationController(ReputationService reputation, ReputationIngestionSettings ingestion,
                                ObjectProvider<ReputationIngestor> ingestor) {
        this.reputation = reputation;
        this.ingestion = ingestion;
        this.ingestor = ingestor;
    }

    @GetMapping("/api/threat/reputation/snapshot")
    public ResponseEntity<ReputationSnapshot> snapshot(HttpServletRequest request) {
        if (request.getQueryString() != null) return ResponseEntity.badRequest().build();
        if (!ingestion.canServeBrowsers()) return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build();
        return reputation.snapshot().map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build());
    }

    @GetMapping("/api/threat/reputation/feed-status")
    public ResponseEntity<?> feedStatus(HttpServletRequest request) {
        if (request.getQueryString() != null) return ResponseEntity.badRequest().build();
        var active = ingestor.getIfAvailable();
        return ResponseEntity.ok(active == null ? Map.of("pollState", "DISABLED") : active.status());
    }
}

package com.example.threatdetection.controller;

import com.example.threatdetection.reputation.ReputationService;
import com.example.threatdetection.reputation.ReputationSnapshot;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ReputationController {
    private final ReputationService reputation;

    public ReputationController(ReputationService reputation) {
        this.reputation = reputation;
    }

    @GetMapping("/api/threat/reputation/snapshot")
    public ResponseEntity<ReputationSnapshot> snapshot(HttpServletRequest request) {
        if (request.getQueryString() != null) return ResponseEntity.badRequest().build();
        return reputation.snapshot().map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build());
    }
}

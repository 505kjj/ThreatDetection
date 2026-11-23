package com.example.threatdetection.service;

import com.example.threatdetection.dto.RiskResponse;
import com.example.threatdetection.model.AlertLog;
import com.example.threatdetection.repository.AlertLogRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Service for managing threat alerts.
 * Automatically generates alerts for Suspicious, High Risk, and Critical events.
 */
@Service
public class AlertService {

    private static final Logger log = LoggerFactory.getLogger(AlertService.class);

    private final AlertLogRepository alertLogRepository;

    public AlertService(AlertLogRepository alertLogRepository) {
        this.alertLogRepository = alertLogRepository;
    }

    /**
     * Check if an alert should be generated based on the risk response.
     * Alerts are generated for Suspicious, High Risk, and Critical levels.
     */
    public void checkAndGenerateAlert(String sessionId, String domain, RiskResponse response) {
        String level = response.getRiskLevel();
        if ("Safe".equals(level)) {
            return; // No alert for safe responses
        }

        String message = String.format(
                "Behavior classified as [%s] with risk score %d. Reasons: %s",
                level, response.getRiskScore(),
                String.join(", ", response.getReasons())
        );

        AlertLog alert = AlertLog.builder()
                .sessionId(sessionId)
                .domain(domain)
                .riskScore(response.getRiskScore())
                .riskLevel(level)
                .message(message)
                .resolved(false)
                .createdAt(LocalDateTime.now())
                .build();

        alertLogRepository.save(alert);
    }

    /**
     * Get all alerts ordered by creation time (newest first).
     */
    public List<AlertLog> getAllAlerts() {
        return alertLogRepository.findAllByOrderByCreatedAtDesc();
    }

    /**
     * Get unresolved alerts.
     */
    public List<AlertLog> getUnresolvedAlerts() {
        return alertLogRepository.findByResolvedFalseOrderByCreatedAtDesc();
    }

    /**
     * Get the latest alert.
     */
    public Optional<AlertLog> getLatestAlert() {
        List<AlertLog> latest = alertLogRepository.findTop1ByOrderByCreatedAtDesc();
        return latest.isEmpty() ? Optional.empty() : Optional.of(latest.get(0));
    }

    /**
     * Resolve an alert by ID.
     */
    public Optional<AlertLog> resolveAlert(Long id) {
        Optional<AlertLog> alertOpt = alertLogRepository.findById(id);
        if (alertOpt.isPresent()) {
            AlertLog alert = alertOpt.get();
            alert.setResolved(true);
            alert.setResolvedAt(LocalDateTime.now());
            alertLogRepository.save(alert);
            log.info("Alert [{}] resolved", id);
            return Optional.of(alert);
        }
        return Optional.empty();
    }
}

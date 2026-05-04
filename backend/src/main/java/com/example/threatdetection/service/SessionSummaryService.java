package com.example.threatdetection.service;

import com.example.threatdetection.model.RiskLog;
import com.example.threatdetection.repository.RiskLogRepository;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Service for computing session summaries.
 * Aggregates all risk logs for a session into a single summary view.
 */
@Service
public class SessionSummaryService {

    private final RiskLogRepository riskLogRepository;

    public SessionSummaryService(RiskLogRepository riskLogRepository) {
        this.riskLogRepository = riskLogRepository;
    }

    /**
     * Compute a summary for the given session.
     */
    public Map<String, Object> getSessionSummary(String sessionId) {
        List<RiskLog> logs = riskLogRepository.findBySessionIdOrderByCreatedAtDesc(sessionId);

        if (logs.isEmpty()) {
            Map<String, Object> empty = new LinkedHashMap<>();
            empty.put("sessionId", sessionId);
            empty.put("totalEvents", 0);
            empty.put("message", "No data found for this session");
            return empty;
        }

        int highestRiskScore = logs.stream().mapToInt(RiskLog::getRiskScore).max().orElse(0);
        int trustScore = 100 - highestRiskScore;

        // Determine highest risk level by priority
        String highestRiskLevel = determineHighestLevel(logs);

        long totalEvents = logs.size();
        long totalWarnings = logs.stream()
                .filter(l -> "Suspicious".equals(l.getRiskLevel()))
                .count();
        long totalHighRisk = logs.stream()
                .filter(l -> "High Risk".equals(l.getRiskLevel()))
                .count();
        long totalCritical = logs.stream()
                .filter(l -> "Critical".equals(l.getRiskLevel()))
                .count();

        // Collect unique reasons
        Set<String> allReasons = new LinkedHashSet<>();
        for (RiskLog log : logs) {
            if (log.getReasons() != null && !log.getReasons().isBlank()) {
                Arrays.stream(log.getReasons().split("\\s*\\|\\s*"))
                        .filter(r -> !r.isBlank())
                        .forEach(allReasons::add);
            }
        }

        // Determine final action from the highest-risk log
        String finalAction = logs.stream()
                .max(Comparator.comparingInt(RiskLog::getRiskScore))
                .map(RiskLog::getAction)
                .orElse("ALLOW");

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("sessionId", sessionId);
        summary.put("highestRiskScore", highestRiskScore);
        summary.put("trustScore", trustScore);
        summary.put("highestRiskLevel", highestRiskLevel);
        summary.put("totalEvents", totalEvents);
        summary.put("totalWarnings", totalWarnings);
        summary.put("totalHighRisk", totalHighRisk);
        summary.put("totalCritical", totalCritical);
        summary.put("mainReasons", new ArrayList<>(allReasons));
        summary.put("finalAction", finalAction);

        return summary;
    }

    private String determineHighestLevel(List<RiskLog> logs) {
        Map<String, Integer> priority = Map.of(
                "Safe", 0, "Suspicious", 1, "High Risk", 2, "Critical", 3
        );

        return logs.stream()
                .map(RiskLog::getRiskLevel)
                .filter(Objects::nonNull)
                .max(Comparator.comparingInt(level -> priority.getOrDefault(level, 0)))
                .orElse("Safe");
    }
}

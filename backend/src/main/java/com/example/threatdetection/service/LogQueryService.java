package com.example.threatdetection.service;

import com.example.threatdetection.model.RiskLog;
import com.example.threatdetection.repository.RiskLogRepository;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Service for querying and filtering risk logs.
 */
@Service
public class LogQueryService {

    private final RiskLogRepository riskLogRepository;

    public LogQueryService(RiskLogRepository riskLogRepository) {
        this.riskLogRepository = riskLogRepository;
    }

    /**
     * Get filtered logs based on optional riskLevel, domain, and search parameters.
     */
    public List<RiskLog> getFilteredLogs(String riskLevel, String domain, String search) {
        // If all filters are empty, return default top 100
        if (isBlank(riskLevel) && isBlank(domain) && isBlank(search)) {
            return riskLogRepository.findTop100ByOrderByCreatedAtDesc();
        }

        return riskLogRepository.findFiltered(
                isBlank(riskLevel) ? null : riskLevel,
                isBlank(domain) ? null : domain,
                isBlank(search) ? null : search
        );
    }

    /**
     * Get dashboard statistics: counts by risk level.
     */
    public DashboardStats getDashboardStats() {
        long total = riskLogRepository.count();
        long safe = riskLogRepository.countByRiskLevel("Safe");
        long suspicious = riskLogRepository.countByRiskLevel("Suspicious");
        long highRisk = riskLogRepository.countByRiskLevel("High Risk");
        long critical = riskLogRepository.countByRiskLevel("Critical");

        return new DashboardStats(total, safe, suspicious, highRisk, critical);
    }

    private boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    /**
     * Simple record for dashboard statistics.
     */
    public record DashboardStats(
            long totalLogs,
            long safeCount,
            long suspiciousCount,
            long highRiskCount,
            long criticalCount
    ) {}
}

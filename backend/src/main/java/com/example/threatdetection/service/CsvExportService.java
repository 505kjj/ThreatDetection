package com.example.threatdetection.service;

import com.example.threatdetection.model.RiskLog;
import com.example.threatdetection.repository.RiskLogRepository;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Service for exporting risk logs as CSV.
 */
@Service
public class CsvExportService {

    private final RiskLogRepository riskLogRepository;

    public CsvExportService(RiskLogRepository riskLogRepository) {
        this.riskLogRepository = riskLogRepository;
    }

    /**
     * Export the latest 100 risk decisions without browsing metadata.
     */
    public String exportLogsAsCsv() {
        List<RiskLog> logs = riskLogRepository.findTop100ByOrderByCreatedAtDesc();

        StringBuilder sb = new StringBuilder();
        sb.append("ID,Session ID,Risk Score,Trust Score,Risk Level,Action,Confidence,Created At\n");

        for (RiskLog log : logs) {
            sb.append(log.getId())
              .append(",").append(log.getSessionId())
              .append(",").append(log.getRiskScore())
              .append(",").append(log.getTrustScore())
              .append(",").append(log.getRiskLevel())
              .append(",").append(log.getAction())
              .append(",").append(log.getConfidence())
              .append(",").append(log.getCreatedAt())
              .append("\n");
        }

        return sb.toString();
    }

}

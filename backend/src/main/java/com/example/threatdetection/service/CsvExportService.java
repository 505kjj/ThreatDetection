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
     * Export all risk logs as a CSV string.
     */
    public String exportLogsAsCsv() {
        List<RiskLog> logs = riskLogRepository.findTop100ByOrderByCreatedAtDesc();

        StringBuilder sb = new StringBuilder();
        sb.append("ID,Session ID,Domain,Risk Score,Trust Score,Risk Level,URL,Event Type,Action Type,Page Category,Field Type,Reasons,Tags,Action,Confidence,Created At\n");

        for (RiskLog log : logs) {
            sb.append(escapeCsv(log.getId()))
              .append(",").append(escapeCsv(log.getSessionId()))
              .append(",").append(escapeCsv(log.getDomain()))
              .append(",").append(log.getRiskScore())
              .append(",").append(log.getTrustScore())
              .append(",").append(escapeCsv(log.getRiskLevel()))
              .append(",").append(escapeCsv(log.getUrl()))
              .append(",").append(escapeCsv(log.getEventType()))
              .append(",").append(escapeCsv(log.getActionType()))
              .append(",").append(escapeCsv(log.getPageCategory()))
              .append(",").append(escapeCsv(log.getFieldType()))
              .append(",").append(escapeCsv(log.getReasons()))
              .append(",").append(escapeCsv(log.getTags()))
              .append(",").append(escapeCsv(log.getAction()))
              .append(",").append(log.getConfidence())
              .append(",").append(log.getCreatedAt())
              .append("\n");
        }

        return sb.toString();
    }

    private String escapeCsv(Object value) {
        if (value == null) return "";
        String str = value.toString();
        if (str.contains(",") || str.contains("\"") || str.contains("\n")) {
            return "\"" + str.replace("\"", "\"\"") + "\"";
        }
        return str;
    }
}

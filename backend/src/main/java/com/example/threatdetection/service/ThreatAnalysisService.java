package com.example.threatdetection.service;

import com.example.threatdetection.dto.BehaviorRequest;
import com.example.threatdetection.dto.RiskResponse;
import com.example.threatdetection.engine.RiskEngine;
import com.example.threatdetection.model.RiskLog;
import com.example.threatdetection.repository.RiskLogRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

/**
 * Core threat analysis service.
 * Coordinates event logging, risk evaluation, session updates, and risk log persistence.
 */
@Service
public class ThreatAnalysisService {

    private static final Logger log = LoggerFactory.getLogger(ThreatAnalysisService.class);

    private final RiskEngine riskEngine;
    private final EventLoggingService eventLoggingService;
    private final SessionService sessionService;
    private final RiskLogRepository riskLogRepository;
    private final AlertService alertService;

    public ThreatAnalysisService(RiskEngine riskEngine,
                                  EventLoggingService eventLoggingService,
                                  SessionService sessionService,
                                  RiskLogRepository riskLogRepository,
                                  AlertService alertService) {
        this.riskEngine = riskEngine;
        this.eventLoggingService = eventLoggingService;
        this.sessionService = sessionService;
        this.riskLogRepository = riskLogRepository;
        this.alertService = alertService;
    }

    /**
     * Analyze a behavior request: log event, evaluate risk, update session, persist risk log.
     */
    public RiskResponse analyze(BehaviorRequest request) {
        // 1. Log the behavior event
        try {
            eventLoggingService.logEvent(request);
        } catch (Exception e) {
            log.error("Failed to log behavior event: {}", e.getMessage());
        }

        // 2. Run the risk engine
        RiskResponse response = riskEngine.evaluate(request);

        // 3. Update the session risk level
        try {
            if (request.getSessionId() != null) {
                sessionService.updateSessionRisk(
                        request.getSessionId(),
                        response.getRiskScore(),
                        response.getRiskLevel()
                );
            }
        } catch (Exception e) {
            log.error("Failed to update session risk: {}", e.getMessage());
        }

        // 4. Persist risk log
        try {
            RiskLog riskLog = RiskLog.builder()
                    .sessionId(request.getSessionId())
                    .domain(request.getDomain())
                    .riskScore(response.getRiskScore())
                    .trustScore(response.getTrustScore())
                    .riskLevel(response.getRiskLevel())
                    .url(request.getUrl())
                    .eventType(request.getEventType())
                    .actionType(request.getActionType())
                    .pageCategory(request.getPageCategory())
                    .fieldType(request.getFieldType())
                    .reasons(String.join(" | ", response.getReasons()))
                    .tags(String.join(", ", response.getTags()))
                    .action(response.getAction())
                    .confidence(response.getConfidence())
                    .createdAt(LocalDateTime.now())
                    .build();
            riskLogRepository.save(riskLog);
        } catch (Exception e) {
            log.error("Failed to persist risk log: {}", e.getMessage());
        }

        // 5. Generate alert if risk level is not Safe
        try {
            alertService.checkAndGenerateAlert(
                    request.getSessionId(), request.getDomain(), response);
        } catch (Exception e) {
            log.error("Failed to generate alert: {}", e.getMessage());
        }

        log.info("Analysis complete for session [{}] on [{}]: score={}, level={}, action={}",
                request.getSessionId(),
                request.getDomain(),
                response.getRiskScore(),
                response.getRiskLevel(),
                response.getAction());

        return response;
    }
}

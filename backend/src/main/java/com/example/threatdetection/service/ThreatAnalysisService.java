package com.example.threatdetection.service;

import com.example.threatdetection.dto.BehaviorRequest;
import com.example.threatdetection.dto.RiskResponse;
import com.example.threatdetection.engine.RiskEngine;
import com.example.threatdetection.model.RiskLog;
import com.example.threatdetection.model.ThreatSession;
import com.example.threatdetection.reputation.ReputationService;
import com.example.threatdetection.repository.RiskLogRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

/**
 * Core threat analysis service.
 * Coordinates event logging, risk evaluation, session updates, and risk log persistence.
 */
@Service
public class ThreatAnalysisService {

    private final RiskEngine riskEngine;
    private final EventLoggingService eventLoggingService;
    private final SessionService sessionService;
    private final RiskLogRepository riskLogRepository;
    private final AlertService alertService;
    private final ReputationService reputationService;

    public ThreatAnalysisService(RiskEngine riskEngine,
                                  EventLoggingService eventLoggingService,
                                  SessionService sessionService,
                                  RiskLogRepository riskLogRepository,
                                  AlertService alertService,
                                  ReputationService reputationService) {
        this.riskEngine = riskEngine;
        this.eventLoggingService = eventLoggingService;
        this.sessionService = sessionService;
        this.riskLogRepository = riskLogRepository;
        this.alertService = alertService;
        this.reputationService = reputationService;
    }

    /**
     * Analyze a behavior request: log event, evaluate risk, update session, persist risk log.
     */
    @Transactional
    public RiskResponse analyze(BehaviorRequest request, String ownerId) {
        ThreatSession session = sessionService.requireOwnedSession(request.getSessionId(), ownerId);
        eventLoggingService.logEvent(request, session);
        RiskResponse response = reputationService.applyHostReputation(session.getDomain(), riskEngine.evaluate(request));

        session.setCurrentRiskScore(response.getRiskScore());
        session.setRiskLevel(response.getRiskLevel());
        session.setLastActivity(LocalDateTime.now());

        riskLogRepository.save(RiskLog.builder()
                .sessionId(session.getSessionId())
                .domain(session.getDomain())
                .riskScore(response.getRiskScore())
                .trustScore(response.getTrustScore())
                .riskLevel(response.getRiskLevel())
                .eventType(request.getEventType())
                .actionType(request.getActionType())
                .reasons(String.join(" | ", response.getReasons()))
                .tags(String.join(", ", response.getTags()))
                .action(response.getAction())
                .confidence(response.getConfidence())
                .build());

        alertService.checkAndGenerateAlert(session.getSessionId(), session.getDomain(), response);
        return response;
    }
}

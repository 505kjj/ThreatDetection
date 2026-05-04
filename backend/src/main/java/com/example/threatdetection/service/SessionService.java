package com.example.threatdetection.service;

import com.example.threatdetection.dto.SessionStartRequest;
import com.example.threatdetection.model.ThreatSession;
import com.example.threatdetection.repository.ThreatSessionRepository;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;

/**
 * Service for managing threat monitoring sessions.
 */
@Service
public class SessionService {

    private final ThreatSessionRepository sessionRepository;

    public SessionService(ThreatSessionRepository sessionRepository) {
        this.sessionRepository = sessionRepository;
    }

    /**
     * Start or retrieve an existing session.
     */
    public ThreatSession startSession(SessionStartRequest request) {
        Optional<ThreatSession> existing = sessionRepository.findBySessionId(request.getSessionId());
        if (existing.isPresent()) {
            ThreatSession session = existing.get();
            session.setLastActivity(LocalDateTime.now());
            return sessionRepository.save(session);
        }

        ThreatSession session = ThreatSession.builder()
                .sessionId(request.getSessionId())
                .domain(request.getDomain())
                .startTime(LocalDateTime.now())
                .lastActivity(LocalDateTime.now())
                .currentRiskScore(0)
                .riskLevel("Safe")
                .userAgentHash(request.getUserAgentHash())
                .build();

        return sessionRepository.save(session);
    }

    /**
     * Get a session by session ID.
     */
    public Optional<ThreatSession> getSession(String sessionId) {
        return sessionRepository.findBySessionId(sessionId);
    }

    /**
     * Update session risk information.
     */
    public void updateSessionRisk(String sessionId, int riskScore, String riskLevel) {
        sessionRepository.findBySessionId(sessionId).ifPresent(session -> {
            session.setCurrentRiskScore(riskScore);
            session.setRiskLevel(riskLevel);
            session.setLastActivity(LocalDateTime.now());
            sessionRepository.save(session);
        });
    }
}

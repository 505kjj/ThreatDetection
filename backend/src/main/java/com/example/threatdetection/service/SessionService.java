package com.example.threatdetection.service;

import com.example.threatdetection.dto.SessionStartRequest;
import com.example.threatdetection.model.ThreatSession;
import com.example.threatdetection.repository.ThreatSessionRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Locale;
import java.util.UUID;

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
     * Issue a fresh session for the authenticated browser.
     */
    public ThreatSession startSession(SessionStartRequest request, String ownerId) {
        return sessionRepository.save(ThreatSession.builder()
                .sessionId(UUID.randomUUID().toString())
                .domain(request.getDomain().toLowerCase(Locale.ROOT))
                .ownerId(ownerId)
                .build());
    }

    public ThreatSession requireReadableSession(String sessionId, Authentication principal) {
        if (principal.getAuthorities().stream().anyMatch(authority -> authority.getAuthority().equals("ROLE_ADMIN"))) {
            return sessionRepository.findBySessionIdAndOwnerIdIsNotNull(sessionId)
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        }
        return requireOwnedSession(sessionId, principal.getName());
    }

    public ThreatSession requireOwnedSession(String sessionId, String ownerId) {
        return sessionRepository.findBySessionIdAndOwnerId(sessionId, ownerId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }
}

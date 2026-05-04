package com.example.threatdetection.controller;

import com.example.threatdetection.dto.SessionStartRequest;
import com.example.threatdetection.model.ThreatSession;
import com.example.threatdetection.service.SessionService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Optional;

/**
 * Session management API controller.
 */
@RestController
@RequestMapping("/api/threat/session")
public class SessionController {

    private final SessionService sessionService;

    public SessionController(SessionService sessionService) {
        this.sessionService = sessionService;
    }

    /**
     * POST /api/threat/session/start
     * Start or resume a monitoring session.
     */
    @PostMapping("/start")
    public ResponseEntity<ThreatSession> startSession(@RequestBody SessionStartRequest request) {
        ThreatSession session = sessionService.startSession(request);
        return ResponseEntity.ok(session);
    }

    /**
     * GET /api/threat/session/{sessionId}
     * Get session details.
     */
    @GetMapping("/{sessionId}")
    public ResponseEntity<?> getSession(@PathVariable String sessionId) {
        Optional<ThreatSession> session = sessionService.getSession(sessionId);
        if (session.isPresent()) {
            return ResponseEntity.ok(session.get());
        }
        return ResponseEntity.notFound().build();
    }
}

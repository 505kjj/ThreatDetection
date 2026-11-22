package com.example.threatdetection.controller;

import com.example.threatdetection.dto.ApiFields;
import com.example.threatdetection.dto.SessionStartRequest;
import com.example.threatdetection.model.ThreatSession;
import com.example.threatdetection.service.SessionService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Pattern;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

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
     * Issue a new monitoring session for the authenticated browser.
     */
    @PostMapping(value = "/start", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ThreatSession> startSession(@Valid @RequestBody SessionStartRequest request,
                                                       Authentication principal) {
        ThreatSession session = sessionService.startSession(request, principal.getName());
        return ResponseEntity.ok(session);
    }

    /**
     * GET /api/threat/session/{sessionId}
     * Get session details.
     */
    @GetMapping("/{sessionId}")
    public ResponseEntity<ThreatSession> getSession(@PathVariable @Pattern(regexp = ApiFields.SESSION_ID) String sessionId,
                                                     Authentication principal) {
        return ResponseEntity.ok(sessionService.requireReadableSession(sessionId, principal));
    }
}

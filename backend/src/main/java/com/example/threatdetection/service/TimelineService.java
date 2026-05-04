package com.example.threatdetection.service;

import com.example.threatdetection.model.RiskLog;
import com.example.threatdetection.repository.RiskLogRepository;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Service for retrieving session timelines.
 * Returns risk logs for a given session ordered chronologically.
 */
@Service
public class TimelineService {

    private final RiskLogRepository riskLogRepository;

    public TimelineService(RiskLogRepository riskLogRepository) {
        this.riskLogRepository = riskLogRepository;
    }

    /**
     * Get the timeline (chronological risk logs) for a session.
     */
    public List<RiskLog> getSessionTimeline(String sessionId) {
        return riskLogRepository.findBySessionIdOrderByCreatedAtAsc(sessionId);
    }
}

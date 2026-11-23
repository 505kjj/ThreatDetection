package com.example.threatdetection.service;

import com.example.threatdetection.dto.BehaviorRequest;
import com.example.threatdetection.model.BehaviorEvent;
import com.example.threatdetection.model.ThreatSession;
import com.example.threatdetection.repository.BehaviorEventRepository;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

/**
 * Service for persisting behavior events.
 */
@Service
public class EventLoggingService {

    private final BehaviorEventRepository eventRepository;

    public EventLoggingService(BehaviorEventRepository eventRepository) {
        this.eventRepository = eventRepository;
    }

    /**
     * Log a behavior event from the extension.
     */
    public BehaviorEvent logEvent(BehaviorRequest request, ThreatSession session) {
        BehaviorEvent event = BehaviorEvent.builder()
                .sessionId(session.getSessionId())
                .eventType(request.getEventType())
                .actionType(request.getActionType())
                .redirectCount(request.getRedirectCount())
                .averageClickGapMs(request.getAverageClickGapMs())
                .clicksLast10Sec(request.getClicksLast10Sec())
                .pagesVisitedLast30Sec(request.getPagesVisitedLast30Sec())
                .tabSwitchCount(request.getTabSwitchCount())
                .copyPasteCount(request.getCopyPasteCount())
                .formSubmitCount(request.getFormSubmitCount())
                .timestamp(LocalDateTime.now())
                .build();

        return eventRepository.save(event);
    }
}

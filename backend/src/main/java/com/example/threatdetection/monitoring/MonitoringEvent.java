package com.example.threatdetection.monitoring;

import java.time.Instant;
import java.util.UUID;

record MonitoringEvent(String clientId, UUID eventId, Instant receivedAt, Instant detectedAt, boolean synthetic,
                       MonitoringSignal signal, MonitoringSignal.Action action) {
    boolean matches(Instant detection, MonitoringSignal evidence, MonitoringSignal.Action requestedAction) {
        return detectedAt.equals(detection) && signal == evidence && action == requestedAction;
    }

    MonitoringService.Entry entry() {
        return new MonitoringService.Entry(detectedAt, signal.category, signal.severity(), signal.source, action,
                signal.reason);
    }
}

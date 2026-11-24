package com.example.threatdetection.monitoring;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "monitoring_event",
        uniqueConstraints = @UniqueConstraint(columnNames = {"client_id", "event_id"}),
        indexes = @Index(columnList = "synthetic, received_at"))
class MonitoringEvent {
    @Id @GeneratedValue
    private Long id;

    @Column(name = "client_id", nullable = false, length = 64)
    private String clientId;
    @Column(name = "event_id", nullable = false)
    private UUID eventId;
    @Column(name = "received_at", nullable = false)
    private Instant receivedAt;
    @Column(nullable = false)
    private Instant detectedAt;
    @Column(nullable = false)
    private boolean synthetic;
    @Enumerated(EnumType.STRING) @Column(nullable = false, length = 32)
    private MonitoringSignal signal;
    @Enumerated(EnumType.STRING) @Column(nullable = false, length = 8)
    private MonitoringSignal.Action action;

    protected MonitoringEvent() {}

    MonitoringEvent(String clientId, UUID eventId, Instant receivedAt, Instant detectedAt, boolean synthetic,
                    MonitoringSignal signal, MonitoringSignal.Action action) {
        this.clientId = clientId;
        this.eventId = eventId;
        this.receivedAt = receivedAt;
        this.detectedAt = detectedAt;
        this.synthetic = synthetic;
        this.signal = signal;
        this.action = action;
    }

    boolean matches(Instant detection, MonitoringSignal evidence, MonitoringSignal.Action requestedAction) {
        return detectedAt.equals(detection) && signal == evidence && action == requestedAction;
    }

    MonitoringService.Entry entry() {
        return new MonitoringService.Entry(detectedAt, signal.category, signal.severity(), signal.source, action,
                signal.reason);
    }
}

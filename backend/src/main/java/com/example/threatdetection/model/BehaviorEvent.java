package com.example.threatdetection.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Stores individual behavior events received from the extension.
 * Contains ONLY metadata — never actual form values or sensitive data.
 */
@Entity
@Table(name = "behavior_events")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class BehaviorEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String sessionId;

    private String eventType;
    private String actionType;

    @Builder.Default
    private int redirectCount = 0;

    @Builder.Default
    private double averageClickGapMs = -1;

    @Builder.Default
    private int clicksLast10Sec = 0;

    @Builder.Default
    private int pagesVisitedLast30Sec = 0;

    @Builder.Default
    private int tabSwitchCount = 0;

    @Builder.Default
    private int copyPasteCount = 0;

    @Builder.Default
    private int formSubmitCount = 0;

    @Builder.Default
    private LocalDateTime timestamp = LocalDateTime.now();
}

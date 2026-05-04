package com.example.threatdetection.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Behavior metadata sent from the Chrome extension.
 * Contains ONLY metadata — never actual form values, passwords, or sensitive data.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class BehaviorRequest {

    private String sessionId;
    private String domain;
    private String url;
    private String path;
    private String referrer;

    @Builder.Default
    private int redirectCount = 0;

    private String eventType;
    private String actionType;
    private String pageCategory;
    private String fieldType;

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

    // Optional fields for advanced rules
    @Builder.Default
    private int failedActionCount = 0;

    @Builder.Default
    private boolean deviceChanged = false;

    private String userAgentHash;
    private String timestamp;
}

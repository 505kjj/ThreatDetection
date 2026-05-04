package com.example.threatdetection.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request to record an admin action taken on a session.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ActionRequest {

    private String sessionId;
    private String domain;
    private String action;
    private String riskLevel;
}

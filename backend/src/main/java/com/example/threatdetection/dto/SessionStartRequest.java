package com.example.threatdetection.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request to start or register a new threat monitoring session.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SessionStartRequest {

    private String sessionId;
    private String domain;
    private String userAgentHash;
}

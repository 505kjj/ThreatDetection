package com.example.threatdetection.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Represents a threat monitoring session for a domain.
 */
@Entity
@Table(name = "threat_sessions")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ThreatSession {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String sessionId;

    @Column(nullable = false)
    private String domain;

    @Builder.Default
    private LocalDateTime startTime = LocalDateTime.now();

    @Builder.Default
    private LocalDateTime lastActivity = LocalDateTime.now();

    @Builder.Default
    private int currentRiskScore = 0;

    @Builder.Default
    private String riskLevel = "Safe";

    private String userAgentHash;
}

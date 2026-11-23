package com.example.threatdetection.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
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
    @JsonIgnore
    private Long id;

    @Column(nullable = false, unique = true, length = 36)
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

    // Existing demo sessions have no owner and cannot be used through the secured API.
    @JsonIgnore
    private String ownerId;
}

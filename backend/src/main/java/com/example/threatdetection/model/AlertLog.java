package com.example.threatdetection.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Stores alert entries generated when risk levels exceed thresholds.
 */
@Entity
@Table(name = "alert_logs")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AlertLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String sessionId;
    private String domain;
    private int riskScore;
    private String riskLevel;

    @Column(length = 4096)
    private String message;

    @Builder.Default
    private boolean resolved = false;

    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();

    private LocalDateTime resolvedAt;
}

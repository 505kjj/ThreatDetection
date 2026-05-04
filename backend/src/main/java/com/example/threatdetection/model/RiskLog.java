package com.example.threatdetection.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Stores risk analysis results for audit and admin review.
 */
@Entity
@Table(name = "risk_logs")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RiskLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String sessionId;
    private String domain;
    private int riskScore;
    private int trustScore;
    private String riskLevel;

    @Column(length = 2048)
    private String url;

    private String eventType;
    private String actionType;
    private String pageCategory;
    private String fieldType;

    @Column(length = 4096)
    private String reasons;

    @Column(length = 2048)
    private String tags;

    private String action;
    private double confidence;

    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();
}

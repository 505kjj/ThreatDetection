package com.example.threatdetection.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.SQLRestriction;

import java.time.LocalDateTime;

/**
 * Stores risk analysis results for audit and admin review.
 */
@Entity
@Table(name = "risk_logs")
@SQLRestriction("secure_record = true")
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

    private String eventType;
    private String actionType;

    @Column(length = 4096)
    private String reasons;

    @Column(length = 2048)
    private String tags;

    private String action;
    private double confidence;

    // Only records created through the validated API are visible to readers and exporters.
    @JsonIgnore
    @Builder.Default
    private Boolean secureRecord = true;

    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();
}

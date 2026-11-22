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
 * Stores alert entries generated when risk levels exceed thresholds.
 */
@Entity
@Table(name = "alert_logs")
@SQLRestriction("secure_record = true")
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

    @JsonIgnore
    @Builder.Default
    private Boolean secureRecord = true;

    @Column(length = 4096)
    private String message;

    @Builder.Default
    private boolean resolved = false;

    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();

    private LocalDateTime resolvedAt;
}

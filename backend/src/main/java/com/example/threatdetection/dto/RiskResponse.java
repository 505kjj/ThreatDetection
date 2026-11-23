package com.example.threatdetection.dto;

import com.example.threatdetection.reputation.ReputationStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Risk analysis response returned to the Chrome extension.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RiskResponse {
    private ReputationStatus reputationStatus;

    private int riskScore;
    private int trustScore;
    private String riskLevel;
    private List<String> reasons;
    private List<String> tags;
    private String action;
    private double confidence;
    private String timestamp;
}

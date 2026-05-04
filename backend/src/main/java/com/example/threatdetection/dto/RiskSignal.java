package com.example.threatdetection.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Individual risk signal produced by a single rule evaluation.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RiskSignal {

    private int score;
    private String reason;
    private String tag;
    private String category;
}

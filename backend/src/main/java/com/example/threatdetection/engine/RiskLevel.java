package com.example.threatdetection.engine;

/**
 * Risk classification levels with score thresholds.
 */
public enum RiskLevel {

    SAFE("Safe", 0, 30),
    SUSPICIOUS("Suspicious", 31, 60),
    HIGH_RISK("High Risk", 61, 90),
    CRITICAL("Critical", 91, 100);

    private final String label;
    private final int minScore;
    private final int maxScore;

    RiskLevel(String label, int minScore, int maxScore) {
        this.label = label;
        this.minScore = minScore;
        this.maxScore = maxScore;
    }

    public String getLabel() {
        return label;
    }

    /**
     * Determine risk level from a numeric score.
     */
    public static RiskLevel fromScore(int score) {
        if (score <= 30) return SAFE;
        if (score <= 60) return SUSPICIOUS;
        if (score <= 90) return HIGH_RISK;
        return CRITICAL;
    }
}

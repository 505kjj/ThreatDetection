package com.example.threatdetection.engine;

/**
 * Soft intervention actions mapped to risk levels.
 */
public enum RiskAction {

    ALLOW("ALLOW"),
    SHOW_WARNING("SHOW_WARNING"),
    FORCE_RELOGIN("FORCE_RELOGIN"),
    ADMIN_ALERT("ADMIN_ALERT");

    private final String value;

    RiskAction(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    /**
     * Determine the appropriate action for a given risk level.
     */
    public static RiskAction fromRiskLevel(RiskLevel level) {
        return switch (level) {
            case SAFE -> ALLOW;
            case SUSPICIOUS -> SHOW_WARNING;
            case HIGH_RISK -> FORCE_RELOGIN;
            case CRITICAL -> ADMIN_ALERT;
        };
    }
}

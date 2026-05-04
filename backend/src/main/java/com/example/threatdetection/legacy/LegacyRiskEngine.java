package com.example.threatdetection.legacy;

import java.util.*;

/**
 * LEGACY RISK ENGINE — preserved for reference.
 * The new modular engine is in the engine package.
 */
public class LegacyRiskEngine {

    public static Map<String, Object> analyze(int redirectCount, double clickSpeed, String action) {

        int risk = 0;
        List<String> reasons = new ArrayList<>();
        List<String> tags = new ArrayList<>();

        // Redirect Logic
        if (redirectCount == 1) {
            risk += 1;
            reasons.add("External redirect detected");
            tags.add("Redirect-based risk");
        } else if (redirectCount > 1) {
            risk += 2;
            reasons.add("Multiple redirects detected");
            tags.add("High redirect chain");
        }

        // Behavior Check
        if (clickSpeed < 1.0) {
            risk += 1;
            reasons.add("User clicked too fast");
            tags.add("Behavior anomaly");
        }

        // Context-Aware Risk
        if (action.equalsIgnoreCase("password")) {
            risk += 1;
            reasons.add("Sensitive action detected");
        }

        // Final Risk Level
        String level;
        if (risk == 0) {
            level = "Safe";
        } else if (risk == 1) {
            level = "Suspicious";
        } else {
            level = "High Risk";
        }

        // Soft Intervention
        String actionResponse;
        if (level.equals("Safe")) {
            actionResponse = "Allow";
        } else if (level.equals("Suspicious")) {
            actionResponse = "Show Warning";
        } else {
            actionResponse = "Force Re-login";
        }

        // Final Response
        Map<String, Object> result = new HashMap<>();
        result.put("risk_level", level);
        result.put("reasons", reasons);
        result.put("tags", tags);
        result.put("action", actionResponse);

        return result;
    }
}

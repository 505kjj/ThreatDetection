package com.example.threatdetection.legacy;

import org.springframework.web.bind.annotation.*;
import java.util.Map;

/**
 * LEGACY CONTROLLER — preserved for reference.
 * The new API is handled by ThreatController in the controller package.
 * This class is intentionally disabled (no @RestController annotation active).
 */
// @RestController
// @CrossOrigin
public class LegacyRiskController {

    @PostMapping("/analyze-legacy")
    public Map<String, Object> analyze(@RequestBody Map<String, Object> data) {
        int redirectCount = (int) data.getOrDefault("redirect_count", 0);
        double clickSpeed = Double.parseDouble(data.getOrDefault("click_speed", 1).toString());
        String action = data.getOrDefault("action", "browse").toString();

        return LegacyRiskEngine.analyze(redirectCount, clickSpeed, action);
    }
}

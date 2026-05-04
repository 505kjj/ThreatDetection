package com.example.threatdetection.rules;

import com.example.threatdetection.dto.BehaviorRequest;
import com.example.threatdetection.dto.RiskSignal;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Evaluates risk from click speed and click frequency.
 * Abnormally fast clicking or high click counts indicate bot-like or frustrated behavior.
 */
@Component
public class ClickSpeedRiskRule implements RiskRule {

    @Override
    public String getRuleName() {
        return "ClickSpeedRiskRule";
    }

    @Override
    public List<RiskSignal> evaluate(BehaviorRequest request) {
        List<RiskSignal> signals = new ArrayList<>();
        double avgGap = request.getAverageClickGapMs();
        int clicks = request.getClicksLast10Sec();

        // Average click gap analysis
        if (avgGap > 0 && avgGap < 250) {
            signals.add(RiskSignal.builder()
                    .score(20)
                    .reason("Extremely rapid clicking detected (avg gap: " + Math.round(avgGap) + "ms) — possible bot or credential stuffing")
                    .tag("rapid_clicking")
                    .category("behavior")
                    .build());
        } else if (avgGap >= 250 && avgGap < 500) {
            signals.add(RiskSignal.builder()
                    .score(12)
                    .reason("Fast clicking pattern detected (avg gap: " + Math.round(avgGap) + "ms)")
                    .tag("fast_clicking")
                    .category("behavior")
                    .build());
        }

        // Click count in last 10 seconds
        if (clicks > 15) {
            signals.add(RiskSignal.builder()
                    .score(20)
                    .reason("High click frequency: " + clicks + " clicks in last 10 seconds")
                    .tag("click_flood")
                    .category("behavior")
                    .build());
        } else if (clicks > 8) {
            signals.add(RiskSignal.builder()
                    .score(10)
                    .reason("Elevated click frequency: " + clicks + " clicks in last 10 seconds")
                    .tag("elevated_clicks")
                    .category("behavior")
                    .build());
        }

        return signals;
    }
}

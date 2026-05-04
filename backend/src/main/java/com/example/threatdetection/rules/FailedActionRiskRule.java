package com.example.threatdetection.rules;

import com.example.threatdetection.dto.BehaviorRequest;
import com.example.threatdetection.dto.RiskSignal;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Evaluates risk from failed actions (login failures, form errors).
 * Multiple failures indicate brute-force or credential-testing attacks.
 */
@Component
public class FailedActionRiskRule implements RiskRule {

    @Override
    public String getRuleName() {
        return "FailedActionRiskRule";
    }

    @Override
    public List<RiskSignal> evaluate(BehaviorRequest request) {
        List<RiskSignal> signals = new ArrayList<>();
        int failedActions = request.getFailedActionCount();

        if (failedActions >= 3) {
            signals.add(RiskSignal.builder()
                    .score(30)
                    .reason("Multiple failed actions detected: " + failedActions + " failures (possible brute-force attack)")
                    .tag("brute_force")
                    .category("security")
                    .build());
        } else if (failedActions == 2) {
            signals.add(RiskSignal.builder()
                    .score(15)
                    .reason("Repeated failed actions detected: " + failedActions + " failures")
                    .tag("repeated_failures")
                    .category("security")
                    .build());
        }

        return signals;
    }
}

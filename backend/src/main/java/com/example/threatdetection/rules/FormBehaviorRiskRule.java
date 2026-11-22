package com.example.threatdetection.rules;

import com.example.threatdetection.dto.BehaviorRequest;
import com.example.threatdetection.dto.RiskSignal;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Evaluates risk from form submission patterns.
 * Repeated submissions are an activity signal. A single submission is normal behavior.
 */
@Component
public class FormBehaviorRiskRule implements RiskRule {

    @Override
    public String getRuleName() {
        return "FormBehaviorRiskRule";
    }

    @Override
    public List<RiskSignal> evaluate(BehaviorRequest request) {
        List<RiskSignal> signals = new ArrayList<>();
        int formSubmits = request.getFormSubmitCount();

        // Excessive form submissions
        if (formSubmits > 3) {
            signals.add(RiskSignal.builder()
                    .score(15)
                    .reason("Repeated form submissions observed: " + formSubmits)
                    .tag("form_abuse")
                    .category("form")
                    .build());
        }

        return signals;
    }
}

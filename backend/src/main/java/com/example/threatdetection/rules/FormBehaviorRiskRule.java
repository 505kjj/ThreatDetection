package com.example.threatdetection.rules;

import com.example.threatdetection.dto.BehaviorRequest;
import com.example.threatdetection.dto.RiskSignal;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Evaluates risk from form submission patterns.
 * Repeated form submissions or submissions on sensitive pages indicate brute-force or abuse.
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
        String eventType = request.getEventType();
        String pageCategory = request.getPageCategory();

        // Excessive form submissions
        if (formSubmits > 3) {
            signals.add(RiskSignal.builder()
                    .score(15)
                    .reason("Excessive form submissions detected: " + formSubmits + " submits (possible brute-force)")
                    .tag("form_abuse")
                    .category("form")
                    .build());
        }

        // Form submit on sensitive page
        if ("form_submit".equals(eventType) && "sensitive_page".equals(pageCategory)) {
            signals.add(RiskSignal.builder()
                    .score(15)
                    .reason("Form submitted on a sensitive page")
                    .tag("sensitive_form_submit")
                    .category("form")
                    .build());
        }

        return signals;
    }
}

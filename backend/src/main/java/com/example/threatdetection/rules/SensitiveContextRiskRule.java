package com.example.threatdetection.rules;

import com.example.threatdetection.dto.BehaviorRequest;
import com.example.threatdetection.dto.RiskSignal;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Evaluates risk from sensitive page/field/action context.
 * Actions on sensitive pages with sensitive fields carry higher risk.
 */
@Component
public class SensitiveContextRiskRule implements RiskRule {

    @Override
    public String getRuleName() {
        return "SensitiveContextRiskRule";
    }

    @Override
    public List<RiskSignal> evaluate(BehaviorRequest request) {
        List<RiskSignal> signals = new ArrayList<>();

        String pageCategory = request.getPageCategory();
        String fieldType = request.getFieldType();
        String actionType = request.getActionType();
        String eventType = request.getEventType();

        // Sensitive page context
        if ("sensitive_page".equals(pageCategory)) {
            signals.add(RiskSignal.builder()
                    .score(15)
                    .reason("Activity detected on a sensitive page: " + request.getPath())
                    .tag("sensitive_page")
                    .category("context")
                    .build());
        }

        // Password field interaction
        if ("password".equalsIgnoreCase(fieldType)) {
            signals.add(RiskSignal.builder()
                    .score(15)
                    .reason("Password field accessed during this session")
                    .tag("password_interaction")
                    .category("context")
                    .build());
        }

        // OTP field interaction
        if ("otp".equalsIgnoreCase(fieldType)) {
            signals.add(RiskSignal.builder()
                    .score(15)
                    .reason("OTP field accessed during this session")
                    .tag("otp_interaction")
                    .category("context")
                    .build());
        }

        // Sensitive action
        if ("sensitive_action".equals(actionType)) {
            signals.add(RiskSignal.builder()
                    .score(20)
                    .reason("Sensitive action performed: " + eventType)
                    .tag("sensitive_action")
                    .category("context")
                    .build());
        }

        // Password focus event
        if ("password_focus".equals(eventType)) {
            signals.add(RiskSignal.builder()
                    .score(15)
                    .reason("Password field focus detected — monitoring for credential theft patterns")
                    .tag("password_focus")
                    .category("context")
                    .build());
        }

        return signals;
    }
}

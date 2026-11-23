package com.example.threatdetection.rules;

import com.example.threatdetection.dto.BehaviorRequest;
import com.example.threatdetection.dto.RiskSignal;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Evaluates browser-reported redirects as behavior signals.
 */
@Component
public class RedirectRiskRule implements RiskRule {

    @Override
    public String getRuleName() {
        return "RedirectRiskRule";
    }

    @Override
    public List<RiskSignal> evaluate(BehaviorRequest request) {
        List<RiskSignal> signals = new ArrayList<>();
        int redirectCount = request.getRedirectCount();

        if (redirectCount <= 0) {
            return signals;
        }

        if (redirectCount == 1) {
            signals.add(RiskSignal.builder()
                    .score(10)
                    .reason("Browser reported one redirect")
                    .tag("redirect_based_risk")
                    .category("navigation")
                    .build());
        } else if (redirectCount == 2) {
            signals.add(RiskSignal.builder()
                    .score(18)
                    .reason("Browser reported multiple redirects")
                    .tag("redirect_chain")
                    .category("navigation")
                    .build());
        } else {
            signals.add(RiskSignal.builder()
                    .score(25)
                    .reason("Browser reported " + redirectCount + " redirects")
                    .tag("high_redirect_chain")
                    .category("navigation")
                    .build());
        }

        // Extra risk if redirects lead to a sensitive page
        if ("sensitive_page".equals(request.getPageCategory()) && redirectCount >= 2) {
            signals.add(RiskSignal.builder()
                    .score(5)
                    .reason("Redirect chain leads to a sensitive page")
                    .tag("redirect_to_sensitive")
                    .category("navigation")
                    .build());
        }

        return signals;
    }
}

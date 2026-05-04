package com.example.threatdetection.rules;

import com.example.threatdetection.dto.BehaviorRequest;
import com.example.threatdetection.dto.RiskSignal;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Evaluates risk from unknown or suspicious referrer sources.
 * Empty referrers on sensitive pages or external unknown referrers indicate potential attacks.
 */
@Component
public class UnknownReferrerRiskRule implements RiskRule {

    @Override
    public String getRuleName() {
        return "UnknownReferrerRiskRule";
    }

    @Override
    public List<RiskSignal> evaluate(BehaviorRequest request) {
        List<RiskSignal> signals = new ArrayList<>();
        String referrer = request.getReferrer();
        String domain = request.getDomain();
        boolean isSensitivePage = "sensitive_page".equals(request.getPageCategory());

        boolean isEmptyReferrer = (referrer == null || referrer.isBlank());
        boolean isExternalReferrer = !isEmptyReferrer && domain != null && !referrer.contains(domain);

        if (isEmptyReferrer && isSensitivePage) {
            signals.add(RiskSignal.builder()
                    .score(8)
                    .reason("Direct access to sensitive page with no referrer (possible bookmark/link attack)")
                    .tag("no_referrer_sensitive")
                    .category("referrer")
                    .build());
        }

        if (isExternalReferrer) {
            signals.add(RiskSignal.builder()
                    .score(15)
                    .reason("User arrived from an external unknown source: referrer does not match monitored domain")
                    .tag("external_referrer")
                    .category("referrer")
                    .build());
        }

        return signals;
    }
}

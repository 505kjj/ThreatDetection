package com.example.threatdetection.rules;

import com.example.threatdetection.dto.BehaviorRequest;
import com.example.threatdetection.dto.RiskSignal;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Evaluates risk from rapid page navigation.
 * Visiting many pages in a short time indicates automated scanning or reconnaissance.
 */
@Component
public class NavigationBurstRiskRule implements RiskRule {

    @Override
    public String getRuleName() {
        return "NavigationBurstRiskRule";
    }

    @Override
    public List<RiskSignal> evaluate(BehaviorRequest request) {
        List<RiskSignal> signals = new ArrayList<>();
        int pagesVisited = request.getPagesVisitedLast30Sec();

        if (pagesVisited > 8) {
            signals.add(RiskSignal.builder()
                    .score(15)
                    .reason("Navigation burst detected: " + pagesVisited + " pages visited in last 30 seconds (possible automated scanning)")
                    .tag("navigation_burst")
                    .category("navigation")
                    .build());
        } else if (pagesVisited > 4) {
            signals.add(RiskSignal.builder()
                    .score(8)
                    .reason("Elevated navigation speed: " + pagesVisited + " pages visited in last 30 seconds")
                    .tag("fast_navigation")
                    .category("navigation")
                    .build());
        }

        return signals;
    }
}

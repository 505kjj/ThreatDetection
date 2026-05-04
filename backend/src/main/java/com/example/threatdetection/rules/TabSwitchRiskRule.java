package com.example.threatdetection.rules;

import com.example.threatdetection.dto.BehaviorRequest;
import com.example.threatdetection.dto.RiskSignal;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Evaluates risk from tab switching behavior.
 * Frequent tab switches during sensitive operations indicate copy-paste attacks or social engineering.
 */
@Component
public class TabSwitchRiskRule implements RiskRule {

    @Override
    public String getRuleName() {
        return "TabSwitchRiskRule";
    }

    @Override
    public List<RiskSignal> evaluate(BehaviorRequest request) {
        List<RiskSignal> signals = new ArrayList<>();
        int tabSwitches = request.getTabSwitchCount();

        if (tabSwitches > 5) {
            signals.add(RiskSignal.builder()
                    .score(15)
                    .reason("Frequent tab switching detected: " + tabSwitches + " switches (possible copy-paste attack or social engineering)")
                    .tag("high_tab_switching")
                    .category("session")
                    .build());
        } else if (tabSwitches > 2) {
            signals.add(RiskSignal.builder()
                    .score(8)
                    .reason("Elevated tab switching: " + tabSwitches + " switches during session")
                    .tag("tab_switching")
                    .category("session")
                    .build());
        }

        return signals;
    }
}

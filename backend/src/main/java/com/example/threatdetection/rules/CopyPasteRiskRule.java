package com.example.threatdetection.rules;

import com.example.threatdetection.dto.BehaviorRequest;
import com.example.threatdetection.dto.RiskSignal;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Evaluates risk from copy/paste operations.
 * Pasting into sensitive fields on sensitive pages is a strong indicator of credential stuffing.
 */
@Component
public class CopyPasteRiskRule implements RiskRule {

    @Override
    public String getRuleName() {
        return "CopyPasteRiskRule";
    }

    @Override
    public List<RiskSignal> evaluate(BehaviorRequest request) {
        List<RiskSignal> signals = new ArrayList<>();
        int copyPasteCount = request.getCopyPasteCount();
        String pageCategory = request.getPageCategory();

        if (copyPasteCount > 5) {
            signals.add(RiskSignal.builder()
                    .score(15)
                    .reason("Excessive copy/paste operations: " + copyPasteCount + " detected")
                    .tag("excessive_copy_paste")
                    .category("behavior")
                    .build());
        } else if (copyPasteCount > 2 && "sensitive_page".equals(pageCategory)) {
            signals.add(RiskSignal.builder()
                    .score(10)
                    .reason("Copy/paste detected on sensitive page (" + copyPasteCount + " operations)")
                    .tag("sensitive_copy_paste")
                    .category("behavior")
                    .build());
        }

        return signals;
    }
}

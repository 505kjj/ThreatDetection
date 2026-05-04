package com.example.threatdetection.rules;

import com.example.threatdetection.dto.BehaviorRequest;
import com.example.threatdetection.dto.RiskSignal;

import java.util.List;

/**
 * Interface for modular risk evaluation rules.
 * Each rule evaluates a specific behavioral dimension and returns risk signals.
 */
public interface RiskRule {

    /**
     * Evaluate the behavior request and return zero or more risk signals.
     * Returning an empty list means no risk was detected by this rule.
     */
    List<RiskSignal> evaluate(BehaviorRequest request);

    /**
     * Human-readable name for this rule (used in logging).
     */
    String getRuleName();
}

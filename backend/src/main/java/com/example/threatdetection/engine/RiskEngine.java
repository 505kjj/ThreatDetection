package com.example.threatdetection.engine;

import com.example.threatdetection.dto.BehaviorRequest;
import com.example.threatdetection.dto.RiskResponse;
import com.example.threatdetection.dto.RiskSignal;
import com.example.threatdetection.rules.RiskRule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Core risk analysis engine.
 * Orchestrates all registered risk rules, aggregates signals,
 * and produces an explainable risk response.
 */
@Component
public class RiskEngine {

    private static final Logger log = LoggerFactory.getLogger(RiskEngine.class);
    private static final int MAX_SCORE = 100;
    private static final int MAX_BEHAVIOR_SCORE = 60;

    private final List<RiskRule> rules;

    /**
     * Spring auto-injects all beans implementing RiskRule.
     */
    public RiskEngine(List<RiskRule> rules) {
        this.rules = rules;
        log.info("RiskEngine initialized with {} rules: {}",
                rules.size(),
                rules.stream().map(RiskRule::getRuleName).toList());
    }

    /**
     * Evaluate a behavior request against all registered rules.
     *
     * @param request the behavior metadata from the extension
     * @return an explainable risk response
     */
    public RiskResponse evaluate(BehaviorRequest request) {
        List<RiskSignal> allSignals = new ArrayList<>();

        // Run every rule
        for (RiskRule rule : rules) {
            try {
                List<RiskSignal> signals = rule.evaluate(request);
                if (signals != null && !signals.isEmpty()) {
                    allSignals.addAll(signals);
                    log.debug("Rule [{}] produced {} signal(s)", rule.getRuleName(), signals.size());
                }
            } catch (Exception e) {
                log.error("Behavior rule [{}] failed", rule.getRuleName());
            }
        }

        // Aggregate
        int totalScore = allSignals.stream().mapToInt(RiskSignal::getScore).sum();
        // Browser-reported behavior alone cannot establish a dangerous destination.
        int cappedScore = Math.min(totalScore, MAX_BEHAVIOR_SCORE);

        // De-duplicate reasons and tags while preserving order
        Set<String> reasonSet = new LinkedHashSet<>();
        Set<String> tagSet = new LinkedHashSet<>();
        for (RiskSignal signal : allSignals) {
            if (signal.getReason() != null) reasonSet.add(signal.getReason());
            if (signal.getTag() != null) tagSet.add(signal.getTag());
        }

        List<String> reasons = new ArrayList<>(reasonSet);
        List<String> tags = new ArrayList<>(tagSet);

        // Classify
        RiskLevel level = RiskLevel.fromScore(cappedScore);
        RiskAction action = RiskAction.fromRiskLevel(level);

        // Confidence: ratio of capped score to total possible concern
        double confidence = totalScore > 0
                ? Math.min(1.0, (double) cappedScore / MAX_SCORE)
                : 1.0;

        // Default safe response if nothing was detected
        if (allSignals.isEmpty()) {
            reasons.add("No suspicious behavior observed in this event");
            tags.add("normal_behavior");
        }

        int trustScore = 100 - cappedScore;

        return RiskResponse.builder()
                .riskScore(cappedScore)
                .trustScore(trustScore)
                .riskLevel(level.getLabel())
                .reasons(reasons)
                .tags(tags)
                .action(action.getValue())
                .confidence(Math.round(confidence * 100.0) / 100.0)
                .timestamp(Instant.now().toString())
                .build();
    }
}

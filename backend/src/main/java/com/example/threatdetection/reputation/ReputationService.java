package com.example.threatdetection.reputation;

import com.example.threatdetection.dto.RiskResponse;
import com.example.threatdetection.engine.RiskAction;
import com.example.threatdetection.engine.RiskLevel;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Service;

@Service
public class ReputationService {
    private final ReputationProvider provider;

    public ReputationService(ReputationProvider provider) {
        this.provider = provider;
    }

    public Optional<ReputationSnapshot> snapshot() {
        return provider.current().filter(value -> value.isCurrent(Instant.now()));
    }

    public RiskResponse applyHostReputation(String hostname, RiskResponse behavior) {
        var current = snapshot();
        if (current.isEmpty()) {
            behavior.setReputationStatus(ReputationStatus.UNAVAILABLE);
        } else if (current.get().confirmsHost(hostname)) {
            behavior.setReputationStatus(ReputationStatus.CONFIRMED_MALICIOUS);
            behavior.setRiskLevel(RiskLevel.CRITICAL.getLabel());
            behavior.setAction(RiskAction.ADMIN_ALERT.getValue());
            behavior.setRiskScore(100);
            behavior.setTrustScore(0);
            behavior.setConfidence(1.0);
            behavior.setReasons(List.of("Exact hostname matched the threat intelligence snapshot"));
            behavior.setTags(List.of("confirmed_reputation_match"));
        } else {
            behavior.setReputationStatus(RiskLevel.SUSPICIOUS.getLabel().equals(behavior.getRiskLevel())
                    ? ReputationStatus.SUSPICIOUS_UNCONFIRMED : ReputationStatus.NO_KNOWN_MATCH);
        }
        return behavior;
    }
}

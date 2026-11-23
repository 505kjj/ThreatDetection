package com.example.threatdetection.reputation;

import java.time.Duration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class ReputationIngestionSettings {
    static final String SOURCE = "CERT_POLSKA";
    static final Duration MAX_AGE = Duration.ofMinutes(15);
    static final Duration MINIMUM_POLL_INTERVAL = Duration.ofMinutes(5);

    private final boolean enabled;
    private final boolean browserDistributionApproved;

    public ReputationIngestionSettings(
            @Value("${threat.reputation.ingestion.enabled:false}") boolean enabled,
            @Value("${threat.reputation.ingestion.browser-distribution-approved:false}") boolean browserDistributionApproved,
            @Value("${threat.reputation.ingestion.poll-interval:PT5M}") String pollInterval) {
        if (enabled && Duration.parse(pollInterval).compareTo(MINIMUM_POLL_INTERVAL) < 0) {
            throw new IllegalArgumentException("CERT Polska ingestion requires a poll interval of at least five minutes");
        }
        this.enabled = enabled;
        this.browserDistributionApproved = browserDistributionApproved;
    }

    public boolean enabled() {
        return enabled;
    }

    public boolean canServeBrowsers() {
        return !enabled || browserDistributionApproved;
    }
}

package com.example.threatdetection.reputation;

import com.fasterxml.jackson.annotation.JsonFormat;
import java.io.IOException;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(name = "threat.reputation.ingestion.enabled", havingValue = "true")
public class ReputationIngestor {
    private static final Logger LOG = LoggerFactory.getLogger(ReputationIngestor.class);
    private final ThreatFeed feed;
    private final PublishedSnapshotStore store;
    private final FileReputationProvider provider;
    private final ReputationIngestionSettings settings;
    private volatile Poll poll = new Poll(PollState.WAITING, null, null, 0, 0, null, null);

    ReputationIngestor(ThreatFeed feed, PublishedSnapshotStore store, FileReputationProvider provider,
                       ReputationIngestionSettings settings) {
        this.feed = feed;
        this.store = store;
        this.provider = provider;
        this.settings = settings;
    }

    @Scheduled(initialDelayString = "${threat.reputation.ingestion.initial-delay:PT0S}",
            fixedDelayString = "${threat.reputation.ingestion.poll-interval:PT5M}")
    synchronized void update() {
        Instant attempt = Instant.now();
        ThreatFeed.Result downloaded;
        try {
            downloaded = feed.fetch(attempt);
        } catch (IOException | RuntimeException failure) {
            failed(PollState.FEED_FAILED, attempt);
            return;
        }

        try {
            var snapshot = downloaded.snapshot();
            if (!snapshot.isCurrent(Instant.now())) throw new IOException("Reputation feed is stale");
            var previous = provider.loadedPublication().orElse(null);
            if (previous != null && !snapshot.generatedAt().isAfter(previous.snapshot().generatedAt())) {
                if (!previous.version().equals(store.version(snapshot))) {
                    throw new IOException("Reputation feed version moved backward or conflicted");
                }
                if (!store.hasVersion(previous.version())) publish(snapshot);
            } else {
                publish(snapshot);
            }
            poll = new Poll(PollState.AVAILABLE, attempt, Instant.now(), poll.successes() + 1, poll.failures(),
                    downloaded.activeIndicators(), downloaded.rejectedIndicators());
            LOG.info("Reputation feed verified: source={}, active={}, published={}, rejected={}",
                    ReputationIngestionSettings.SOURCE, downloaded.activeIndicators(),
                    snapshot.entries().size(), downloaded.rejectedIndicators());
        } catch (IOException | RuntimeException failure) {
            failed(PollState.PUBLISH_FAILED, attempt);
        }
    }

    private void publish(ReputationSnapshot snapshot) throws IOException {
        var written = store.publish(snapshot);
        provider.refresh();
        if (provider.loadedPublication().filter(current -> written.version().equals(current.version())).isEmpty()) {
            throw new IOException("Published reputation snapshot was not accepted by the reader");
        }
    }

    private void failed(PollState state, Instant attempt) {
        poll = new Poll(state, attempt, poll.lastSuccessAt(), poll.successes(), poll.failures() + 1,
                poll.sourceActiveIndicators(), poll.rejectedIndicators());
        LOG.warn("Reputation update failed: source={}, state={}", ReputationIngestionSettings.SOURCE, state);
    }

    public FeedStatus status() {
        var currentPoll = poll;
        var loaded = provider.loadedPublication().orElse(null);
        var snapshot = loaded == null ? null : loaded.snapshot();
        DataState dataState = snapshot == null ? DataState.MISSING
                : snapshot.isCurrent(Instant.now()) ? DataState.CURRENT : DataState.STALE;
        return new FeedStatus(ReputationIngestionSettings.SOURCE, currentPoll.state(), dataState,
                currentPoll.state() == PollState.AVAILABLE || currentPoll.state() == PollState.PUBLISH_FAILED,
                settings.canServeBrowsers(), currentPoll.lastAttemptAt(), currentPoll.lastSuccessAt(),
                currentPoll.successes(), currentPoll.failures(), loaded == null ? null : loaded.version(),
                snapshot == null ? null : snapshot.generatedAt(), snapshot == null ? null : snapshot.expiresAt(),
                snapshot == null ? 0 : snapshot.entries().size(), currentPoll.sourceActiveIndicators(),
                currentPoll.rejectedIndicators());
    }

    public enum PollState { WAITING, AVAILABLE, FEED_FAILED, PUBLISH_FAILED }
    public enum DataState { MISSING, CURRENT, STALE }

    public record FeedStatus(
            String provider, PollState pollState, DataState dataState,
            boolean providerAvailable, boolean browserDistributionApproved,
            @JsonFormat(shape = JsonFormat.Shape.STRING) Instant lastAttemptAt,
            @JsonFormat(shape = JsonFormat.Shape.STRING) Instant lastSuccessAt,
            long successfulPolls, long failedPolls, String version,
            @JsonFormat(shape = JsonFormat.Shape.STRING) Instant sourceModifiedAt,
            @JsonFormat(shape = JsonFormat.Shape.STRING) Instant expiresAt,
            int publishedIndicators, Integer sourceActiveIndicators, Integer rejectedIndicators) {}

    private record Poll(PollState state, Instant lastAttemptAt, Instant lastSuccessAt, long successes, long failures,
                        Integer sourceActiveIndicators, Integer rejectedIndicators) {}
}

package com.example.threatdetection.reputation;

import jakarta.annotation.PostConstruct;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import tools.jackson.databind.json.JsonMapper;

/** Loads a licensed, operator-prepared snapshot from disk. No per-visit network or file I/O. */
@Component
public class FileReputationProvider implements ReputationProvider {
    private static final Logger LOG = LoggerFactory.getLogger(FileReputationProvider.class);

    private final JsonMapper mapper;
    private final String path;
    private final ReputationIngestionSettings settings;
    private final PublishedSnapshotStore store;
    private volatile PublishedSnapshotStore.Published publication;
    private boolean reportedFailure;

    FileReputationProvider(JsonMapper mapper, @Value("${threat.reputation.snapshot-path:}") String path,
                           ReputationIngestionSettings settings, PublishedSnapshotStore store) {
        this.mapper = mapper;
        this.path = path;
        this.settings = settings;
        this.store = store;
    }

    @PostConstruct
    @Scheduled(initialDelayString = "${threat.reputation.reload-interval:PT30S}",
            fixedDelayString = "${threat.reputation.reload-interval:PT30S}")
    synchronized void refresh() {
        if (path.isBlank()) return;
        if (settings.enabled()) {
            refreshManaged();
            return;
        }
        try (var input = Files.newInputStream(Path.of(path))) {
            byte[] data = input.readNBytes(PublishedSnapshotStore.MAX_PAYLOAD_BYTES + 1);
            if (data.length > PublishedSnapshotStore.MAX_PAYLOAD_BYTES) {
                throw new IllegalArgumentException("Snapshot too large");
            }
            ReputationSnapshot candidate = mapper.readValue(data, ReputationSnapshot.class);
            if (candidate == null || !candidate.isCurrent(Instant.now())) {
                throw new IllegalArgumentException("Snapshot outside validity window");
            }
            publication = new PublishedSnapshotStore.Published(null, candidate);
            reportedFailure = false;
        } catch (IOException | RuntimeException failure) {
            publication = null;
            warn();
        }
    }

    private void refreshManaged() {
        try {
            var next = store.load();
            var now = Instant.now();
            if (next.snapshot().generatedAt().isAfter(now.plusSeconds(60)) ||
                    (publication != null && !next.version().equals(publication.version()) &&
                            !next.snapshot().generatedAt().isAfter(publication.snapshot().generatedAt()))) {
                throw new IOException("Managed snapshot is out of order");
            }
            publication = next;
            if (next.snapshot().isCurrent(now)) reportedFailure = false;
            else warn();
        } catch (IOException | RuntimeException failure) {
            // Keep the last authenticated publication. current() enforces its original expiration.
            warn();
        }
    }

    private void warn() {
        if (!reportedFailure) LOG.warn("URL reputation snapshot is unavailable, invalid, or stale");
        reportedFailure = true;
    }

    Optional<PublishedSnapshotStore.Published> loadedPublication() {
        return Optional.ofNullable(publication);
    }

    @Override
    public Optional<ReputationSnapshot> current() {
        return loadedPublication().map(PublishedSnapshotStore.Published::snapshot)
                .filter(value -> value.isCurrent(Instant.now()));
    }
}

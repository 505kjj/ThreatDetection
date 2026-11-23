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
    private static final int MAX_BYTES = 3 * 1024 * 1024;
    private static final Logger LOG = LoggerFactory.getLogger(FileReputationProvider.class);

    private final JsonMapper mapper;
    private final String path;
    private volatile ReputationSnapshot snapshot;
    private boolean reportedFailure;

    public FileReputationProvider(JsonMapper mapper, @Value("${threat.reputation.snapshot-path:}") String path) {
        this.mapper = mapper;
        this.path = path;
    }

    @PostConstruct
    @Scheduled(initialDelayString = "${threat.reputation.reload-interval:PT30S}",
            fixedDelayString = "${threat.reputation.reload-interval:PT30S}")
    void refresh() {
        if (path.isBlank()) return;
        try (var input = Files.newInputStream(Path.of(path))) {
            byte[] data = input.readNBytes(MAX_BYTES + 1);
            if (data.length > MAX_BYTES) throw new IllegalArgumentException("Snapshot too large");
            ReputationSnapshot candidate = mapper.readValue(data, ReputationSnapshot.class);
            if (candidate == null || !candidate.isCurrent(Instant.now())) {
                throw new IllegalArgumentException("Snapshot outside validity window");
            }
            snapshot = candidate;
            reportedFailure = false;
        } catch (IOException | RuntimeException failure) {
            snapshot = null;
            if (!reportedFailure) LOG.warn("URL reputation snapshot is unavailable or invalid");
            reportedFailure = true;
        }
    }

    @Override
    public Optional<ReputationSnapshot> current() {
        return Optional.ofNullable(snapshot).filter(value -> value.isCurrent(Instant.now()));
    }
}

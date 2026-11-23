package com.example.threatdetection.reputation;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

/** Reserved names and inert test indicators. Never configured in the application. */
final class FixtureReputationProvider implements ReputationProvider {
    static final String SAFE = "bank.example.test";
    static final String PHISH = "known-phish.example.test";
    static final String MALWARE_PATH = "https://shared.example.test/download";
    private final ReputationSnapshot snapshot;

    FixtureReputationProvider(Instant generatedAt, Instant expiresAt) {
        snapshot = new ReputationSnapshot(generatedAt, expiresAt, List.of(
                new ReputationSnapshot.Entry(ReputationSnapshot.Kind.HOST, PHISH, ReputationSnapshot.Threat.PHISHING),
                new ReputationSnapshot.Entry(ReputationSnapshot.Kind.URL_SHA256, sha256(MALWARE_PATH),
                        ReputationSnapshot.Threat.MALWARE)));
    }

    static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException failure) {
            throw new IllegalStateException(failure);
        }
    }

    @Override
    public Optional<ReputationSnapshot> current() {
        return Optional.of(snapshot);
    }
}
